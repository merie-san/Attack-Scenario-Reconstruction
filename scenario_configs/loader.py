"""Load campaign definitions and generation rules without dataset dependencies."""
from collections.abc import Callable
import copy
from dataclasses import dataclass
import importlib
import importlib.util
import json
from pathlib import Path
import sys
from types import ModuleType
from uuid import uuid4

from scenario_reconstructor.dag import AttackGoal
from scenario_reconstructor.models import AttackType, Host, HostAttribute, Precondition


@dataclass(frozen=True)
class ScenarioConfig:
    """Campaign rules, reconstruction definitions, and independent host factory."""

    next_attack_dict: dict[str, list[str]]
    enable_src_for: dict[str, list[str]]
    enable_dst_for: dict[str, list[str]]
    possible_srcs: dict[str, list[str]]
    possible_dsts: dict[str, list[str]]
    dst_restricted_atks: dict[str, list[str]]
    final_atk: str
    enable_atks: list[str]
    atk_types: list[AttackType]
    undetermined: AttackType
    create_hosts: Callable[[], list[Host]]
    external_host_attributes: set[HostAttribute]
    attack_goal: AttackGoal
    score_columns: tuple[str, ...]


def _object(value, field):
    if not isinstance(value, dict):
        raise ValueError(f"{field} must be an object")
    return value


def _string(value, field):
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{field} must be a non-empty string")
    return value


def _list(value, field):
    if not isinstance(value, list):
        raise ValueError(f"{field} must be a list")
    return value


def _strings(value, field):
    return [_string(item, field) for item in _list(value, field)]


def _required(data, field):
    if field not in data:
        raise ValueError(f"Missing required field: {field}")
    return data[field]


def _rules(data):
    rules = {}
    for field in ("next_attack_dict", "enable_src_for", "enable_dst_for", "possible_srcs",
                  "possible_dsts", "dst_restricted_atks"):
        value = (_required(data, field) if field in
                 ("next_attack_dict", "possible_srcs", "possible_dsts") else data.get(field, {}))
        rules[field] = {_string(key, field): _strings(items, field)
                        for key, items in _object(value, field).items()}
    rules["final_atk"] = _string(_required(data, "final_atk"), "final_atk")
    rules["enable_atks"] = _strings(data.get("enable_atks", []), "enable_atks")
    return rules


def _from_json(data):
    data = _object(data, "Configuration")
    rules = _rules(data)
    attacks = _list(_required(data, "attack_types"), "attack_types")
    undetermined = data.get("undetermined", {
        "identifier": "undetermined", "preconditions": [], "postconditions": [],
    })
    referenced = set()

    def attribute_names(value, field):
        names = _strings(value, field)
        referenced.update(names)
        return names

    definitions = []
    for index, value in enumerate([*attacks, undetermined]):
        field = f"attack_types[{index}]" if index < len(attacks) else "undetermined"
        value = _object(value, field)
        identifier = _string(_required(value, "identifier"), f"{field}.identifier")
        description = value.get("description", "")
        if not isinstance(description, str):
            raise ValueError(f"{field}.description must be a string")
        conditions = []
        for condition in _list(_required(value, "preconditions"), f"{field}.preconditions"):
            condition = _object(condition, f"{field}.preconditions entry")
            names = attribute_names(_required(condition, "attributes"), f"{field}.attributes")
            targets_source = _required(condition, "targets_source")
            if not isinstance(targets_source, bool):
                raise ValueError(f"{field}.targets_source must be a boolean")
            conditions.append((names, targets_source))
        postconditions = attribute_names(_required(value, "postconditions"), f"{field}.postconditions")
        definitions.append((identifier, conditions, postconditions, description))
    identifiers = [definition[0] for definition in definitions[:-1]]
    if len(set(identifiers)) != len(identifiers):
        raise ValueError("attack_types identifiers must be unique")

    hosts = _required(data, "hosts")
    if isinstance(hosts, dict):
        hosts = [{"ip": ip, "attributes": attributes} for ip, attributes in hosts.items()]
    host_definitions = []
    for host in _list(hosts, "hosts"):
        host = _object(host, "hosts entry")
        ip = _string(_required(host, "ip"), "hosts.ip")
        names = attribute_names(_required(host, "attributes"), "hosts.attributes")
        host_definitions.append((ip, names))
    external = attribute_names(data.get("external_host_attributes", []), "external_host_attributes")
    if "attributes" in data:
        declared = set(_strings(data["attributes"], "attributes"))
        unknown = referenced - declared
        if unknown:
            raise ValueError(f"Unknown attribute names: {', '.join(sorted(unknown))}")
    else:
        declared = referenced
    try:
        attributes = HostAttribute("ConfiguredHostAttributes", {name: name for name in sorted(declared)})
    except (TypeError, ValueError) as error:
        raise ValueError(f"Invalid attribute names: {error}") from error

    def resolve(names):
        return {attributes[name] for name in names}

    attack_types = [AttackType(identifier, {Precondition(resolve(names), source)
                                          for names, source in conditions}, resolve(posts), description)
                    for identifier, conditions, posts, description in definitions]
    attack_by_id = {attack.identifier: attack for attack in attack_types[:-1]}

    def create_hosts():
        result = []
        for ip, names in host_definitions:
            host = Host(ip)
            host.update_compromise_attributes(resolve(names))
            result.append(host)
        return result

    goal = _object(data.get("attack_goal", {"attack_type": rules["final_atk"]}), "attack_goal")
    goal_values = {}
    for field in ("attack_type", "source_ip", "destination_ip"):
        value = goal.get(field)
        if value is not None:
            _string(value, f"attack_goal.{field}")
        goal_values[field] = value
    goal_type = goal_values["attack_type"]
    if goal_type is not None and goal_type not in attack_by_id:
        raise ValueError(f"Unknown attack_goal.attack_type: {goal_type}")
    goal_values["attack_type"] = attack_by_id.get(goal_type)
    columns = _strings(data.get("score_columns", identifiers), "score_columns")
    return ScenarioConfig(**rules, atk_types=attack_types[:-1], undetermined=attack_types[-1],
                          create_hosts=create_hosts, external_host_attributes=resolve(external),
                          attack_goal=AttackGoal(**goal_values), score_columns=tuple(columns))


def _from_module(module):
    required = ("ATK_TYPES", "UNDETERMINED", "NEXT_ATTACK_DICT", "ENABLE_SRC_FOR", "ENABLE_DST_FOR",
                "POSSIBLE_SRCS", "POSSIBLE_DSTS", "DST_RESTRICTED_ATKS", "FINAL_ATK", "ENABLE_ATKS")
    values = {}
    for name in required:
        if not hasattr(module, name):
            raise ValueError(f"Configuration module is missing required attribute: {name}")
        values[name.lower()] = getattr(module, name)
    rules = _rules(values)
    attacks = _list(values["atk_types"], "ATK_TYPES")
    if not all(isinstance(attack, AttackType) for attack in attacks):
        raise ValueError("ATK_TYPES must contain AttackType objects")
    if not isinstance(values["undetermined"], AttackType):
        raise ValueError("UNDETERMINED must be an AttackType")
    factory = getattr(module, "create_hosts", None)
    if hasattr(module, "create_hosts"):
        if not callable(factory):
            raise ValueError("create_hosts must be callable")
    elif hasattr(module, "HOSTS"):
        hosts = copy.deepcopy(_list(module.HOSTS, "HOSTS"))
        if not all(isinstance(host, Host) for host in hosts):
            raise ValueError("HOSTS must contain Host objects")

        def factory():
            return copy.deepcopy(hosts)
    else:
        raise ValueError("Configuration module requires create_hosts or HOSTS")
    attack_by_id = {attack.identifier: attack for attack in attacks}
    external = getattr(module, "EXTERNAL_HOST_ATTRIBUTES", set())
    goal = getattr(module, "ATTACK_GOAL", AttackGoal(attack_type=attack_by_id.get(rules["final_atk"])))
    columns = getattr(module, "SCORE_COLUMNS", getattr(module, "ATTACK_SCORE_COLUMNS",
                                                     tuple(attack.identifier for attack in attacks)))
    if module.__name__ == "scenario_configs.capture":
        external = {module.DollarCharHostAttributes.START_MACHINE}
        goal = AttackGoal(attack_type=module.DOLLAR_CHAR, destination_ip="10.0.0.1")
        columns = (module.NMAP_10_T5_NAME, module.NMAP_MQTT_NAME, module.NMAP_BANNER_NAME,
                   module.BRUTE_FORCE_MALFORMED_NAME, module.DOLLAR_CHAR_NAME, module.SCP_INST_NAME)
    if not isinstance(external, set) or not all(isinstance(item, HostAttribute) for item in external):
        raise ValueError("EXTERNAL_HOST_ATTRIBUTES must be a set of HostAttribute values")
    if not isinstance(goal, AttackGoal):
        raise ValueError("ATTACK_GOAL must be an AttackGoal")
    if not isinstance(columns, (list, tuple)):
        raise ValueError("SCORE_COLUMNS / ATTACK_SCORE_COLUMNS must be a list or tuple of strings")
    columns = _strings(list(columns), "SCORE_COLUMNS / ATTACK_SCORE_COLUMNS")
    return ScenarioConfig(**rules, atk_types=list(attacks), undetermined=values["undetermined"],
                          create_hosts=factory, external_host_attributes=set(external),
                          attack_goal=goal, score_columns=tuple(columns))


def _load_python_file(path: Path) -> ModuleType:
    name = f"_scenario_config_{uuid4().hex}"
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise ValueError(f"Cannot load configuration file: {path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    try:
        spec.loader.exec_module(module)
    except Exception:
        sys.modules.pop(name, None)
        raise
    return module


def load_scenario_config(spec: str = "capture") -> ScenarioConfig:
    """Load a campaign module or a trusted Python/JSON configuration file."""
    if not isinstance(spec, str) or not spec.strip():
        raise ValueError("Configuration must be a module name or a .py/.json file path")
    path = Path(spec)
    try:
        if path.is_file():
            if path.suffix.lower() == ".json":
                with path.open(encoding="utf-8") as source:
                    return _from_json(json.load(source))
            if path.suffix.lower() == ".py":
                return _from_module(_load_python_file(path))
            raise ValueError("Configuration file must have a .py or .json extension")
        if path.suffix.lower() in (".py", ".json") or any(char in spec for char in ("/", "\\")):
            raise ValueError(f"Configuration file does not exist: {spec}")
        name = spec if spec.startswith("scenario_configs.") else f"scenario_configs.{spec}"
        return _from_module(importlib.import_module(name))
    except Exception as error:
        raise ValueError(f"Invalid scenario configuration {spec!r}: {error}") from error
