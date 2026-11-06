"""Compatibility CLI and configuration exports for the original cAPTure entry point."""
from experiments.capture import main
from scenario_configs.capture import *  # Preserve established experiment constants.
from scenario_configs.capture import __all__ as _configuration_exports

__all__ = [*_configuration_exports, "main"]

if __name__ == "__main__":
    main()
