# Attack Scenario Reconstruction

This is a code repository for my master thesis on Attack Scenario Reconstruction. I report here its introductory chapter:

Given the increasing adoption of IT and OT technology in every corner of today’s society, it has become increasingly important to secure them against all sorts and types of cyber threats. This is especially true for
safety critical systems which can cause enormous economic damage or even loss of human life in case of failure. Famous examples of cyber attacks include:

- 2010 Stuxnet Worm attack on Iran nuclear facilities
- 2015 Russian First Ukraine power grid attack
- 2017 North Korean WannaCry ransomware attack
- and many others...

Many defense systems and mechanisms have been developed against such threats: IDS (Intrusion Detection System), IPS (Intrusion Prevention System), firewalls, antiviruses, authentication mechanisms, audits trails, access control mechanisms. . .

IDSs, in particular, are a widely adopted solution for automatic intrusion detection. IDSs come in different flavors but they all have some common, well-known weaknesses:

- They only detect single steps in possibly multi-step attacks.
- They do not try to explain the relationships between detected intrusion steps.
- They generate numerous false positive detections even with relatively small FPRs, given the rarity of actual intrusion compared to normal traffic.
- As a consequence they produce numerous alerts giving rise to the so-called alert fatigue problem.
- They do not try to understand the root cause of the alerts.
- IDSs are highly heterogeneous generate vastly different alerts in syntax and semantics.

Moreover, most real attacks consist of multiple coordinated steps with clear objectives and cause-effect relationships that cannot be captured by simple single-step detectors. This causes alerts produced by real intrusion steps to be hidden in a sea of false positives and highly heterogeneous alerts, causing a difficult needle in a haystack problem.

For this reason most modern IT or OT systems deploy some sort of SIEM (Security Information Event Management), which has the function of collecting, aggregating and analyzing security event data for the purposes of threat detection, investigation and response. Nowadays SIEMS have become central in SOC (Security Operation Centers) for security monitoring and compliance management use cases. SIEM systems are expected to make reliable and timely decisions regarding supposedly ongoing attacks and their priority. Scenario reconstruction techniques are central in helping SIEM systems summarize the current security situation and allow for faster administrator interventions.

Attack scenario reconstruction therefore refers to the process in which we try to find the most likely intrusion steps of an attack. Attack scenario reconstruction helps defenders understand how the attack was carried out and what may be next moves of the attacker, allowing them to identify system vulnerabilities, to acquire information that may become useful in future investigations and to organize a quick and effective response. For this reason it is very useful in DFIR (Digital Forensics Incident Response) processes.

Although attack scenario reconstruction mainly uses alerts for the pur pose of reconstruction, it can also access data from different host sources like audit logs, application logs; or network sources like IP flows, DNS logs or network traffic in general. Scenario reconstruction from homogeneous data uses only a single data source, they are simpler but may not be able to capture the system fully. Scenario reconstruction from heterogeneous data on the other hand, uses different types of data, offering a more complete view of the system. From the point of view of the type of the correlation method we can distinguish between similarity-based methods, sequential-based methods and case-based methods. Each using the namesake correlation method type for scenario building. The focus in this paper is showcasing an implementation of a scenario reconstruction mechanism for NIDS through the use of attack graphs based correlation.
