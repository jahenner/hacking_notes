# Threat Intel
## Applying Threat Intel
To help collect CTI and TTPs it is often easier to start with a framework such as MITRE ATT&CK, TIBER-EU, and OST Map. These frameworks help collect known TTPs and categorize them based on varying characteristics:

1) Threat Group
2) Kill Chain Phase
3) Tactic
4) Objective/Goal

Start by selecting an adversary to emulate. Then identify all TTPs categorized with that chosen adversary and map them to a known cyber kill chain.

Using the specific TTPs associated with the targeted adversary is used as a planning technique and not an area of focus. It is possible that only one member of the red cell can collect the information.

## TTP Mapping
This tactic is employed by the red cell to map adversaries' collected TTPs to a standard cyber kill chain. First you will need to select a target, which can be based on:

1) Target Industry
2) Employed Attack Vectors
3) Country of Origin
4) Other Factors

### Example using [APT39](https://attack.mitre.org/groups/G0087/)
APT39 is a cyber-espionage group run by the Iranian Ministry, known for targeting a wide variety of industries. This example will also be using the Lockheed Martin Cyber Kill Chain to map TTPs.

We can collect TTPs from MITRE ATT&CK framework. ATT&CK has a Navigator to help visualize each TTP and categorize its place in the kill chain.

To use the Navigator go to the groups summary page. It is located next to the Techniques Used section. You can download or view the document. It highlights the TTPs in their respective place in the kill chain.

## Other Applications of CTI
CTI can be used during engagement execution to emulate the adversary's behavioral characteristics, such as:

* C2 Traffic
    * User Agents
    * Ports, Protocols
    * Listener Profiles
* Malware and Tooling
    * IOCs
    * Behaviors

### C2 Traffic Emulation
[Malleable profiles](https://www.cobaltstrike.com/help-malleable-c2) allow a red team operator to control multiple aspects of a C2's listener traffic.

Information to be implemented in the profile can be gathered from ISACs and collected IOCs or packet captures, including:

* Host Headers
* POST URIs
* Server REsponses and Headers

The gathered traffic can aid a red team to make their traffic look similar to the targeted adversary to get closer to the goal of adversary emulation.

### Malware and Tooling
If an adversary uses a custom dropper, the red team can emulate the dropper by:

* Identifying traffic
* Observing syscalls and API calls
* Identifying overall dropper behavior and objective
* Tampering with file signatures and IOCs