# DDoS Clearing House
## Converters
*Requirements:*
- python 3.8

### simple_iptables_converter.py
Converts a fingerprint json file to a set of iptables rules, v2 enhanced.

*Requirements:*
- iptables
- ipset

*Options:*
- `--version` prints version and exits
- `-v` or `--verbose` enable info-level logging
- `-d` or `--debug` enable debug-level logging
- `-f` or `--fingerprint` name of the fingerprint json file
- `-e` or `--enable` automatically enable the generated iptables rules

### multi_converter.py
Takes a single fingerprint json file and feeds it to the following modules.

### modules/misp_exporter.py
Converts a fingerprint json file to a MISP event and publish it on a MISP instance. It also downloads in the local directory a file containig the snort rules created from the MISP event. The MISP instance URL and automation key can be filled in directly in pymisp or as a cmd line argument or in the misp_exporter.py file.

*Requirements:*
- misp 2.4.148+

### modules/converter_iptables.py
Converts a fingerprint json file to a set of iptables rules.

### modules/converter_snort.py
Converts a fingerprint json file to a set of snort rules.

*Options:*
- `--version` prints version and exits
- `-f` or `--fingerprint` name of the fingerprint json file
- `-u` or `--misp_url` URL of the MISP instance on which to publish the event
- `-k` or `--misp_key` MISP automation key of the account on the MISP instance on which to publish the event
- `-d` or `--distribution` distribution level for the newly created event [0-3]
- `-i` or `--event_info` event info field, i.e., the event name in MISP
- `-a` or `--analysis_level` analysis level of the newly created event [0-2]
- `-t` or `--threat_level` threat level ID of the newly created event [1-4]
- `-s` or `--subnets` use subnets as attributes instead of ips (reccomended if the number of ip addresses is huge)
- `-g` or `--sharing_group` the group used to share the event on MISP
