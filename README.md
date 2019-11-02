# aos8-tools
## Aruba OS 8 Cluster Health Check Tool
### Objective
This tool identifies inappropriate configurations on controller cluster members, which could lead to inconsistent controller cluster states. Checks are performed for the following configuration types, which generally should not reside directly on a cluster member configuration:
* vlan
* ap-group
* wlan
* aaa
* rf
* ap
* ids
* ip access-list
* user-role
* netdestination
* netservice
* netdestination6
* time-range
* ifmap 

The tool will recommend any identified configuration lines to be moved up to the parent configuration node of the cluster member controller.

### Requirements
* Python 3 (Developed with Python 3.6.3)

### Usage
```
$ python3 cluster-healthcheck.py -h
usage: cluster-healthcheck.py [-h] -m MM -u USER [-i]

Aruba OS 8 Cluster Health Check Tool - This tool identifies inappropriate
configurations on controller cluster members. Checks are performed for vlan,
ap-group, wlan, aaa, rf, ap, ids, ip access-list, user-role, netdestination,
netservice, netdestination6, time-range & ifmap configuration types.

optional arguments:
  -h, --help            show this help message and exit
  -m MM, --mm MM        Mobility Master IP / Hostname
  -u USER, --user USER  Mobility Master admin user name
  -i, --insecure        Allow insecure SSL cert / Skip cert verification

This software is licensed under the Apache License Version 2.0. It is
distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND,
either express or implied.
$ 
```
