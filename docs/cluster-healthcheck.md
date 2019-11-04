# Aruba OS 8 Cluster Health Check Tool
## Objective
This tool identifies inappropriate configurations on controller cluster members, which could lead to inconsistent  cluster states. For exanmple, the following issues would be detected:
* VLAN configuration that exists on some cluster members, but not others - Results in profile errors, traffic blackhole.
* WLAN / Virtual AP configuration that exists on some clusters, but not others - APs using controller with WLAN / Virtual AP configuration as A-AAC will broadcast SSID, others will not.
* AAA configuration manually defined on cluster members - Manual config leads on inconsistent config on cluster members due to typos; User authentication fails on some members but succeed on others.

Checks are performed for the following configuration types, which generally should not reside directly on a cluster member configuration:
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

## Requirements
* Python 3 (Developed with Python 3.6.3)

## Usage
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
## Example
```
$ python3 cluster-healthcheck.py --mm 192.168.11.31 --user admin -i
Password for admin: 
Logged in sucessfully with status code 200.
Received UIDARUBA: 0c312345-4321-8735-9178-9992c9b8a2e

Controller Clusters Found
=========================

Cluster 1: wlan-cluster
-- controller2 (MAC: 00:0c:29:aa:bb:22) with IP address 192.168.12.42 at /md/cluster/00:0c:29:aa:bb:22
-- controller1 (MAC: 00:0c:29:aa:bb:11) with IP address 192.168.12.41 at /md/cluster/00:0c:29:aa:bb:11

Recommendations for controller2 in cluster wlan-cluster at /md/cluster/00:0c:29:aa:bb:22
======================================================================================

The following AP Group configs should be moved to parent configuration node "/md/cluster" or higher:
- ap-group "apg-test"

The following AAA configs should be moved to parent configuration node "/md/cluster" or higher:
- aaa authentication-server radius "radius-testserver"
    host "1.1.1.1"
    key 900000bd6401e6666667958f9c5a4ea3
- aaa server-group "radius-testgroup"
    load-balance
    auth-server radius-testserver position 1

Recommendations for controller1 in cluster wlan-cluster at /md/cluster/00:0c:29:aa:bb:11
======================================================================================

The following VLAN configs should be moved to parent configuration node "/md/cluster" or higher:
- vlan 777
- vlan-name test
- vlan test 102

The following WLAN configs should be moved to parent configuration node "/md/cluster" or higher:
- wlan ssid-profile "unusual-ssid"
    essid "unsual-ssid"

The following AAA configs should be moved to parent configuration node "/md/cluster" or higher:
- aaa rfc-3576-server "1.1.1.1"
    key 57e62222222222d54a999999999907c1
- aaa profile "aaaprof_test"

The following RF configs should be moved to parent configuration node "/md/cluster" or higher:
- rf dot11a-radio-profile "test"
    eirp-min 6
    eirp-max 12
```
