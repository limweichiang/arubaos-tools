# Aruba OS 8 Tools
## Overview

This is a collection of tools written for Aruba Networks' Aruba OS 8 WLAN platform. Generally, this tool set is created to:
* Validate and sanitize configuration
* Perform health checks
* Recommend configuration best practices

## Tools Listing

* [Cluster Health Check](docs/cluster-healthcheck.md) - This tool identifies inappropriate
configurations on controller cluster members. Checks are performed for vlan, ap-group, wlan, aaa, rf, ap, ids, ip access-list, user-role, netdestination, netservice, netdestination6, time-range & ifmap configuration types.
* [Mobility Master Differ](https://github.com/limweichiang/mm-differ) - For Mobility Master (MM) pairs configured for Master Redundancy, this tool recurses through each of the MMs configuration hierarchies levels and assesses if both the Master and Backup MM instances are in configuration sync.
