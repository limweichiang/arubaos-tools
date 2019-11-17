# ArubaOS Tools
## Overview

This is a collection of tools written for Aruba Networks' Aruba OS 8 WLAN platform. Generally, this tool set is created to:
* Validate and sanitize configuration
* Perform health checks
* Recommend configuration best practices

## Tools Listing

* [Cluster Healthcheck](docs/cluster-healthcheck.md) - This tool identifies inappropriate
configurations on controller cluster members, and will SSH directly into cluster controllers to check for potential issues.
  * Using MM REST API Calls, the tool will check for vlan, ap-group, wlan, aaa, rf, ap, ids, ip access-list, user-role, netdestination, netservice, netdestination6, time-range & ifmap configuration types. The are flagged if cound configured on the controller node level.
  * Using SSH CLI directly to the controller, the tool will check for configuration failures (failure to fully sync controoller to MM), profile-errors (invalid configuration leading to unkown behavior), and broken clusters (isolated or L3 clusters states)

* [Mobility Master Differ](https://github.com/limweichiang/mm-differ) - For Mobility Master (MM) pairs configured for Master Redundancy, this tool recurses through each of the MMs configuration hierarchies levels and assesses if both the Master and Backup MM instances are in configuration sync.
