'''
Copyright 2019 Lim Wei Chiang

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
'''
import argparse
import getpass
import requests
import sys
import urllib3 # For disabling SSL warnings
import re
import modules.aos8 as aos8
import socket
try:
    import paramiko
except:
    print("Error importing Paramiko module, please install it with \"pip install paramiko\". Quitting...")
    exit(-1)

# Pass this a string of device type
# Returns True if it is a controller, False if not.
# Need to update for 9000 series controllers
def is_controller(device_type):
    if "mc-va" in device_type.lower():
        return True
    elif "a70" in device_type.lower():
        return True
    elif "a72" in device_type.lower():
        return True
    else:
        return False

# Pass this a list of devices
# Returns list of [{Controller Name, Controller MAC}]
def extract_controllers(devices):
    controllers = []
    
    for i in devices:
        if is_controller(i["type"]):
            controllers.append({"name": i["name"], "mac": i["mac"]})
    
    return controllers

# Recurses through configuration node hierarchy JSON to search for controllers.
# Returns dict of configuration path containing controllers, and list of 
# controller names and MAC addresses.
def get_controllers(config_node, parent_config_path=""):
    controllers = {}

    if isinstance(config_node, dict):

        # Getting correct string to describe the current config path (path)
        if config_node.get("type") != None:
            if config_node["type"] == "root":
                current_config_path = "/"
            elif config_node["type"] == "group":
                if parent_config_path == "/":
                    current_config_path = "/" + config_node["name"]
                else:
                    current_config_path = parent_config_path + "/" + config_node["name"]

        # If there are devices on this node, extract controllers
        if (config_node.get("devices") != None) and (len(config_node.get("devices")) > 0):
            current_node_controllers = extract_controllers(config_node["devices"])

            # Check for empty lists, and don't save these.
            if(len(current_node_controllers) > 0):
                controllers[current_config_path] = current_node_controllers

        # Call self to recurse if child nodes exist
        if (config_node.get("childnodes") != None) and (len(config_node.get("childnodes")) > 0):
            controllers.update(get_controllers(config_node["childnodes"], current_config_path))

    # Some nodes are a list, and need to be iterated through
    elif isinstance(config_node, list):
        for i in config_node:
            if i.get("type") != None:
                if i["type"] == "root":
                    i_current_config_path = "/"
                elif i["type"] == "group":
                    if parent_config_path == "/":
                        i_current_config_path = "/" + i["name"]
                    else:
                        i_current_config_path = parent_config_path + "/" + i["name"]

            # If there are devices on this node, extract controllers
            if (i.get("devices") != None) and (len(i.get("devices")) > 0):
                i_current_node_controllers = extract_controllers(i["devices"])

                # Check for empty lists, and don't save these.
                if(len(i_current_node_controllers) > 0):
                    controllers[i_current_config_path] = i_current_node_controllers

            # Call self to recurse if child nodes exist
            if (i.get("childnodes") != None) and (len(i.get("childnodes")) > 0):
                controllers.update(get_controllers(i["childnodes"], i_current_config_path))

    return controllers

# Create a dict of config (key), with list of subsconfig (value) if available. Example:
# 
# Original:
# interface gigabitethernet 0/0/0
#     description GE0/0/0
#     switchport mode trunk
#     no spanning-tree
#     trusted
#     trusted vlan 1-4094
# 
# Converted:
# {
#    'interface gigabitethernet 0/0/0':
#       ['description GE0/0/0', 'switchport mode trunk', 'no spanning-tree', 'trusted', 'trusted vlan 1-4094']
#  }
def config_to_dict(config):
    config_dict = {}
    subconfig_parent = ""

    for l in config.split('\n'):
        if l == "":
            pass
        elif re.match("^\S", l):
            config_dict[l] = []
            subconfig_parent = l
        elif re.match("^\s*\S*", l):
            config_dict[subconfig_parent].append(l.lstrip())
        else:
            pass

    return config_dict

# Prints each line of a subconfig, prepended with a string for formatting
def print_subconfig_list(subconfig_list, prepend_str=""):
    for i in subconfig_list:
        print(prepend_str + i)

## Checks for and returns True if VLANs other than that of the Controller IP VLAN is found.
def config_check_vlan(config_line, controller_ip_vlan):
    if re.match("^vlan\s[0-9]{1,4}$", config_line):
        if config_line.split(' ')[1] != str(controller_ip_vlan):
            return True
    elif re.match("^vlan-name\s[a-zA-Z0-9\-\_]*$", config_line):
        return True
    elif re.match("^vlan\s[a-zA-Z0-9\-\_]*\s[0-9]{1,4}$", config_line):
        return True
    else:
        return False

## Checks for and returns True if config contains match_str
def config_check(config_line, match_str):
    re_pattern = "^" + match_str + "\s"

    if re.match(re_pattern, config_line):
        return True
    else:
        return False

# Obtain arguments
parser = argparse.ArgumentParser(
    description="Aruba OS 8 Cluster Health Check Tool - This tool identifies inappropriate configurations on controller cluster members. Checks are performed for vlan, ap-group, wlan, aaa, rf, ap, ids, ip access-list, user-role, netdestination, netservice, netdestination6, time-range & ifmap configuration types.", 
    epilog="This software is licensed under the Apache License Version 2.0. It is distributed on an \"AS IS\" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.")
parser.add_argument("-m", "--mm", required=True, help="Mobility Master IP / Hostname")
parser.add_argument("-u", "--user", required=True, help="Mobility Master admin user name")
parser.add_argument("-i", "--insecure", required=False, action="store_true", help="Allow insecure SSL cert / Skip cert verification")
args = parser.parse_args()

# Process argparse arguments
mm_host = args.mm.strip()
mm_user = args.user.strip()
mm_secure_login = True
if args.insecure: 
    print("WARNING! You have used the \"-i\" or \"--insecure\" option; The tool will NOT validate the SSL certicate presented by the Mobility Master.")
    print("By continuing, your credentials could be compromised by malicious parties.")
    insecure_login_input = input("Enter 'c' to continue in spite of the security risk, or anything else to exit: ")
    
    if insecure_login_input.replace('\n', '').lower() == "c":
        mm_secure_login = False
        urllib3.disable_warnings()
    else:
        sys.exit()

# Get password
mm_passwd = getpass.getpass("Password for " + mm_user +": ")

# Build required URL strings
mm_base_url = "https://" + mm_host + ":4343/"
mm_login_url = mm_base_url + "v1/api/login"
mm_config_node_hierarchy_url = mm_base_url + "/v1/configuration/object/node_hierarchy"
mm_cluster_membership_url = mm_base_url + "/v1/configuration/object/cluster_membership_profile"
mm_controller_ip_vlan_url = mm_base_url + "v1/configuration/object/ctrl_ip"
mm_controller_intf_vlan_url = mm_base_url + "v1/configuration/object/int_vlan"
mm_show_command_url = mm_base_url + "/v1/configuration/showcommand"

# Initiate login with authentication, and persistently store cookies
http_session = requests.Session()
http_session.verify = mm_secure_login
mm_login_response = http_session.get(mm_login_url, params={'username': mm_user, 'password': mm_passwd})

#print("Login Response: " + mm_login_response.text)

# Login to store UIDARUBA
if mm_login_response:
    http_session_arubauid =  mm_login_response.json()['_global_result']['UIDARUBA']
    print("Logged in sucessfully with HTTP status code ", end = '')
    print(mm_login_response.status_code, end = '')
    print(".")
    print("Received UIDARUBA: " + http_session_arubauid)
else:
    print("Login failed with HTTP status code ", end = '')
    print(mm_login_response.status_code, end = '')
    print(". Exiting...")
    sys.exit()

# Pull configuration node hierarchy
mm_config_node_hierarchy_response = http_session.get(mm_config_node_hierarchy_url, params={'UIDARUBA': http_session_arubauid})

if mm_config_node_hierarchy_response:
    #print("Successfully received Configuration Node Hierarchy with status code ", end = '')
    #print(mm_config_node_hierarchy_response.status_code, end = '')
    #print(".")
    #print(mm_config_node_hierarchy_response.text)
    mm_config_node_hierarchy = mm_config_node_hierarchy_response.json()
else:
    print("Failed to get Configuration Node Hierarchy ", end = '')
    print(mm_config_node_hierarchy_response.status_code, end = '')
    print(". Exiting...")
    sys.exit(-1)

# Get a dict of configuration nodes containing controllers, and a list of
# those controllers.
controllers = get_controllers(mm_config_node_hierarchy)

# Create a dict of active controller cluster profiles (key), and a list of
# cluster controllers (value).
controller_clusters = {}
for k,v in controllers.items():
    for i in v:
        controller_path = k + "/" + i["mac"]
        mm_cluster_membership_response = http_session.get(mm_cluster_membership_url, params={'UIDARUBA': http_session_arubauid, 'config_path' : controller_path})

        if (mm_cluster_membership_response):
            cluster_membership = mm_cluster_membership_response.json()
            if (cluster_membership["_data"].get("cluster_membership_profile") != None) and (cluster_membership["_data"][ "cluster_membership_profile"].get("profile") != None):
                cluster_group = cluster_membership["_data"][ "cluster_membership_profile"]["profile"]

                if(controller_clusters.get(cluster_group) == None):
                    controller_clusters[cluster_group] = []
                    controller_clusters[cluster_group].append({"controller-path": controller_path, "controller-parent-path": k, "controller-mac": i["mac"], "controller-name": i["name"]})
                else:
                    controller_clusters[cluster_group].append({"controller-path": controller_path, "controller-parent-path": k, "controller-mac": i["mac"], "controller-name": i["name"]})

# Append controller IP VLAN and IP address to list of cluster controllers.
for k,v in controller_clusters.items():
    for i in v:
        mm_controller_ip_vlan_response = http_session.get(mm_controller_ip_vlan_url, params={'UIDARUBA': http_session_arubauid, 'config_path' : i["controller-path"]})
         
        # Get controller IP VLAN for each controller in a cluster
        if (mm_controller_ip_vlan_response):
            controller_ip_vlan = mm_controller_ip_vlan_response.json()

            if (controller_ip_vlan["_data"].get("ctrl_ip") != None) and (controller_ip_vlan["_data"][ "ctrl_ip"].get("id") != None):
                i["controller-ip-vlan"] = controller_ip_vlan["_data"][ "ctrl_ip"]["id"]

                # Based on identified controller IP VLAN, get controller IP.
                mm_controller_intf_vlan_response = http_session.get(mm_controller_intf_vlan_url, params={'UIDARUBA': http_session_arubauid, 'config_path' : i["controller-path"]})

                if (mm_controller_intf_vlan_response):
                    controller_vlan_intf = mm_controller_intf_vlan_response.json()

                    if controller_vlan_intf["_data"].get("int_vlan") != None:
                        for j in controller_vlan_intf["_data"]["int_vlan"]:
                            if (j.get("id") == i["controller-ip-vlan"]) and (j.get("int_vlan_ip") != None):
                                i["controller-ip"] = j["int_vlan_ip"]["ipaddr"]

        # While we're here, might as well grab configuration committed as well
        mm_show_command_str = "show configuration committed " + i["controller-path"]
        mm_show_command_response = http_session.get(mm_show_command_url, params={"json": "1", "command": mm_show_command_str, 'UIDARUBA': http_session_arubauid})

        if (mm_show_command_response):
            mm_show_command = mm_show_command_response.json()
            i["controller-committed-config"] = mm_show_command["_data"][0].replace(" \n", "\n")

            # WIP Need to break config into dict
            i["controller-committed-config-dict"] = config_to_dict(i["controller-committed-config"])

print("")               
print("Controller Clusters Found")
print("=========================")
print("")

cluster_count = 0
for k,v in controller_clusters.items():
    cluster_count += 1
    print("Cluster", cluster_count, end='')
    print(":", k)

    for i in v:
        print("-- ", end="")
        print(i["controller-name"] + " (MAC: " + i["controller-mac"] + ") with IP address " + i["controller-ip"] + " at " + i["controller-path"])
    
    print("")

# Config checking Loop
for k,v in controller_clusters.items():
    for i in v:
        # Create a copy, we may want to eliminate checked configurations
        target_controller_config = i["controller-committed-config-dict"]

        ### List of variables used for each check/warn combo
        problem = {}
        problem["vlans"] = {}
        problem["ap-group"] = {}
        problem["wlan"] = {}
        problem["aaa"] = {}
        problem["rf"] = {}
        problem["ap"] = {}
        problem["ids"] = {}
        problem["acl"] = {}
        problem["user"] = {}
        problem["netdestination"] = {}
        problem["netservice"] = {}
        problem["netdestination6"] = {}
        problem["timerange"] = {}
        problem["ifmap"] = {}
        problem["config-failure"] = ""
        problem["profile-errors"] = ""

        ### Controller configs and subconfigs are examined line-by-line within this loop. All checks to be implemented here. ###
        for config_k, config_v in target_controller_config.items():

            # Identify VLANs other than controller IP VLAN
            if config_check_vlan(config_k, i["controller-ip-vlan"]):
                problem["vlans"][config_k] = config_v

            # Identify AP Group configs
            elif config_check(config_k, "ap-group"):
                problem["ap-group"][config_k] = config_v

            # Identify WLAN configs
            elif config_check(config_k, "wlan"):
                problem["wlan"][config_k] = config_v
                
            # Identify AAA configs
            elif config_check(config_k, "aaa"):
                problem["aaa"][config_k] = config_v

            # Identify RF configs
            elif config_check(config_k, "rf"):
                problem["rf"][config_k] = config_v

            # Identify AP configs
            elif config_check(config_k, "ap"):
                problem["ap"][config_k] = config_v

            # Identify IDS configs
            elif config_check(config_k, "ids"):
                problem["ids"][config_k] = config_v

            # Identify ACL configs
            elif config_check(config_k, "ip access-list"):
                problem["acl"][config_k] = config_v

            # Identify User Role configs
            elif config_check(config_k, "user-role"):
                problem["user"][config_k] = config_v
            
            # Identify Net Destination configs
            elif config_check(config_k, "netdestination"):
                problem["netdestination"][config_k] = config_v

            # Identify Net Service configs
            elif config_check(config_k, "netservice"):
                problem["netservice"][config_k] = config_v

            # Identify Net Destination IPv6 configs
            elif config_check(config_k, "netdestination6"):
                problem["netdestination6"][config_k] = config_v

            # Identify Time Range configs
            elif config_check(config_k, "time-range"):
                problem["timerange"][config_k] = config_v

            # Identify IF Map configs
            elif config_check(config_k, "ifmap"):
                problem["ifmap"][config_k] = config_v




        ### Controller config issues are flagged out here ###
        recommend_title_str = "Recommendations for " + i["controller-name"] + " in cluster " + k + " at " + i["controller-path"]
        print(recommend_title_str)
        print('='*len(recommend_title_str) + '\n')

        if len(problem["vlans"]) > 0:
            print("The following VLAN configs should be moved to parent configuration node \"" + i["controller-parent-path"] + "\" or higher:")

            for vlan_k, vlan_v in problem["vlans"].items():
                print("-", vlan_k)
            print("")

        if len(problem["ap-group"]) > 0:
            print("The following AP Group configs should be moved to parent configuration node \"" + i["controller-parent-path"] + "\" or higher:")

            for apg_k, apg_v in problem["ap-group"].items():
                print("-", apg_k)
                if len(apg_v) > 0:
                    print_subconfig_list(apg_v, "    ")
            print("")

        if len(problem["wlan"]) > 0:
            print("The following WLAN configs should be moved to parent configuration node \"" + i["controller-parent-path"] + "\" or higher:")

            for wlan_k, wlan_v in problem["wlan"].items():
                print("-", wlan_k)
                if len(wlan_v) > 0:
                    print_subconfig_list(wlan_v, "    ")
            print("")

        if len(problem["aaa"]) > 0:
            print("The following AAA configs should be moved to parent configuration node \"" + i["controller-parent-path"] + "\" or higher:")

            for aaa_k, aaa_v in problem["aaa"].items():
                print("-", aaa_k)
                if len(aaa_v) > 0:
                    print_subconfig_list(aaa_v, "    ")
            print("")

        if len(problem["rf"]) > 0:
            print("The following RF configs should be moved to parent configuration node \"" + i["controller-parent-path"] + "\" or higher:")

            for rf_k, rf_v in problem["rf"].items():
                print("-", rf_k)
                if len(rf_v) > 0:
                    print_subconfig_list(rf_v, "    ")
            print("")

        if len(problem["ap"]) > 0:
            print("The following AP configs should be moved to parent configuration node \"" + i["controller-parent-path"] + "\" or higher:")

            for ap_k, ap_v in problem["ap"].items():
                print("-", ap_k)
                if len(ap_v) > 0:
                    print_subconfig_list(ap_v, "    ")
            print("")

        if len(problem["ids"]) > 0:
            print("The following WIDS configs should be moved to parent configuration node \"" + i["controller-parent-path"] + "\" or higher:")

            for ids_k, ids_v in problem["ids"].items():
                print("-", ids_k)
                if len(ids_v) > 0:
                    print_subconfig_list(ids_v, "    ")
            print("")

        if len(problem["acl"]) > 0:
            print("The following ACL configs should be moved to parent configuration node \"" + i["controller-parent-path"] + "\" or higher:")

            for acl_k, acl_v in problem["acl"].items():
                print("-", acl_k)
                if len(acl_v) > 0:
                    print_subconfig_list(acl_v, "    ")
            print("")

        if len(problem["user"]) > 0:
            print("The following User Role configs should be moved to parent configuration node \"" + i["controller-parent-path"] + "\" or higher:")

            for user_k, user_v in problem["user"].items():
                print("-", user_k)
                if len(user_v) > 0:
                    print_subconfig_list(user_v, "    ")
            print("")

        if len(problem["netdestination"]) > 0:
            print("The following Net Destination configs should be moved to parent configuration node \"" + i["controller-parent-path"] + "\" or higher:")

            for netdestination_k, netdestination_v in problem["netdestination"].items():
                print("-", netdestination_k)
                if len(netdestination_v) > 0:
                    print_subconfig_list(netdestination_v, "    ")
            print("")

        if len(problem["netservice"]) > 0:
            print("The following Net Service configs should be moved to parent configuration node \"" + i["controller-parent-path"] + "\" or higher:")

            for netservice_k, netservice_v in problem["netservice"].items():
                print("-", netservice_k)
                if len(netservice_v) > 0:
                    print_subconfig_list(netservice_v, "    ")
            print("")

        if len(problem["netdestination6"]) > 0:
            print("The following Net Destination IPv6 configs should be moved to parent configuration node \"" + i["controller-parent-path"] + "\" or higher:")

            for netdestination6_k, netdestination6_v in problem["netdestination6"].items():
                print("-", netdestination6_k)
                if len(netdestination6_v) > 0:
                    print_subconfig_list(netdestination6_v, "    ")
            print("")

        if len(problem["timerange"]) > 0:
            print("The following Time Range configs should be moved to parent configuration node \"" + i["controller-parent-path"] + "\" or higher:")

            for timerange_k, timerange_v in problem["timerange"].items():
                print("-", timerange_k)
                if len(timerange_v) > 0:
                    print_subconfig_list(timerange_v, "    ")
            print("")

        if len(problem["ifmap"]) > 0:
            print("The following IF Map configs should be moved to parent configuration node \"" + i["controller-parent-path"] + "\" or higher:")

            for ifmap_k, ifmap_v in problem["ifmap"].items():
                print("-", ifmap_k)
                if len(ifmap_v) > 0:
                    print_subconfig_list(ifmap_v, "    ")
            print("")

        # SSH login to individual controllers to run detailed CLI checks.
        controller_ssh = aos8.AOS8SSHClient()
        controller_secure_login = True
        controller_skip = False

        # Begin Connect: Only 2 tries required with 1 retry allowed if this is not a known SSH host and user wants to ignore security checks.
        for connect_tries in range(2):
            try:
                controller_ssh.aos8connect(i["controller-ip"], mm_user, mm_passwd, secure_login = controller_secure_login)
                break
            except paramiko.ssh_exception.SSHException as ssh_e:
                #Paramiko's exception handling does everything with SSHException which is bonkers.
                if "not found in known_hosts" in str(ssh_e).lower(): # Catch SSHException for unknown host key.
                    print("WARNING! " + i["controller-ip"] + " is not a known SSH host. By continuing, your credentials could be compromised by malicious parties.")
                    cont_input = input("Enter 'c' to continue in spite of the security risk, or anything else to skip SSH checks on this controller: ")
                    if cont_input.replace('\n', '').lower() == "c":
                        controller_secure_login = False
                        continue
                    else:
                        print("Skipping SSH checks for controller " + i["controller-ip"] + ".")
                        controller_skip = True
                        break
                elif "authentication failed" in str(ssh_e).lower(): # Catch SSHException for Auth Fail, in spite of an ACTUAL exception existing for Auth Failed
                    print("Authentication failed. SSH checks expect controller admin credentials (username & password) to be identical to that used for the MM.")
                    print("Skipping SSH checks for controller " + i["controller-ip"] + ".")
                    controller_skip = True
                    break
            except socket.error as sock_e:
                print("Cannot connect to " + i["controller-ip"] + ". Skipping SSH checks for this controller.")
                #print(sock_e)
                controller_skip = True
                break

        if controller_skip == False:
            # Needs more exception handling here.
            controller_ssh.aos8invoke_shell()
            problem["config-failure"] = controller_ssh.aos8execute("show configuration failure")
            
            if len(controller_ssh.aos8execute("show profile-errors | exclude \"-----,Invalid Profiles,Profile  Error\"")) > 0:
                problem["profile-errors"] = controller_ssh.aos8execute("show profile-errors")
            controller_ssh.close()

            if len(problem["config-failure"]) > 0:
                print("Configuration failure found on this controller. Call TAC with results of \"show configuration failure\".")
                print_subconfig_list(problem["config-failure"].split("\n"), "    ")
            else:
                print("No configuration failure found using \"show configuration failure\".")
            print("")

            if len(problem["profile-errors"]) > 0:
                print("Profile errors found on this controller. Please correct the following errors.")
                print_subconfig_list(problem["profile-errors"].split("\n"), "    ")
            else:
                print("No profile errors found using \"show profile-errors\".")
        print("")