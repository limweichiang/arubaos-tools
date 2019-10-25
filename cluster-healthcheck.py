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
import urllib3

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

# Obtain arguments
parser = argparse.ArgumentParser(description="Aruba OS 8 Cluster Health Check Tool")
parser.add_argument("-m", "--mm", required=True, help="Mobility Master IP / Hostname")
parser.add_argument("-u", "--user", required=True, help="Mobility Master admin user name")
parser.add_argument("-i", "--insecure", required=False, action="store_true", help="Allow insecure SSL cert / Skip cert verification")
args = parser.parse_args()

# Process argparse arguments
mm_host = args.mm.strip()
mm_user = args.user.strip()
mm_secure_login = True
if args.insecure: 
    mm_secure_login = False
    urllib3.disable_warnings()

# Get password
mm_passwd = getpass.getpass("Password for " + mm_user +": ")

# Build required URL strings
mm_base_url = "https://" + mm_host + ":4343/"
mm_login_url = mm_base_url + "v1/api/login"
mm_config_node_hierarchy_url = mm_base_url + "/v1/configuration/object/node_hierarchy"
mm_cluster_membership_url = mm_base_url + "/v1/configuration/object/cluster_membership_profile"
mm_controller_ip_vlan_url = mm_base_url + "v1/configuration/object/ctrl_ip"
mm_controller_intf_vlan_url = mm_base_url + "v1/configuration/object/int_vlan"

# Initiate login with authentication, and persistently store cookies
http_session = requests.Session()
http_session.verify = mm_secure_login
mm_login_response = http_session.get(mm_login_url, params={'username': mm_user, 'password': mm_passwd})

#print("Login Response: " + mm_login_response.text)

# Login to store UIDARUBA
if mm_login_response:
    http_session_arubauid =  mm_login_response.json()['_global_result']['UIDARUBA']
    print("Logged in sucessfully with status code ", end = '')
    print(mm_login_response.status_code, end = '')
    print(".")
    print("Received UIDARUBA: " + http_session_arubauid)
else:
    print("Login failed with status code ", end = '')
    print(mm_login_response.status_code, end = '')
    print(". Exiting...")
    exit

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
                    controller_clusters[cluster_group].append({"controller-path": controller_path, "controller-mac": i["mac"], "controller-name": i["name"]})
                else:
                    controller_clusters[cluster_group].append({"controller-path": controller_path, "controller-mac": i["mac"], "controller-name": i["name"]})

# Append controller IP VLAN and IP address to list of cluster controllers.
for k,v in controller_clusters.items():
    for i in v:
        mm_controller_ip_vlan_response = http_session.get(mm_controller_ip_vlan_url, params={'UIDARUBA': http_session_arubauid, 'config_path' : i["controller-path"]})
         
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