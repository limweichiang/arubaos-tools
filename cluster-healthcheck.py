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
if args.insecure: mm_secure_login = False

# Get password
mm_passwd = getpass.getpass("Password for " + mm_user +": ")

# Build required URL strings
mm_base_url = "https://" + mm_host + ":4343/"
mm_login_url = mm_base_url + "v1/api/login"
mm_config_node_hierarchy_url = mm_base_url + "/v1/configuration/object/node_hierarchy"

# Initiate login with authentication, and persistently store cookies
http_session = requests.Session()
http_session.verify = mm_secure_login
mm_login_response = http_session.get(mm_login_url, params={'username': mm_user, 'password': mm_passwd})

#print("Login Response: " + mm_login_response.text)

# Login to store cookie
if mm_login_response:
    print("Logged in sucessfully with status code ", end = '')
    print(mm_login_response.status_code, end = '')
    print(".")
else:
    print("Login failed with status code ", end = '')
    print(mm_login_response.status_code, end = '')
    print(". Exiting...")
    exit

# Cookie check
print("Cookie Monster checking for cookies... " +  http_session.cookies.value)

# Pull configuration node hierarchy
mm_config_node_hierarchy_response = http_session.get(mm_config_node_hierarchy_url)

if mm_config_node_hierarchy_response:
    print("Successfully received Configuration Node Hierarchy with status code ", end = '')
    print(mm_config_node_hierarchy_response.status_code, end = '')
    print(".")
    print(mm_config_node_hierarchy_response.text)
else:
    print("Failed to get Configuration Node Hierarchy ", end = '')
    print(mm_config_node_hierarchy_response.status_code, end = '')
    print(". Exiting...")
    exit