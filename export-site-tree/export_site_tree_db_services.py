#!/usr/bin/env python
import ss
import sys
import json
import logging
import os
import datetime

############ ENV Settings ############
logging.basicConfig(filename='export-site-tree-db-services.log', filemode='w', format='%(name)s - %(levelname)s - %(message)s')
 
############ GLOBALS ############
CONFIGFILE = 'config.json'
# CONFIGFILE = '/var/user-data/config.json'
CONFIG = {}
try:
    with open(CONFIGFILE, 'r') as data:
        CONFIG = json.load(data)
        logging.warning("Loaded "+CONFIGFILE+" configuration")
except:
    print("Missing \""+CONFIGFILE+"\" file, create file named config.json with the following contents:\n{\n  \"log_level\": \"debug\",\n  \"environment\": \"dev\",\n  \"dataset-name\": \"db-logins\",\n  \"mx\": {\n    \"endpoint\": \"https://127.0.0.1:8083\",\n    \"username\": \"youruser\",\n    \"password\": \"yourpassword\"\n  }\n}")
    logging.warning("Missing \""+CONFIGFILE+"\" file, create file named config.json with the following contents:\n{\n  \"log_level\": \"debug\",\n  \"environment\": \"dev\",\n  \"dataset-name\": \"db-logins\",\n  \"mx\": {\n    \"endpoint\": \"https://127.0.0.1:8083\",\n    \"username\": \"youruser\",\n    \"password\": \"yourpassword\"\n  }\n}")
    exit()
SITES = {}
TIMESTAMP = datetime.datetime.now().isoformat()

def run():
	global MX_HOST 
	MX_HOST = CONFIG["mx"]["endpoint"]
	global SESSION_ID 
	SESSION_ID = ss.login(MX_HOST, CONFIG["mx"]["username"], CONFIG["mx"]["password"])
	response = ss.makeCall(MX_HOST, SESSION_ID, "/conf/sites")
	responseObj = response.json()
	for siteName in responseObj["sites"]:
		response = ss.makeCall(MX_HOST, SESSION_ID, "/conf/serverGroups/"+siteName)
		responseObj = response.json()
		for serverGroupName in responseObj["server-groups"]:
			response = ss.makeCall(MX_HOST, SESSION_ID, "/conf/dbServices/"+siteName+"/"+serverGroupName)
			responseObj = response.json()
			for dbServiceName in responseObj["db-services"]:        
				print(siteName+"/"+serverGroupName+"/"+dbServiceName)
	
if __name__ == '__main__':
        run()