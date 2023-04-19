#!/usr/bin/env python
import ss
import sys
import json
import csv
import subprocess
from subprocess import PIPE,Popen
import logging
import os
import datetime

############ ENV Settings ############
logging.basicConfig(filename='apply-audit-policy-to-db-service.log', filemode='w', format='%(name)s - %(levelname)s - %(message)s')

if len(sys.argv)<4:	
	print('[ERROR] Missing argument, please specify the policy name and site tree path to apply the policy to. Example: python apply_audit_policy_to_db_service.py "My Audit Policy Name" "Site Name/Server Group Name/DB Service Name 1,Site Name/Server Group Name/DB Service Name 2" "POST"')
	logging.warning('[ERROR] Missing argument, please specify the policy name and site tree path to apply the policy to. Example: python apply_audit_policy_to_db_service.py "My Audit Policy Name" "Site Name/Server Group Name/DB Service Name 1,Site Name/Server Group Name/DB Service Name 2" "POST"')
	quit()
 
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

def run():
	global MX_HOST 
	MX_HOST = CONFIG["mx"]["endpoint"]
	global SESSION_ID 
	policyName = sys.argv[1]
	siteTreePathAry = sys.argv[2].split(",")
	method = sys.argv[3]
	SESSION_ID = ss.login(MX_HOST, CONFIG["mx"]["username"], CONFIG["mx"]["password"])
	for path in siteTreePathAry:
		print("Making request with method '"+method+"' for policy '"+policyName+"' for services: '"+path+"'")
		response = ss.makeCall(MX_HOST, SESSION_ID, "/conf/dbServices/"+path+"/auditPolicies/"+policyName,method)
	print("Retrieving new policy config:")
	response = ss.makeCall(MX_HOST, SESSION_ID, "/conf/auditPolicies/"+policyName)
	responseObj = response.json()
	print(json.dumps(responseObj))

if __name__ == '__main__':
        run()