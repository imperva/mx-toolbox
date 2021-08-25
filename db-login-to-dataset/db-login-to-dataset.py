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
logging.basicConfig(filename='db-login-to-dataset.log', filemode='w', format='%(name)s - %(levelname)s - %(message)s')

if len(sys.argv)<2:	
	print("[ERROR] Missing argument, please specify the ip address to lookup. Example: python db-login-to-dataset.py 1.2.3.4")
	logging.warning("[ERROR] Missing argument, please specify the ip address to lookup. Example: python db-login-to-dataset.py 1.2.3.4")
	quit()

############ ENV Settings ############
logging.basicConfig(filename='db-login-to-dataset.log', filemode='w', format='%(name)s - %(levelname)s - %(message)s')
 
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


global CACHESESSION 
CACHESESSION = True
TIMESTAMP = datetime.datetime.now().isoformat()
DEBUG = True
CREATE_DATASETS = False
DATASET_WORKSTATION = CONFIG["dataset-name"]+" Workstations"
DATASET_NOT_WORKSTATION = CONFIG["dataset-name"]+" Non-Workstations"
DATASET_UNRESOLVED_HOSTS = CONFIG["dataset-name"]+" Unresolved Hosts"
HOSTNAME_PREFIXES = ["1.0.0","WM","a23","ip-"]
SESSIONPATH = "currentsession.txt"
IPADDR = sys.argv[1]

datasetCols_workstation = {"dataset-name": DATASET_WORKSTATION,"columns": [{"name":"ip","key":True},{"name":"hostname","key":False}]}
datasetCols_non_workstation = {"dataset-name": DATASET_NOT_WORKSTATION,"columns": [{"name":"ip","key":True},{"name":"hostname","key":False}]}
datasetCols_unresolved = {"dataset-name": DATASET_UNRESOLVED_HOSTS,"columns": [{"name":"ip","key":True}]}

def upsertDataset(dataset_name, dataset_obj):
	logging.warning("Checking for dataset: '"+dataset_name+"'")
	response = ss.makeCall(MX_HOST, SESSION_ID, "/conf/dataSets/"+dataset_name+"/data","GET")
	responseObj = response.json()
	if response.status_code!=200:
		logging.warning("Dataset '"+dataset_name+"' not found, creating dataset now")
		response = ss.makeCall(MX_HOST, SESSION_ID, "/conf/dataSets/createDataset?caseSensitive=false","POST",json.dumps(dataset_obj))

def run():
	global MX_HOST 
	MX_HOST = CONFIG["mx"]["endpoint"]
	global SESSION_ID 
	SESSION_ID = ss.getSession(MX_HOST, CONFIG["mx"]["username"], CONFIG["mx"]["password"])
	if CREATE_DATASETS:
		upsertDataset(DATASET_WORKSTATION, datasetCols_workstation)
		upsertDataset(DATASET_NOT_WORKSTATION, datasetCols_non_workstation)
		upsertDataset(DATASET_UNRESOLVED_HOSTS, datasetCols_unresolved)

	# Run nslookup
	pipe = Popen(['nslookup',IPADDR], stdout=PIPE)
	rawoutput = pipe.communicate()		
	if (str(rawoutput[0]).find("** server can't find")!=-1):
		logging.warning("Can not resolve hostname for '"+IPADDR+"', adding IP to '"+DATASET_UNRESOLVED_HOSTS+"' dataset.")
		datasetRecordObj = {"action":"add","records":[{"ip":IPADDR}]}
		response = ss.makeCall(MX_HOST, SESSION_ID, "/conf/dataSets/"+DATASET_UNRESOLVED_HOSTS+"/data","PUT",json.dumps(datasetRecordObj))
	elif (str(rawoutput[0]).find("hostname is NOT present")!=-1):
		logging.warning("Hostname is not present for for '"+IPADDR+"', adding IP to '"+DATASET_NOT_WORKSTATION+"' dataset.")
		datasetRecordObj = {"action":"add","records":[{"ip":IPADDR,"hostname":"no hostname found"}]}
		response = ss.makeCall(MX_HOST, SESSION_ID, "/conf/dataSets/"+DATASET_NOT_WORKSTATION+"/data","PUT",json.dumps(datasetRecordObj))
	else:
		hostname = str(rawoutput[0]).split("name = ").pop(1).split("\n").pop(0)
		datasetRecordObj = {"action":"add","records":[{"ip":IPADDR,"hostname":hostname}]}
		isMatch = False
		for prefix in HOSTNAME_PREFIXES:
			if hostname[0:len(prefix)]==prefix:
				isMatch = True
		curRecords = ss.makeCall(MX_HOST, SESSION_ID, "/conf/dataSets/"+DATASET_NOT_WORKSTATION+"/data","GET")
		curRecordsObj = curRecords.json()
		isPresent = False
		for record in curRecordsObj["records"]:
			if hostname==record["hostname"] and IPADDR==record["ip"]:
				isPresent=True
		if isMatch:
			if not isPresent:
				response = ss.makeCall(MX_HOST, SESSION_ID, "/conf/dataSets/"+DATASET_WORKSTATION+"/data","PUT",json.dumps(datasetRecordObj))
		else:
			response = ss.makeCall(MX_HOST, SESSION_ID, "/conf/dataSets/"+DATASET_NOT_WORKSTATION+"/data","PUT",json.dumps(datasetRecordObj))
	
if __name__ == '__main__':
        run()