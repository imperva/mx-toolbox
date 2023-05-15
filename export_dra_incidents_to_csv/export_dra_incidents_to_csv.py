#!/usr/bin/env python
import os
import sys
import json
import csv
import requests
import subprocess
from subprocess import PIPE,Popen
import logging
import urllib
import time
import copy

############ ENV Settings ############
logging.basicConfig(filename="export-dra-incidents-to-csv.log", filemode='w', format='%(name)s - %(levelname)s - %(message)s')

############ GLOBALS ############
configfile = 'config.json'
CONFIG = {}
CUR_TIME = time.time()
CSV_FILE_NAME = "dra_incidents_"+str(CUR_TIME)+".csv"
# Create csv file, and/or clear any contents in existing file 
open(CSV_FILE_NAME, 'w+').close()
csv_file=open(CSV_FILE_NAME,"w+")

HEADERS = [
	"id",
    "status",
    "severity",
    "event_category",
    "type_code",
    "type_description",
    "event_time",
    "source_username",
    "source_host",
    "source_ip",
    "destination_ip",
    "star",
    "comment",
    "db_type", 
    "destination_ip"
    #,"db_name"
]
CSV_DATA = ['"'+'","'.join(HEADERS)+'"']
try:
    with open(configfile, 'r') as data:
        CONFIG = json.load(data)
        logging.warning("Loaded "+configfile+" configuration")
except:
    logging.warning("Missing \""+configfile+"\" file, create file named config.json with the following contents:\n{\n\t\"log_level\": \"debug\",\n\t\"environment\": \"dev\",\n\t\"dra\": {\n\t\t\"endpoint\": \"https://1.2.3.4\",\n\t\t\"username\": \"YOURUSER\",\n\t\t\"password\": \"YOURPASSWORD\"\n\t}\n}")
    print("Missing \""+configfile+"\" file, create file named config.json with the following contents:\n{\n\t\"log_level\": \"debug\",\n\t\"environment\": \"dev\",\n\t\"dra\": {\n\t\t\"endpoint\": \"https://1.2.3.4\",\n\t\t\"username\": \"YOURUSER\",\n\t\t\"password\": \"YOURPASSWORD\"\n\t}\n}")
    
    exit()
logging.warning("\n\n===========  Start DRA Incidents Export ===========\n")

def run():
    dra_host = "https://"+CONFIG["dra"]["username"]+":"+CONFIG["dra"]["password"]+"@"+CONFIG["dra"]["endpoint"].split("https://").pop()
    incidentsResponse = makeCall(dra_host, "/counterbreach/api/1.0/security_events")    
    for incident in incidentsResponse["events"]:
        if "severity" not in incident:
            incident["severity"] = "N/A"
        event_category =  "incidents" if incident["event_category"]=="INCIDENT" else "anomalies"
        incidentDbResponse = makeCall(dra_host, "/counterbreach/api/1.2/security_events/"+event_category+"/"+str(incident["id"])+"/databases")
        row = [str(incident["id"])]
        row.append(str(incident["status"]))
        row.append(str(incident["severity"]))
        row.append(str(incident["event_category"]))
        row.append(str(incident["type_code"]))
        row.append(str(incident["type_description"]))
        row.append(str(incident["event_time"]))
        row.append("|".join(incident["source_username"]))
        row.append("|".join(incident["source_host"]))
        row.append("|".join(incident["source_ip"]))
        row.append("|".join(incident["destination_ip"]))
        row.append(str(incident["star"]))
        row.append(str(incident["comment"]))
        if "databases" in incidentDbResponse and len(incidentDbResponse["databases"])>0:
            for db in incidentDbResponse["databases"]:
                tmp_row = copy.deepcopy(row)
                tmp_row.append(str(db["db_type"]))
                tmp_row.append(str(db["destination_ip"]))
                # row.append(str(db["db_name"]))
                CSV_DATA.append('"'+'","'.join(tmp_row)+'"')
        else:
            row.append("")
            row.append("")
            CSV_DATA.append('"'+'","'.join(row)+'"')
    csv_file.write("\n".join(CSV_DATA))
    csv_file.close()

def makeCall(dra_host, action, method="GET", data=None):
	url = dra_host+action
	if data == None:
		content = None
	else:
		content = "'"+data.encode("utf-8")+"'"
	try:
		if method == 'POST':
			logging.warning("API REQUEST (" + method + " https://" + url.split("@").pop() + ") " + str(content))
			proc = subprocess.Popen(['/usr/bin/curl','-X','POST',url,'-d',content], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
			stdout, stderr = proc.communicate(input=None)
			response = stdout.decode('utf-8')
			error = stderr.decode('utf-8')
		elif method == 'GET':
			logging.warning("API REQUEST (" + method + " https://" + url.split("@").pop() + ") ")
			proc = subprocess.Popen(['/usr/bin/curl','-X','GET',url], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
			stdout, stderr = proc.communicate(input=None)
			response = stdout.decode('utf-8')
			error = stderr.decode('utf-8')
		elif method == 'DELETE':
			logging.warning("API REQUEST (" + method + " https://" + url.split("@").pop() + ") ")
			proc = subprocess.Popen(['/usr/bin/curl','-X','DELETE',url], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
			stdout, stderr = proc.communicate(input=None)
			response = stdout.decode('utf-8')
			error = stderr.decode('utf-8')
		elif method == 'PUT':
			logging.warning("API REQUEST (" + method + " https://" + url.split("@").pop() + ") " + str(content))
			proc = subprocess.Popen(['/usr/bin/curl','-X','PUT',url,'-d',content], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
			stdout, stderr = proc.communicate(input=None)
			response = stdout.decode('utf-8')
			error = stderr.decode('utf-8')
		logging.warning("API ERROR (" + method + " https://" + url.split("'@").pop() + ") status code: "+str(response))
		return json.loads(str(response))
	except Exception as e:
		logging.warning("ERROR - "+str(e))


if __name__ == '__main__':
    run()
