#!/usr/bin/env python
 
import ss
import sys
import json
import csv
from subprocess import PIPE,Popen
import logging
 
############ ENV Settings ############
logging.basicConfig(filename='export_report_to_dataset.log', filemode='w', format='%(name)s - %(levelname)s - %(message)s')
 
############ GLOBALS ############
configfile = 'config.json'
CONFIG = {}
dataset = {"action":"add","records":[]}

# Parse CSV into dictionary with policy type and applied to assets
logging.warning("\n\n===========  Start db-login-to-dataset ===========\n")
try:
    with open(configfile, 'r') as data:
        CONFIG = json.load(data)
        logging.warning("Loaded "+configfile+" configuration")
except:
    logging.warning("Missing \""+configfile+"\" file, create file named config.json with the following contents:\n{\n\t\"log_level\":\"debug\",\n\t\"environment\":\"dev\",\n\t\"dataset-name\":\"db-logins\",\n\t\"mx\": {\n\t\t\"endpoint\":\"https://127.0.0.1:8083\",\n\t\t\"username\":\"yourusername\",\n\t\t\"password\":\"yourpassword\"\n\t}\n}")
    exit()

if len(sys.argv) > 2:
	dataset["records"].append({"username":sys.argv[1],"source-ip":sys.argv[2]})
	logging.warning("\n\nAdding user and source-ip to dataset: \n"+json.dumps(dataset))
else:
	print("Missing parameters. Please specify a db username, and source-ip as commandline params to the script.  Example: ./db-login-to-dataset.py yourusername 1.2.3.4")
	quit() 

def run():
	mx_host = CONFIG["mx"]["endpoint"]
	session_id = ss.getSession(mx_host, CONFIG["mx"]["username"], CONFIG["mx"]["password"])
	print(session_id)
	ss.makeCall(mx_host, session_id, "/conf/dataSets/"+CONFIG["dataset-name"]+"/data","PUT",json.dumps(dataset))
	
if __name__ == '__main__':
        run()