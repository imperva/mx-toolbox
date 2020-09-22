#!/usr/bin/env python
 
import os
import ss
import sys
import json
import csv
import requests
from subprocess import PIPE,Popen
import logging
import datetime

############ ENV Settings ############
logging.basicConfig(filename='servicenow-update-tickets-with-query.log', filemode='w', format='%(name)s - %(levelname)s - %(message)s')
 
############ GLOBALS ############
CONFIG = ss.initConfig("sn_config.json")
TIMESTAMP = format(datetime.datetime.now()).replace(" ","_").split(".")[0]

reportHeaders = []
recordsIndex = {}
# Parse CSV into dictionary with policy type and applied to assets
logging.warning("\n\n===========  Start process das report ===========\n")
PATH2REPORT = '/opt/SecureSphere/server/SecureSphere/jakarta-tomcat-secsph/webapps/SecureSphere/'+sys.argv[1]
logging.warning('PATH2REPORT='+PATH2REPORT)
# Example argv[1] = /WEB-INF/reptemp/DB_Classification_Scan_Report_admin_13Feb2020_15-53-07.csv
# argv[2] = ISBT_DB_Classification_Scan_Report 
# argv[3] = isbt-db-classification
# ./run_export_report_to_s3.sh /WEB-INF/reptemp/ISBT_DB_Classification_Scan_Report_admin_21Jan2020_00-15-00.csv ISBT_DB_Classification_Scan_Report impervademo-com-state-store/mx-reports/dev.impervademo.com/

def isfloat(x):
    try:
        a = float(x)
    except ValueError:
        return False
    else:
        return True

def isint(x):
    try:
        a = float(x)
        b = int(a)
    except ValueError:
        return False
    else:
        return a == b

def run():
    with open(PATH2REPORT, 'r') as f:
        i=0
        reader = csv.reader(f)
        for row in reader:
            if i==0:
                reportHeaders = row
            else:
                curRowWithIndexes = {}
                for j in range(len(row)):
                    val = row[j]
                    if isint(val):
                        val = int(val)
                    elif isfloat(val):
                        val = float(val)
                    curRowWithIndexes[reportHeaders[j].replace(" ", "_")] = val
                if (curRowWithIndexes["Ticket_ID"] not in recordsIndex):
                    recordsIndex[curRowWithIndexes["Ticket_ID"]] = []
                recordsIndex[curRowWithIndexes["Ticket_ID"]].append(curRowWithIndexes)
            i+=1 
    for sys_id in recordsIndex:
        # Check for ticket
        headers = {"Content-Type":"application/json","Accept":"application/json"}
        change_ticket_response = requests.get(CONFIG["servicenow"]["endpoint"]+"/now/table/change_request?sys_id="+sys_id, auth=(CONFIG["servicenow"]["username"], CONFIG["servicenow"]["password"]), headers=headers)
        change_ticket = change_ticket_response.json()
        change_ticket_update = {"work_notes":""}
        if (len(change_ticket["result"])==1):    
            for record in recordsIndex[sys_id]:
                change_ticket_update["work_notes"] += "Query Event Date: "+record["Event_Date_and_Time"]+"\n"
                change_ticket_update["work_notes"] += "Event ID: "+str(record["Event_ID"])+"\n"
                change_ticket_update["work_notes"] += "DB User: "+record["User"]+"\n"
                change_ticket_update["work_notes"] += "Source IP: "+record["Source_IP"]+"\n"
                change_ticket_update["work_notes"] += "Source Application: "+record["Source_Application"]+"\n"
                change_ticket_update["work_notes"] += "Database: "+record["Database"]+"\n"
                change_ticket_update["work_notes"] += "Schema: "+record["Schema"]+"\n"
                change_ticket_update["work_notes"] += "Instance: "+record["Instance_Name"]+"\n"
                # change_ticket_update["work_notes"] += "Server Group: "+record["Server_Group"]+"\n"
                change_ticket_update["work_notes"] += "Destination IP:Port: "+record["Destination_IP"]+":"+record["Destination_Port"]+"\n"
                change_ticket_update["work_notes"] += "DB Service Type: "+record["Service_Type"]+"\n"
                change_ticket_update["work_notes"] += "DB Agent Name: "+record["Agent_Name"]+"\n"
                change_ticket_update["work_notes"] += "Affected Rows: "+str(record["Affected_Rows"])+"\n"
                change_ticket_update["work_notes"] += "SQL Exception Occurred: "+str(record["SQL_Exception_Occurred"])+"\n"
                change_ticket_update["work_notes"] += "SQL Exception String: "+str(record["SQL_Exception_String"])+"\n"
                change_ticket_update["work_notes"] += "Affected Rows: "+str(record["Affected_Rows"])+"\n"
                change_ticket_update["work_notes"] += "Query: "+record["Query"]+"\n\n"
            change_tickets_response = requests.put(CONFIG["servicenow"]["endpoint"]+"/now/table/change_request/"+sys_id, auth=(CONFIG["servicenow"]["username"], CONFIG["servicenow"]["password"]), headers=headers, data=json.dumps(change_ticket_update))
            logging.warning(json.dumps(change_tickets_response.json()))

if __name__ == '__main__':
    run()
