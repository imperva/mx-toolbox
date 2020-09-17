#!/usr/bin/env python
import ss
import sys
import json
import requests
import logging
import urllib

############ ENV Settings ############
logging.basicConfig(filename="servicenow-create-incident.log", filemode='w', format='%(name)s - %(levelname)s - %(message)s')
CONFIG = ss.initConfig("config.json")

alert = json.loads(" ".join(sys.argv[1:]))
incident = {
    "short_description": alert["alert_desc"]+" - "+alert["alert_number"],
    "work_notes": "Alert Number: "+alert["alert_number"]+"\n "
}
incident["work_notes"] += "Violation Event ID: "+alert["event_id"]+"\n "
incident["work_notes"] += "Database User: "+alert["user"]+"\n "
incident["work_notes"] += "Source IP: "+alert["source-ip"]+"\n "
incident["work_notes"] += "Object Type: "+alert["object-type"]+"\n"
incident["work_notes"] += "Object Name: "+alert["object-name"]+"\n"
incident["work_notes"] += "Violated Item: "+alert["violated-item"]

def run():
    headers = {"Content-Type":"application/json","Accept":"application/json"}
    change_tickets_response = requests.post(CONFIG["servicenow"]["endpoint"]+"/now/table/incident", auth=(CONFIG["servicenow"]["username"], CONFIG["servicenow"]["password"]), headers=headers, data=json.dumps(incident))
    logging.warning(json.dumps(change_tickets_response.json()))    

if __name__ == '__main__':
    run()