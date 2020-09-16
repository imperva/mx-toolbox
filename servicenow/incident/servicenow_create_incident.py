#!/usr/bin/env python
import ss
import sys
import json
import requests
import logging
import urllib

############ ENV Settings ############
logging.basicConfig(filename="servicenow-create-incident.log", filemode='w', format='%(name)s - %(levelname)s - %(message)s')
CONFIG = ss.initConfig("sn_config.json")

alert = json.loads(" ".join(sys.argv[1:]))
incident = {
    "short_description": alert["alert_desc"],
    "work_notes_list": "Alert Number: "+alert["alert_number"]+"\n "
}
incident["work_notes_list"] += "Violation Event ID: "+alert["event_id"]+"\n "
incident["work_notes_list"] += "db-user: "+alert["user"]+"\n "
incident["work_notes_list"] += "source-ip: "+alert["source-ip"]
incident["work_notes_list"] += alert["object-name"]+"\n"+alert["object-type"]+"\n"+alert["violated-item"]

def run():
    # logging.warning(json.dumps(incident))
    headers = {"Content-Type":"application/json","Accept":"application/json"}
    change_tickets_response = requests.post(CONFIG["servicenow"]["endpoint"]+"/now/table/incident", auth=(CONFIG["servicenow"]["username"], CONFIG["servicenow"]["password"]), headers=headers, data=json.dumps(incident))
    logging.warning(json.dumps(change_tickets_response.json()))    

if __name__ == '__main__':
    run()