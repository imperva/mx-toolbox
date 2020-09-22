#!/usr/bin/env python
import ss
import json
import requests
import logging
import urllib

############ ENV Settings ############
logging.basicConfig(filename="servicenow-load-change-request-ids.log", filemode='w', format='%(name)s - %(levelname)s - %(message)s')
CONFIG = ss.initConfig("config.json")
# Add your specific query param filters for change requests, example: '&phase_state=open&assignment_group=db53a9290a0a0a650091abebccf833c6'
servicenow_change_request_filter = '&phase_state=open' 

datasetCols = {
	"dataset-name":CONFIG["ticket_dataset_name"],
	"columns":[
		{"name":"sys_id","key":True},
		{"name":"number","key":False},
        {"name":"short_description","key":False},
	]
}
datasetRecords = { "records":[] }

def run():
    mx_host = CONFIG["mx"]["endpoint"]
    session_id = ss.login(CONFIG["mx"]["endpoint"], CONFIG["mx"]["username"], CONFIG["mx"]["password"])
    dataset_response = ss.makeCall(mx_host, session_id, "/conf/dataSets/"+CONFIG["ticket_dataset_name"]+"/columns")
    dataset = dataset_response.json()
    if ("errors" in dataset):
        dataset_response = ss.makeCall(mx_host, session_id, "/conf/dataSets/createDataset?caseSensitive=false","POST", json.dumps(datasetCols))
        change_request_filter = CONFIG["change_request_filter"] if (CONFIG["change_request_filter"]!='' else ''
    logging.warning("Pulling down change control tickets: "+CONFIG["servicenow"]["endpoint"]+"/now/table/change_request?sysparm_fields=sys_id%2Cnumber%2Cshort_description"+)
    headers = {"Content-Type":"application/json","Accept":"application/json"}
    change_tickets_response = requests.get(CONFIG["servicenow"]["endpoint"]+"/now/table/change_request?sysparm_fields=sys_id%2Cnumber%2Cshort_description"+servicenow_change_request_filter, auth=(CONFIG["servicenow"]["username"], CONFIG["servicenow"]["password"]), headers=headers)
    logging.warning(json.dumps(change_tickets_response.json()))
    if change_tickets_response.status_code != 200: 
        print('Status:', change_tickets_response.status_code, 'Headers:', change_tickets_response.headers, 'Error Response:',change_tickets_response.json())
        exit()
    change_tickets = change_tickets_response.json()
    for ticket in change_tickets["result"]:
        datasetRecords["records"].append({"sys_id":ticket["sys_id"],"number":ticket["number"],"short_description":ticket["short_description"]})
    dataset_response = ss.makeCall(mx_host, session_id, "/conf/dataSets/"+CONFIG["ticket_dataset_name"]+"/data","POST",json.dumps(datasetRecords))
    logging.warning(dataset_response)

if __name__ == '__main__':
    run()