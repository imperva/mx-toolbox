#!/usr/bin/python
import ss
import json
import requests
import logging
import urllib

############ ENV Settings ############
logging.basicConfig(filename="servicenow-load-change-request-ids-from-file.log", filemode='w', format='%(name)s - %(levelname)s - %(message)s')
CONFIG = ss.initConfig("config.json")
# Add your specific query param filters for change requests, example: '&phase_state=open&assignment_group=db53a9290a0a0a650091abebccf833c6'

datasetCols = {
	"dataset-name":CONFIG["ticket_dataset_name"],
	"columns":[
		{"name":"id","key":True},
		{"name":"number","key":False},
        {"name":"short_description","key":False},
        {"name":"description","key":False},
        {"name":"approval","key":False},
        {"name":"state","key":False}
	]
}
datasetRecords = { "records":[] }

def run():
    mx_host = CONFIG["mx"]["endpoint"]
    session_id = ss.login(CONFIG["mx"]["endpoint"], CONFIG["mx"]["username"], CONFIG["mx"]["password"])
    dataset_response = ss.makeCall(mx_host, session_id, "/conf/dataSets/"+CONFIG["ticket_dataset_name"]+"/columns")
    dataset = dataset_response.json()
    change_request_filter = "&"+CONFIG["servicenow"]["change_request_filter"] if CONFIG["servicenow"]["change_request_filter"]!='' else ''
    if ("errors" in dataset):
        dataset_response = ss.makeCall(mx_host, session_id, "/conf/dataSets/createDataset?caseSensitive=false","POST", json.dumps(datasetCols))
    # logging.warning("Pulling down change control tickets: "+CONFIG["servicenow"]["endpoint"]+"/now/table/change_request?sysparm_fields=sys_id%2Cnumber%2Cshort_description"+change_request_filter)
    change_tickets = loadJSON("sample_servicenow_tickets.json")
    logging.warning(json.dumps(change_tickets))
    for ticket in change_tickets:
        ticketObj = {
            "id":ticket["number"],
            "number":ticket["number"],
            "short_description":ticket["shortDescription"],
            "description":ticket["description"],
            "approval":ticket["approval"],
            "state":ticket["state"]
        }
        datasetRecords["records"].append(ticketObj)
    dataset_response = ss.makeCall(mx_host, session_id, "/conf/dataSets/"+CONFIG["ticket_dataset_name"]+"/data","POST",json.dumps(datasetRecords))
    logging.warning(dataset_response)

def loadJSON(file):
	CONFIG = {}
	try:
		with open(file, 'r') as data:
			CONFIG = json.load(data)
			logging.warning("Loaded "+file+" data")
			return CONFIG
	except:
		logging.warning("File \""+file+"\" not found.")
		exit()

if __name__ == '__main__':
    run()