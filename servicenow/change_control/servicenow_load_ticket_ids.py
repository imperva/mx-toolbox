import ss
import json
import requests
import logging
import urllib

############ ENV Settings ############
logging.basicConfig(filename="servicenow-load-ticket-ids.log", filemode='w', format='%(name)s - %(levelname)s - %(message)s')
CONFIG = ss.initConfig("sn_config.json")

datasetCols = {
	"dataset-name":CONFIG["ticket_dataset_name"],
	"columns":[
		{"name":"sys_id","key":True},
		{"name":"number","key":False}
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

    headers = {"Content-Type":"application/json","Accept":"application/json"}
    change_tickets_response = requests.get(CONFIG["servicenow"]["endpoint"]+"/now/table/change_request?sysparm_fields=sys_id%2Cnumber&sysparm_limit=10", auth=(CONFIG["servicenow"]["username"], CONFIG["servicenow"]["password"]), headers=headers)
    if change_tickets_response.status_code != 200: 
        print('Status:', change_tickets_response.status_code, 'Headers:', change_tickets_response.headers, 'Error Response:',change_tickets_response.json())
        exit()
    change_tickets = change_tickets_response.json()
    for ticket in change_tickets["result"]:
        datasetRecords["records"].append({"sys_id":ticket["sys_id"],"number":ticket["number"]})
    dataset_response = ss.makeCall(mx_host, session_id, "/conf/dataSets/"+CONFIG["ticket_dataset_name"]+"/data","POST",json.dumps(datasetRecords))
    print(dataset_response)

if __name__ == '__main__':
    run()