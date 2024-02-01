#!/usr/bin/python
import ss
import json
import requests
import logging
import urllib

############ ENV Settings ############
logging.basicConfig(filename="servicenow-load-change-request-ids-with-cmdb-ci.log", filemode='w', format='%(name)s - %(levelname)s - %(message)s')
CONFIG = ss.initConfig("config.json")
# Add your specific query param filters for change requests, example: '&phase_state=open&assignment_group=db53a9290a0a0a650091abebccf833c6'

cmdb_tables = [
    "cmdb_ci_db_mssql_database",
    "cmdb_ci_db_mssql_instance",
    "cmdb_ci_oracle_database"
    # "cmdb_ci_oracle_asm",
    # "cmdb_ci_app_server_ora_ess",
    # "cmdb_ci_app_server_ora_ias_m",
    # "cmdb_ci_app_server_ora_ias",
    # "cmdb_ci_appl_ora_conc",
    # "cmdb_ci_appl_ora_disc_ui",
    # "cmdb_ci_appl_ora_disc",
    # "cmdb_ci_appl_ora_ebs",
    # "cmdb_ci_appl_ora_forms_ui",
    # "cmdb_ci_appl_ora_forms",
    # "cmdb_ci_appl_ora_fs",
    # "cmdb_ci_appl_ora_gg_extract",
    # "cmdb_ci_appl_ora_gg_replicat",
    # "cmdb_ci_appl_ora_http",
    # "cmdb_ci_appl_ora_metric_client",
    # "cmdb_ci_appl_ora_metric_svr",
    # "cmdb_ci_appl_ora_notif_svr",
    # "cmdb_ci_appl_ora_oacore",
    # "cmdb_ci_appl_ora_oafm",
    # "cmdb_ci_appl_ora_pm",
    # "cmdb_ci_appl_ora_report",
    # "cmdb_ci_appl_ora_tns",
    # "cmdb_ci_appl_ora_tnslsnr",
    # "cmdb_ci_appl_oracle_golden_gate",
    # "cmdb_ci_db_ora_catalog",
    # "cmdb_ci_db_ora_instance",
    # "cmdb_ci_db_ora_listener",
    # "cmdb_ci_db_ora_pdb_instance",
    # "cmdb_ci_db_ora_service",
    # "cmdb_ci_endpoint_oracle_db_schema",
    # "cmdb_ci_endpoint_oracle_db",
    # "cmdb_ci_endpoint_oracle_esb",
    # "cmdb_ci_endpoint_oracle_ias",
    # "cmdb_ci_endpoint_oracle_rac",
    # "cmdb_ci_endpoint_oracle_tns",
    # "cmdb_ci_oracle_bi_presentation_service",
    # "cmdb_ci_oracle_bi_scheduler",
    # "cmdb_ci_oracle_bi_server",
    # "cmdb_ci_oracle_cluster_node",
    # "cmdb_ci_oracle_cluster",
    # "cmdb_ci_oracle_enqueue_monitor",
    # "cmdb_ci_oracle_management_agent",
    # "cmdb_ci_rubrik_db_ora_host",
    # "cmdb_ci_rubrik_db_ora_rac",
    # "cmdb_ci_db_mssql_analysis",
    # "cmdb_ci_db_mssql_catalog",
    # "cmdb_ci_db_mssql_int_job",
    # "cmdb_ci_db_mssql_integration",
    # "cmdb_ci_db_mssql_reporting",
    # "cmdb_ci_db_mssql_server",
    # "cmdb_ci_endpoint_ssas_mssql",
    # "cmdb_ci_endpoint_ssis_mssql",
    # "cmdb_ci_mssql_cluster",
    # "cmdb_ci_mssql_cluster_node"
]

datasetCols = {
    "dataset-name":CONFIG["ticket_dataset_name"],
    "columns":[
        {"name":"id","key":True},
        {"name":"number","key":False},
        {"name":"short_description","key":False},
        {"name":"start_date","key":False},
        {"name":"end_date","key":False},
        {"name":"assigned_to","key":False},
        {"name":"cmdb_ci","key":False},
        {"name":"cmdb_name","key":False},
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
    logging.warning("Pulling down change control tickets: "+CONFIG["servicenow"]["endpoint"]+"/now/table/change_request?"+change_request_filter)
    headers = {"Content-Type":"application/json","Accept":"application/json"}
    change_tickets_response = requests.get(CONFIG["servicenow"]["endpoint"]+"/now/table/change_request?"+change_request_filter, auth=(CONFIG["servicenow"]["username"], CONFIG["servicenow"]["password"]), headers=headers)
    logging.warning(json.dumps(change_tickets_response.json()))
    if change_tickets_response.status_code != 200: 
        print('Status:', change_tickets_response.status_code, 'Headers:', change_tickets_response.headers, 'Error Response:',change_tickets_response.json())
        exit()
    change_tickets = change_tickets_response.json()
    cmdb_ci_list = {}
    change_tickets_list = {}
    for ticket in change_tickets["result"]:
        change_tickets_list[ticket["number"]] = {
            "id":ticket["number"],
            "number":ticket["number"],
            "short_description":strip_non_ascii(ticket["short_description"]),
            "start_date":ticket["start_date"],
            "end_date":ticket["end_date"],
            "assigned_to":ticket["assigned_to"]["value"] if "value" in ticket["assigned_to"] else "",
            "cmdb_ci":"NA",
            "cmdb_name":"NA"
        }
        if "value" in ticket["cmdb_ci"]:
            cmdb_ci_list[ticket["cmdb_ci"]["value"]] = ""
            change_tickets_list[ticket["number"]]["cmdb_ci"] = ticket["cmdb_ci"]["value"]
    
    cmdb_ci_ids = ",".join(cmdb_ci_list.keys())
    cmdb_ci_filter = "sysparm_fields=sys_id,cluster_name,database,host,name,ip_address"
    for table in cmdb_tables:
        logging.warning("Checking for sys_id values in table: '"+table+"': "+CONFIG["servicenow"]["endpoint"]+"/now/table/"+table+"?"+cmdb_ci_filter+"&sysparm_query=sys_idIN"+cmdb_ci_ids)
        cmdb_ci_response = requests.get(CONFIG["servicenow"]["endpoint"]+"/now/table/"+table+"?"+cmdb_ci_filter+"&sysparm_query=sys_idIN"+cmdb_ci_ids, auth=(CONFIG["servicenow"]["username"], CONFIG["servicenow"]["password"]), headers=headers)
        cmdb_ci_data = cmdb_ci_response.json()
        for ci in cmdb_ci_data["result"]:
            if ci["sys_id"] in cmdb_ci_list:
                logging.warning("Assigning cmdb_ci.name '"+ci["name"]+" for cmdb_ci.sys_id: "+ci["sys_id"])
                cmdb_ci_list[ci["sys_id"]] = ci["name"]

    # change_tickets_response = requests.get(CONFIG["servicenow"]["endpoint"]+"/now/table/change_request?"+change_request_filter, auth=(CONFIG["servicenow"]["username"], CONFIG["servicenow"]["password"]), headers=headers)
    for ticketNumber in change_tickets_list:
        ticket = change_tickets_list[ticketNumber]
        if ticket["cmdb_ci"]!='' and ticket["cmdb_ci"] in cmdb_ci_list:
            logging.warning("Assigning cmdb_name '"+ci["name"]+"' to ticket number: "+ticketNumber)
            ticket["cmdb_name"] = cmdb_ci_list[ticket["cmdb_ci"]]
        datasetRecords["records"].append(ticket)
    dataset_response = ss.makeCall(mx_host, session_id, "/conf/dataSets/"+CONFIG["ticket_dataset_name"]+"/data","POST",json.dumps(datasetRecords))
    logging.warning(dataset_response)

def strip_non_ascii(string):
    stripped = (c for c in string if 0 < ord(c) < 127)
    return ''.join(stripped)

if __name__ == '__main__':
    run()