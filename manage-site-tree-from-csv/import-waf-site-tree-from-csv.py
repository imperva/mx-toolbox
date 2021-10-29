#!/usr/bin/env python

import ss
import sys
import json
import csv
import requests
import logging
import urllib
from subprocess import PIPE,Popen
import pyparsing


############ ENV Settings ############
logging.basicConfig(filename="import_site_tree_from_csv.log", filemode='w', format='%(name)s - %(levelname)s - %(message)s')

############ GLOBALS ############
CONFIGFILE = 'config.json'
CONFIG = {}

try:
    with open(CONFIGFILE, 'r') as data:
        CONFIG = json.load(data)
except:
    print("Missing \""+CONFIGFILE+"\" file, create file named \""+CONFIGFILE+"\" with the following contents:\n{\n\t\"log_level\": \"debug\",\n\t\"log_file_name\": \"gateway_statistics.log\",\n\t\"environment\": \"dev\",\n\t\"is_userspace\":false,\n\t\"environment\": \"dev\",\n\t\"log_search\": {\n\t\t\"enabled\": true,\n\t\t\"files\": [{\n\t\t\t\"path\": \"/var/log/messages\",\n\t\t\t\"search_patterns\": [{\n\t\t\t\t\t\"name\":\"YOUR_EVENT_NAME\",\n\t\t\t\t\t\"pattern\":\"some text pattern\"\n\t\t\t\t}, {\n\t\t\t\t\t\"name\":\"YOUR_EVENT_NAME_2\",\n\t\t\t\t\t\"pattern\":\"some other text pattern\"\n\t\t\t\t}\n\t\t\t]\n\t\t}]\n\t},\n\t\"newrelic\": {\n\t\t\"enabled\": false,\n\t\t\"account_id\": \"ACCOUNT_ID\",\n\t\t\"api_key\": \"API_KEY\",\n\t\t\"event_type\": \"GWStats\"\n\t},\n\t\"influxdb\": {\n\t\t\"enabled\": true,\n\t\t\"host\": \"http://1.2.3.4:8086/write?db=imperva_performance_stats\"\n\t},\n\t\"syslog\": {\n\t\t\"enabled\": true,\n\t\t\"host\": \"1.2.3.4\",\n\t\t\"port\": 514\n\t}\n}")
    exit()

if len(sys.argv)<2:
	print("[ERROR] Missing argument, please specify the path to the csv to import. \n  Example: python import-waf-site-tree-from-csv.py /path/to/mysitetree.csv")
	logging.warning("[ERROR] Missing argument, please specify the path to the csv to import. Example: python import-waf-site-tree-from-csv.py /path/to/mysitetree.csv")
	quit()

try:
    CSV_FILE_PATH = sys.argv[1]
except:
    print('Path to csv is missing, please specify a path to csv file you are looking to import. Example: python import-waf-site-tree-from-csv.py "path/to/yourfile.csv"')
    exit()

def run():
    sites = ss.ParseCsvWaf(CSV_FILE_PATH)
    print(json.dumps(sites))
    mx_host = CONFIG["mx"]["endpoint"]
    session_id = ss.login(mx_host, CONFIG["mx"]["username"], CONFIG["mx"]["password"])
    for site_name in sites:
        site = sites[site_name]
        logging.warning("Adding site '"+site_name+"' to site tree.")
        response = ss.makeCall(CONFIG["mx"]["endpoint"],session_id, "/conf/sites/"+site_name,"POST",json.dumps({}))
        if ss.ErrorCheck(response):
            for server_group_name in site:
                server_group = site[server_group_name]
                logging.warning("Adding server group '"+server_group_name+"' to site '"+site_name+"' to site tree.")
                response = ss.makeCall(CONFIG["mx"]["endpoint"],session_id, "/conf/serverGroups/"+site_name+"/"+server_group_name,"POST",json.dumps({}))
                if ss.ErrorCheck(response):
                    if "operation_mode" in server_group:
                        logging.warning("Setting operationMode '"+server_group["operation_mode"]+"' for '"+server_group_name+"'")
                        data = {"operationMode":server_group["operation_mode"]}
                        response = ss.makeCall(CONFIG["mx"]["endpoint"],session_id, "/conf/serverGroups/"+site_name+"/"+server_group_name,"PUT",json.dumps(data)) 
                    if "server_ip" in server_group:
                        for server_ip in server_group["server_ips"]:
                            logging.warning("Adding '"+server_ip+"' to protectedIPs for '"+server_group_name+"'")
                            response = ss.makeCall(CONFIG["mx"]["endpoint"],session_id, "/conf/serverGroups/"+site_name+"/"+server_group_name+"/protectedIPs/"+server_ip+"?gatewayGroup="+server_group["server_ips"][server_ip],"POST",json.dumps({}))
                    for service_name in server_group["services"]:
                        logging.warning("Adding '"+service_name+"' service to '"+server_group_name+"'")
                        service = server_group["services"][service_name]
                        data = {
                            "ports":list(service["ports"].keys()),
                            "sslPorts":list(service["sslPorts"].keys())
                        }
                        response = ss.makeCall(CONFIG["mx"]["endpoint"],session_id, "/conf/webServices/"+site_name+"/"+server_group_name+"/"+service_name,"POST",json.dumps(data))
                        
                        for ssl_key_name in service["sslCerts"]:
                            logging.warning("Adding SSL key '"+ssl_key_name+"' to '"+service_name+"' service")
                            sslCertObj = service["sslCerts"][ssl_key_name]
                            response = ss.makeCall(CONFIG["mx"]["endpoint"],session_id, "/conf/webServices/"+site_name+"/"+server_group_name+"/"+service_name+"/sslCertificates/"+ssl_key_name,"POST",json.dumps(sslCertObj))

                        for krp_alias_name in service["krpConfigs"]:
                            logging.warning("Adding KRP inbound rule to '"+service_name+"' service")
                            krp_rule = service["krpConfigs"][krp_alias_name]
                            response = ss.makeCall(CONFIG["mx"]["endpoint"],session_id, "/conf/webServices/"+site_name+"/"+server_group_name+"/"+service_name+"/krpInboundRules/"+krp_rule["gateway_group"]+"/"+krp_rule["gateway_krp_alias_name"]+"/"+krp_rule["krp_inbound_port"],"POST",json.dumps(krp_rule["krpRules"]))
                        
                        for application_name in service["applications"]:
                            appObj = service["applications"][application_name]
                            newAppObj = {"learnSettings":"LearnAll","parseOCSPRequests":False}
                            logging.warning("Adding application '"+application_name+"' to service "+service_name)
                            response = ss.makeCall(CONFIG["mx"]["endpoint"],session_id, "/conf/webApplications/"+site_name+"/"+server_group_name+"/"+service_name+"/"+application_name,"POST",json.dumps(newAppObj))
                            for priority in appObj["hostToAppMappings"]:
                                appMappingObj = appObj["hostToAppMappings"][priority]
                                logging.warning("Adding application mapping '"+json.dumps(appMappingObj)+"' to service "+service_name)
                                response = ss.makeCall(CONFIG["mx"]["endpoint"],session_id, "/conf/webServices/"+site_name+"/"+server_group_name+"/"+service_name+"/hostToAppMappings/"+application_name+"/"+priority,"POST",json.dumps(appMappingObj))
            
    # Apply policies
    # if CONFIG["applyWAFPolicies"]["enabled"]:
    #     print("apply policies")
    # policies = ss.ParseCsvWafPolicies(CONFIG["applyWAFPolicies"]["pathToCsv"])
    # for server_group_name in site:
    #     server_group = site[server_group_name]
    #     for service_name in server_group["services"]:
            # https://172.16.57.220:8083/SecureSphere/api/v1/conf/webServices/{siteName}/{serverGroupName}/{webServiceName}/securityPolicies
    #         service = server_group["services"][service_name]
    #         for application_name in service["applications"]:
    #             # https://172.16.57.220:8083/SecureSphere/api/v1/conf/webApplications/{siteName}/{serverGroupName}/{webServiceName}/{webApplicationName}/webApplicationCustomPolicies/{policyName}




if __name__ == '__main__':
    run()
