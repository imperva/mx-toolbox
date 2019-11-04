#!/usr/bin/env python

import ss
import sys
import json
import csv
import requests
import logging
import urllib

############ ENV Settings ############
logging.basicConfig(filename="export-learned-hosts.log", filemode='w', format='%(name)s - %(levelname)s - %(message)s')

############ GLOBALS ############
configfile = 'config.json'
CONFIG = {}
CSV_FILE_NAME = "learned_hosts.csv"
# Create csv file, and/or clear any contents in existing file 
open(CSV_FILE_NAME, 'w+').close()
csv_file=open(CSV_FILE_NAME,"w+")

CSV_DATA = ["Site,Server Group,Service,Application,Learned Host"]

try:
    with open(configfile, 'r') as data:
        CONFIG = json.load(data)
        logging.warning("Loaded "+configfile+" configuration")

except:
    logging.warning("Missing \""+configfile+"\" file, create file named config.json with the following contents:\n{\n\t\"log_level\": \"debug\",\n\t\"environment\": \"dev\",\n\t\"mx_auth\": {\n\t\t\"endpoint\": \"MXENDPOINT\",\n\t\t\"username\": \"MXUSERNAME\",\n\t\t\"password\": \"MXPASSWORD\",\n\t\t\"license_key\": \"LICENSE_KEY\"\n\t},\n\t\"newrelic_auth\": {\n\t\t\"account_id\": \"ACCOUNT_ID\",\n\t\t\"api_key\": \"API_KEY\",\n\t\t\"event_type\": \"WAFAlerts\",\n\t}\n}")
    exit()
logging.warning("\n\n===========  Start Table Group Export ===========\n")

def run():
    mx_host = CONFIG["mx"]["endpoint"]
    session_id = ss.login(mx_host, CONFIG["mx"]["username"], CONFIG["mx"]["password"])
    sites_response = ss.makeCall(mx_host, session_id, "/conf/sites")
    sites = sites_response.json()
    for site in sites["sites"]:
        server_groups_response = ss.makeCall(mx_host, session_id, "/conf/serverGroups/"+site)
        server_groups = server_groups_response.json()
        for server_group in server_groups["server-groups"]:
            web_services_response = ss.makeCall(mx_host, session_id, "/conf/webServices/"+site+"/"+server_group)
            web_services = web_services_response.json()
            for web_service in web_services["web-services"]:
                applications_response = ss.makeCall(mx_host, session_id, "/conf/webApplications/"+site+"/"+server_group+"/"+web_service)
                applications = applications_response.json()    
                for application in applications["webApplications"]:
                    profile_response = ss.makeCall(mx_host, session_id, "/conf/webProfile/"+site+"/"+server_group+"/"+web_service+"/"+application)
                    profile = profile_response.json()    
                    for learned_host in profile["learnedHosts"]:
                        row = [site]
                        row.append(server_group)
                        row.append(web_service)
                        row.append(application)
                        row.append(learned_host)
                        CSV_DATA.append('"'+'","'.join(row)+'"')
    # print(CSV_DATA)
    csv_file.write("\n".join(CSV_DATA))
    csv_file.close()

if __name__ == '__main__':
    run()


