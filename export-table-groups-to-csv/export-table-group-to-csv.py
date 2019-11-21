#!/usr/bin/env python

import ss
import sys
import json
import csv
import requests
import logging
import urllib

############ ENV Settings ############
logging.basicConfig(filename="export-table-group-to-csv.log", filemode='w', format='%(name)s - %(levelname)s - %(message)s')

############ GLOBALS ############
configfile = 'config.json'
krprules = []
CONFIG = {}
CSV_FILE_NAME = "table_groups_export.csv"
# Create csv file, and/or clear any contents in existing file 
open(CSV_FILE_NAME, 'w+').close()
csv_file=open(CSV_FILE_NAME,"w+")

# Limit table group export to the following list.  If array is empty [], script will recursively export all table groups from the MX
TBL_GROUPS = []
CSV_DATA = ["Table Group Name,Data Type,Name,Type,Column"]

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
    
    # If TBL_GROUPS is empty, retrieve list of all table groups from MX
    if not len(TBL_GROUPS):
        tbl_grps_response = ss.makeCall(mx_host, session_id, "/conf/tableGroups/")
        tbl_grps = tbl_grps_response.json()
        logging.warning("\n\nNo table groups found, loading all table groups from MX\n"+json.dumps(tbl_grps))

        for tbl_grp in tbl_grps:
            TBL_GROUPS.append(tbl_grp["displayName"])
    
    # Iterate through list of table group names and append to .csv
    for tbl_grp_name in TBL_GROUPS:
        if "/" not in tbl_grp_name:
            tbl_grp_name_ary = tbl_grp_name.split(' - ')        
            print("retrieving table group: "+tbl_grp_name)
            data_type = tbl_grp_name_ary[len(tbl_grp_name_ary)-1]
            tbl_grp_response = ss.makeCall(mx_host, session_id, "/conf/tableGroups/"+tbl_grp_name+"/data")
            tbl_grp = tbl_grp_response.json()
            # CSV_DATA.append(tbl_grp_name)
            for record in tbl_grp["records"]:
                if "Columns" in record:
                    for column_name in record["Columns"]:
                        row = [tbl_grp_name]
                        row.append(data_type)
                        row.append((record["Name"] or 'n/a'))
                        row.append((record["Type"] or 'n/a'))
                        row.append(column_name)
                        CSV_DATA.append('"'+'","'.join(row)+'"')
                else: 
                    row = [tbl_grp_name]
                    row.append(data_type)
                    row.append((record["Type"] or 'n/a'))
                    row.append((record["Name"] or 'n/a'))
                    row.append("n/a")
                    CSV_DATA.append('"'+'","'.join(row)+'"')
        else:
            print("ignoring table group: "+tbl_grp_name)
            
    csv_file.write("\n".join(CSV_DATA))
    csv_file.close()

if __name__ == '__main__':
    run()


