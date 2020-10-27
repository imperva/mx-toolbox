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
logging.basicConfig(filename='servicenow-process-das-report.log', filemode='w', format='%(name)s - %(levelname)s - %(message)s')
 
############ GLOBALS ############
CONFIG = ss.initConfig("sn_config.json")
TIMESTAMP = format(datetime.datetime.now()).replace(" ","_").split(".")[0]

reportHeaders = []
recordsIndex = {"records":[], "cmdb_cis":{}}
cmdbServiceMap = {
    "cassandra":"cmdb_ci_cassandra_instance",
    "couchbase":"cmdb_ci_database", # default
    "db2":"cmdb_ci_db_db2_instance",
    "greenplum":"cmdb_ci_database", # default
    "hbase":"cmdb_ci_db_hbase_instance",
    "hdfs":"cmdb_ci_database", # default
    "hive":"cmdb_ci_database", # default
    "impala":"cmdb_ci_database", # default
    "ims":"cmdb_ci_database", # default
    "informix":"cmdb_ci_db_informix_instance",
    "mariadb":"cmdb_ci_db_mysql_instance",
    "mongo":"cmdb_ci_db_mongodb_instance",
    "mssql":"cmdb_ci_db_mssql_instance",
    "ms sql":"cmdb_ci_db_mssql_instance",
    "mysql":"cmdb_ci_db_mysql_instance",
    "netezza":"cmdb_ci_database", # default
    "oracle":"cmdb_ci_db_ora_instance",
    "postgresql":"cmdb_ci_db_postgresql_instance",
    "progress":"cmdb_ci_database", # default
    "sailfish":"cmdb_ci_database", # default
    "saphana":"cmdb_ci_appl_sap_hana_db",
    "sybase":"cmdb_ci_endpoint_sybase",
    "sybaseiq":"cmdb_ci_endpoint_sybase",
    "teradata":"cmdb_ci_database" # default
}

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
                recordsIndex["records"].append(curRowWithIndexes)
            i+=1 
        # print(json.dumps(recordsIndex["records"]))
        for record in recordsIndex["records"]:
            # record = recordsIndex["records"][i]
            if (record["DB_Type"]+";|;"+record["Target_Server_IP"] not in recordsIndex["cmdb_cis"]):
                recordsIndex["cmdb_cis"][record["DB_Type"]+";|;"+record["Target_Server_IP"]] = record
                logging.warning(record["DB_Type"]+";|;"+record["Target_Server_IP"])
        logging.warning(json.dumps(recordsIndex["cmdb_cis"]))
        for cmdb_ci_key in recordsIndex["cmdb_cis"]:
            cmdb_ci = recordsIndex["cmdb_cis"][cmdb_ci_key]
            headers = {"Content-Type":"application/json","Accept":"application/json"}
            cmdb_ci_list_response = requests.get(CONFIG["servicenow"]["endpoint"]+"/now/table/"+cmdbServiceMap[cmdb_ci["DB_Type"].lower()]+"?sysparm_query=ip_address%3D"+cmdb_ci["Target_Server_IP"], auth=(CONFIG["servicenow"]["username"], CONFIG["servicenow"]["password"]), headers=headers)
            cmdb_ci_list = cmdb_ci_list_response.json()
            if (len(cmdb_ci_list["result"])==0):
                logging.warning("=====================  CREATE CMDB CI =========================")
                cmdb_ci_record = {
                    "ip_address": cmdb_ci["Target_Server_IP"],
                    "name": cmdb_ci["Server_Group"]+"-"+cmdb_ci["Service_Name"],
                    "sys_class_name": cmdbServiceMap[cmdb_ci["DB_Type"].lower()],
                    "subcategory": "Database",
                    "jdbc_port": str(cmdb_ci["Location_Port"]),
                    "tcp_port": ":"+str(cmdb_ci["Location_Port"])+":"
                }
                create_cmdb_ci_response = requests.post(CONFIG["servicenow"]["endpoint"]+"/now/table/"+cmdbServiceMap[cmdb_ci["DB_Type"].lower()], auth=(CONFIG["servicenow"]["username"], CONFIG["servicenow"]["password"]), headers=headers, data=json.dumps(cmdb_ci_record))
                create_cmdb_ci = create_cmdb_ci_response.json()
                recordsIndex["cmdb_cis"][cmdb_ci_key]["cmdb_ci"] = create_cmdb_ci["result"]["sys_id"]
                logging.warning(json.dumps(create_cmdb_ci))
            else:
                recordsIndex["cmdb_cis"][cmdb_ci_key]["cmdb_ci"] = cmdb_ci_list["result"][0]["sys_id"]

        for record in recordsIndex["records"]:
            vuln_item = {
                "vulnerability": record["Test_Vulnerability_Type_CVE"],
                "ip_address": record["Target_Server_IP"],
                "port": str(record["Location_Port"]),
                "work_notes": record["Test_Vulnerability_Type_Description"],
                "cmdb_ci":recordsIndex["cmdb_cis"][record["DB_Type"]+";|;"+record["Target_Server_IP"]]["cmdb_ci"]
            }
            create_vuln_item_response = requests.post(CONFIG["servicenow"]["endpoint"]+"/now/table/sn_vul_vulnerable_item", auth=(CONFIG["servicenow"]["username"], CONFIG["servicenow"]["password"]), headers=headers, data=json.dumps(vuln_item))
            create_vuln_item = create_vuln_item_response.json()
            logging.warning(json.dumps(create_vuln_item))

if __name__ == '__main__':
    run()
