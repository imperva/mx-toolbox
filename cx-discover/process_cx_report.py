#!/usr/bin/env python
 
import ss
import os
import sys
import json
import csv
from subprocess import PIPE,Popen
import logging
import datetime
import re
import urllib

############ ENV Settings ############
logging.basicConfig(filename='s3.log', filemode='w', format='%(name)s - %(levelname)s - %(message)s')
 
############ GLOBALS ############
configfile = 'config.json'
AWSREGION = "us-east-1"

TIMESTAMP = format(datetime.datetime.now()).replace(" ","_").split(".")[0]
CONFIG = {}
try:
    with open(configfile, 'r') as data:
        CONFIG = json.load(data)
        logging.warning("Loaded "+configfile+" configuration")
except:
    logging.warning("Missing \""+configfile+"\" file, create file named config.json referencing template.config.json")
    exit()

S3_BUCKET = CONFIG["s3_bucket"]
S3_PREFIX = CONFIG["s3_prefix"]
S3_REPORT_NAME = CONFIG["s3_report_name"]+"_"+TIMESTAMP+".json"

open(S3_REPORT_NAME, 'w+').close()
f_index=open(S3_REPORT_NAME,"w+")

recordsCsv = {"headers":[],"records":[]}
reportHeaders = []
recordsIndex = {"records":[]}
tableGroups = {}

cxClassificationColumnMapping = CONFIG["cxClassificationSettings"]["columnMapping"]
cxClassificationAppendedValues = CONFIG["cxClassificationSettings"]["appendedValues"]
cxTableGroupColumnMapping = CONFIG["cxTableGroupSettings"]["columnMapping"]
cxTableGroupDBServiceMapping = CONFIG["cxTableGroupSettings"]["cxToSesDBServiceTypeMapping"]
objectMapping = CONFIG["cxTableGroupSettings"]["cxToSesObjectMapping"]
tableGroupPrefix = "CX - "

# Parse CSV into dictionary with policy type and applied to assets
logging.warning("\n\n===========  Start MX policy sync ===========\n")
logging.warning('CSVREPORT='+sys.argv[1])
PATH2REPORT = '/var/user-data/cx-discover/'+sys.argv[1]
# Example argv[1] = DiscoverReport_Export.csv
# argv[2] = ISBT_DB_Classification_Scan_Report 
# argv[3] = isbt-db-classification
# ./run_export_cx_report_to_s3.sh /WEB-INF/reptemp/ISBT_DB_Classification_Scan_Report_admin_21Jan2020_00-15-00.csv ISBT_DB_Classification_Scan_Report isbt-db-classification/mx.prod.impervademo.com/
# python process_cx_report.py DiscoverReport_Export.csv CX_DB_Classification_Scan_Report isbt-db-classification/mx.stage.impervademo.com/
# scp -i ~/.ssh/your-key.pem ec2-user@1.2.3.4:~/cx-discover/* .

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
		# Parse csv
		for row in reader:
			if i==0:
				recordsCsv["headers"] = row
			else:
				curRawRowWithIndexes = {}
				curRowWithIndexes = {}				
				for j in range(len(row)):
					val = row[j]
					if isint(val):
						val = int(val)
					elif isfloat(val):
						val = float(val)
					header = re.findall(r"([A-Za-z0-9].+?[A-Za-z0-9].+)", recordsCsv["headers"][j].replace(" ","_").strip()).pop()
					curRawRowWithIndexes[header] = val
					# Parse only classification columns to send to ELK from config 
					if header in cxClassificationColumnMapping:
						if header=="Table_Type":
							curRowWithIndexes[cxClassificationColumnMapping[header]] = objectMapping[val]
						elif header=="Datasource_Type":
							curRowWithIndexes[cxClassificationColumnMapping[header]] = cxTableGroupDBServiceMapping[val]
						else:
							curRowWithIndexes[cxClassificationColumnMapping[header]] = val
					for col in cxClassificationAppendedValues:
						curRowWithIndexes[col] = cxClassificationAppendedValues[col]
					curRowWithIndexes["Decision_Changed_Date"] = TIMESTAMP
					curRowWithIndexes["Execution_Date"] = TIMESTAMP
				curRowWithIndexes["Table_Group"] = tableGroupPrefix+curRawRowWithIndexes["Datasource_Type"]+" - "+curRawRowWithIndexes["Datasource_Name"]+" - "+curRawRowWithIndexes["Schema"]+" - "+curRawRowWithIndexes["Category"]
				recordsIndex["records"].append(curRowWithIndexes)
				recordsCsv["records"].append(curRawRowWithIndexes)
			i+=1
	# Write file formatted with string indexes per row/column
	f_index.write(json.dumps(recordsIndex))
	f_index.close()
	logging.warning('uploading file to s3: aws s3 cp '+S3_REPORT_NAME+' s3://'+S3_BUCKET+"/"+S3_PREFIX+"/"+S3_REPORT_NAME)
	logging.warning("uploading file ("+S3_REPORT_NAME+") to S3 with the following records: "+json.dumps(recordsIndex))
	pipe = Popen(['aws','s3','cp',S3_REPORT_NAME,'s3://'+S3_BUCKET+"/"+S3_PREFIX+"/"+S3_REPORT_NAME], stdout=PIPE)
	pipe.communicate()
	os.remove(S3_REPORT_NAME) 

	for record in recordsCsv["records"]:
		tableGroupName = tableGroupPrefix+record["Datasource_Type"]+" - "+curRawRowWithIndexes["Datasource_Name"]+" - "+record["Schema"]+" - "+record["Category"]
		tableName = record["Table"]
		columnName = record["Column"]
		if tableGroupName not in tableGroups:
			tableGroups[tableGroupName] = {
				"dataType":record["Category"],
				"serviceType":cxTableGroupDBServiceMapping[record["Datasource_Type"]],
				"records":{}
			}
		if tableName not in tableGroups[tableGroupName]:
			tableGroups[tableGroupName]["records"][tableName] = {
				"Type":objectMapping[record["Table_Type"]],
				"Name":tableName,
				"col_map":{},
				"Columns":[]
			}
		if columnName not in tableGroups[tableGroupName]["records"][tableName]["col_map"]:
			tableGroups[tableGroupName]["records"][tableName]["col_map"][columnName]=True
			tableGroups[tableGroupName]["records"][tableName]["Columns"].append(columnName)

	curTableGroupsInMx = {}
	mx_host = CONFIG["mx"]["endpoint"]
	session_id = ss.login(mx_host, CONFIG["mx"]["username"], CONFIG["mx"]["password"])
	tbl_grps_response = ss.makeCall(mx_host, session_id, "/conf/tableGroups/")
	tbl_grps = tbl_grps_response.json()
	
	for tbl_grp in tbl_grps:
		curTableGroupsInMx[tbl_grp["displayName"]] = True
	
	for tableGroupName in tableGroups:
		tableGroup = tableGroups[tableGroupName]
		if tableGroupName not in curTableGroupsInMx:
			logging.warning("Table group now found, adding table group: "+str(tableGroupName))
			newTableGroupObj = {
				"isSensitive":True,
				"serviceTypes":[tableGroup["serviceType"]],
				"dataType":tableGroup["dataType"],
				"displayName":tableGroupName
			}
			tbl_grps_response = ss.makeCall(mx_host, session_id, "/conf/tableGroups/","POST",json.dumps(newTableGroupObj))
		newTableGroupRecordsObj = {"records":[]}
		for tableName in tableGroup["records"]:
			record = tableGroup["records"][tableName]
			newTableGroupRecordsObj["records"].append({
				"Name":tableName,
				"Type":record["Type"],
				"Columns":record["Columns"]
			})	
		logging.warning("Populating table group ("+str(tableGroupName)+") with the following records: "+json.dumps(newTableGroupRecordsObj))
		tbl_grps_response = ss.makeCall(mx_host, session_id, "/conf/tableGroups/"+urllib.quote(tableGroupName)+"/data","POST",json.dumps(newTableGroupRecordsObj))

if __name__ == '__main__':
        run()