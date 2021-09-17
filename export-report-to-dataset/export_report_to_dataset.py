#!/usr/bin/env python
 
import sys
import json
import csv
from subprocess import PIPE,Popen
import logging
import ss

############ Load Configs ############
CONFIGFILE="config.json"
try:
    with open(CONFIGFILE, 'r') as data:
        CONFIG = json.load(data)
except:
    print("Missing \""+CONFIGFILE+"\" file, create file named \""+CONFIGFILE+"\" with the following contents:\n{\n\t\"log_level\": \"WARNING\",\n\t\"mx\": {\n\t\t\"endpoint\": \"MXENDPOINT\",\n\t\t\"username\": \"MXUSERNAME\",\n\t\t\"password\": \"MXPASSWORD\"\n\t}\n}")
    exit()

############ ENV Settings ############
logging.basicConfig(filename="export-report-to-dataset.log", filemode='w', format='%(name)s - %(levelname)s - %(message)s')

############ GLOBALS ############
PATH2REPORT = '/opt/SecureSphere/server/SecureSphere/jakarta-tomcat-secsph/webapps/SecureSphere/'+sys.argv[1]
DATASETNAME = "_".join(sys.argv[2:]).lower()
datasetObj = {"records":[]}
datasetCols = {"dataset-name":DATASETNAME,"columns":[], "number-of-columns":1}
logging.warning("\n\n===========  Start export report to dataset ===========\n")
logging.warning('DATASETNAME='+DATASETNAME)
logging.warning('PATH2REPORT='+PATH2REPORT)

def run():
	with open(PATH2REPORT, 'r') as f:
		i=0
		reader = csv.reader(f)
		for row in reader:
			if i==0:
				datasetCols["columns"].append({"name":"id","key":True})
				for header in row:
					datasetCols["columns"].append({"name":header.lower().replace(" ","_"),"key":False})
					datasetCols["number-of-columns"]+=1
			else:
				datasetRecord = {}
				j=0
				datasetRecord["id"] = "id_"+str(i)
				for val in row:
					datasetRecord[datasetCols["columns"][j+1]["name"]] = val
					j+=1
				datasetObj["records"].append(datasetRecord)
			i+=1
		session_id = ss.login(CONFIG["mx"]["endpoint"], CONFIG["mx"]["username"], CONFIG["mx"]["password"])
		response = ss.makeCall(CONFIG["mx"]["endpoint"],session_id, "/conf/dataSets/"+DATASETNAME+"/columns")
		responseObj = response.json()
		if "errors" in responseObj:
			logging.warning("Dataset '"+DATASETNAME+"' not found, creating dataset now")
			response = ss.makeCall(CONFIG["mx"]["endpoint"],session_id, "/conf/dataSets/createDataset?caseSensitive=false","POST",json.dumps(datasetCols))
		response = ss.makeCall(CONFIG["mx"]["endpoint"],session_id, "/conf/dataSets/"+DATASETNAME+"/data","POST",json.dumps(datasetObj))
	logging.warning("\n\n===========  End export report to dataset ===========\n")

if __name__ == '__main__':
        run()