#!/usr/bin/env python
 
import os
import sys
import json
import csv
from subprocess import PIPE,Popen
import logging
 
############ ENV Settings ############
logging.basicConfig(filename='export-report-to-scp.log', filemode='w', format='%(name)s - %(levelname)s - %(message)s')
 
############ GLOBALS ############
sourcePolicies = {}
AWSREGION = "us-east-1"
REPORT_NAME = sys.argv[2]
SCP_LOCATION = sys.argv[3]
SCP_PASS = sys.argv[4]
 
BUCKET_KEY = "/mx.impervademo.com/"
FILE_KEYS = REPORT_NAME+"_key_index.json"
open(FILE_KEYS, 'w+').close()
f_index=open(FILE_KEYS,"w+")

recordsCsv = {"headers":[],"rows":[]}
reportHeaders = []
recordsIndex = {"records":[]}
recordsTgTbl = {}
recordsTblCol = {}

# Parse CSV into dictionary with policy type and applied to assets
logging.warning("\n\n===========  Start export report to scp ===========\n")
logging.warning('PATH2REPORT='+sys.argv[1])
PATH2REPORT = '/opt/SecureSphere/server/SecureSphere/jakarta-tomcat-secsph/webapps/SecureSphere/'+sys.argv[1]
# Example argv[1] = /WEB-INF/reptemp/ISBT_DB_Classification_Scan_Report_admin_17Sep2019_13-19-28.csv 
# argv[2] = ISBT_DB_Classification_Scan_Report 
# argv[3] = youruser@1.2.3.4:/yourshare/.
# argv[4] = YourPassword
# ./export_report_to_scp.py /WEB-INF/reptemp/DB_Classification_Scan_Report_admin_06Nov2019_11-08-35.csv ISBT_DB_Classification_Scan_Report youruser@1.2.3.4:/yourshare/. YourPassword
 
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
				recordsCsv["headers"] = row
				reportHeaders = row
			else:
				recordsCsv["rows"].append(row)
				# Create entry for string header value - keys
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

	# # Write file formatted with string indexes per row/column
	f_index.write(json.dumps(recordsIndex))
	f_index.close()
	pipe = Popen(['sshpass','-p',SCP_PASS,'scp',FILE_KEYS,SCP_LOCATION], stdout=PIPE)
	output = pipe.communicate()
	os.remove(FILE_KEYS) 

if __name__ == '__main__':
	run()