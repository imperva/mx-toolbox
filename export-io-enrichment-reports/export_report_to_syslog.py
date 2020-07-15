#!/usr/bin/env python
 
import os
import sys
import json
import csv
from subprocess import PIPE,Popen
import logging
import datetime
import socket

############ ENV Settings ############
logging.basicConfig(filename='export_report_to_syslog.log', filemode='w', format='%(name)s - %(levelname)s - %(message)s')
 
############ GLOBALS ############
sourcePolicies = {}
SYSLOGHOST = "your.host.com"
SYSLOGPORT = 514

TIMESTAMP = format(datetime.datetime.now()).replace(" ","_").split(".")[0]

recordsCsv = {"headers":[],"rows":[]}
reportHeaders = []
recordsIndex = {"records":[],"timestamp":TIMESTAMP}

# Parse CSV into dictionary with policy type and applied to assets
logging.warning("\n\n===========  Start MX policy sync ===========\n")
logging.warning('PATH2REPORT='+sys.argv[1])
PATH2REPORT = '/opt/SecureSphere/server/SecureSphere/jakarta-tomcat-secsph/webapps/SecureSphere/'+sys.argv[1]
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

	# Write file formatted with string indexes per row/column
	try:
		logging.warning("sending syslog: "+json.dumps(jsonObj))
		s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		s.connect((SYSLOGHOST, SYSLOGPORT))
		s.sendall(b'{0}'.format(json.dumps(recordsIndex)))
		s.close()
	except socket.error as msg:
		logging.warning("sendSyslog() exception: "+msg)

if __name__ == '__main__':
        run()