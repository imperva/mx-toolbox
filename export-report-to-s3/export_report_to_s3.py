#!/usr/bin/env python
 
import sys
import json
import csv
from subprocess import PIPE,Popen
import logging
 
############ ENV Settings ############
logging.basicConfig(filename='s3.log', filemode='w', format='%(name)s - %(levelname)s - %(message)s')
 
############ GLOBALS ############
sourcePolicies = {}
AWSREGION = "us-east-1"
REPORT_NAME = sys.argv[2]
BUCKET_NAME = sys.argv[3]
 
BUCKET_KEY = "/mx.impervademo.com/"
FILE_KEYS = REPORT_NAME+"_key_index.json"
FILE_CSV = REPORT_NAME+"_csv_index.json"
FILE_TGTBL_KEYS = REPORT_NAME+"_tgtbl_index.json"
FILE_TBLCOL_KEYS = REPORT_NAME+"_tblcol_index.json"

open(FILE_KEYS, 'w').close()
open(FILE_CSV, 'w+').close()
open(FILE_TGTBL_KEYS, 'w+').close()
open(FILE_TBLCOL_KEYS, 'w+').close()
f_index=open(FILE_KEYS,"w+")
f_csv=open(FILE_CSV,"w+")
f_tbl=open(FILE_TGTBL_KEYS,"w+")
f_col=open(FILE_TBLCOL_KEYS,"w+")

recordsCsv = {"headers":[],"rows":[]}
reportHeaders = []
recordsIndex = {"records":[]}
recordsTgTbl = {}
recordsTblCol = {}

# Parse CSV into dictionary with policy type and applied to assets
logging.warning("\n\n===========  Start MX policy sync ===========\n")
logging.warning('PATH2REPORT='+sys.argv[1])
PATH2REPORT = '/opt/SecureSphere/server/SecureSphere/jakarta-tomcat-secsph/webapps/SecureSphere/'+sys.argv[1]
# Example argv[1] = /WEB-INF/reptemp/ISBT_DB_Classification_Scan_Report_admin_17Sep2019_13-19-28.csv 
# argv[2] = ISBT_DB_Classification_Scan_Report 
# argv[3] = isbt-db-classification
 
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
					curRowWithIndexes[reportHeaders[j].replace(" ", "_")] = row[j]
				recordsIndex["records"].append(curRowWithIndexes)
				
				# Create entry for table group name as key index
				tableGroupName = row[35].replace(" ", "_")
				tableName = row[37].replace(" ", "_")
				colName = row[5].replace(" ", "_")
				if tableGroupName not in recordsTgTbl:
					recordsTgTbl[tableGroupName] = {}
				recordTgTbl = recordsTgTbl[tableGroupName]
				if tableName not in recordTgTbl:
					recordTgTbl[tableName] = []
				recordTgTbl[tableName].append(curRowWithIndexes)

				# Create unique string for table/column combination
				recordsTblCol[tableGroupName+"_"+tableName+"_"+colName] = curRowWithIndexes
			i+=1
	# Write file formatted like csv with headers/rows
	f_csv.write(json.dumps(recordsCsv))
	f_csv.close()
	pipe = Popen(['aws','s3','cp',FILE_CSV,'s3://'+BUCKET_NAME+BUCKET_KEY+FILE_CSV], stdout=PIPE)
	output = pipe.communicate()
    
	# Write file formatted with string indexes per row/column
	f_index.write(json.dumps(recordsIndex))
	f_index.close()
	pipe = Popen(['aws','s3','cp',FILE_KEYS,'s3://'+BUCKET_NAME+BUCKET_KEY+FILE_KEYS], stdout=PIPE)
	output = pipe.communicate()

	# Write file formatted with string indexes per table group and table groupings
	f_tbl.write(json.dumps(recordsTgTbl))
	f_tbl.close()
	pipe = Popen(['aws','s3','cp',FILE_TGTBL_KEYS,'s3://'+BUCKET_NAME+BUCKET_KEY+FILE_TGTBL_KEYS], stdout=PIPE)
	output = pipe.communicate()

	# Write file formatted with string indexes per table group, table, and colulumn groupings
	f_col.write(json.dumps(recordsTblCol))
	f_col.close()
	pipe = Popen(['aws','s3','cp',FILE_TBLCOL_KEYS,'s3://'+BUCKET_NAME+BUCKET_KEY+FILE_TBLCOL_KEYS], stdout=PIPE)
	output = pipe.communicate()


if __name__ == '__main__':
        run()