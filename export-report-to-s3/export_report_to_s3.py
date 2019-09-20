#!/usr/bin/env python

import ss
import sys
import json
import csv
from subprocess import PIPE,Popen
import logging
import urllib
import boto
import boto.s3

############ ENV Settings ############
logging.basicConfig(filename='s3.log', filemode='w', format='%(name)s - %(levelname)s - %(message)s')

############ GLOBALS ############
sourcePolicies = {}
AWSREGION = "us-east-1"
REPORT_NAME = sys.argv[2]
BUCKET_NAME = sys.argv[3]

BUCKET_KEY = "/mx.impervademo.com/"
FILE_KEY_INDEX = REPORT_NAME+"_key_index.json"
FILE_CSV_INDEX = REPORT_NAME+"_csv_index.json"
# open(BUCKET_PATH_INDEX, 'w').close()
open(FILE_CSV_INDEX, 'w+').close()
# f_index=open(BUCKET_PATH_INDEX,"w+")
f_csv=open(FILE_CSV_INDEX,"w+")

recordsIndex = {"records":[]}
recordsCsv = {"headers":[],"rows":[]}

# Parse CSV into dictionary with policy type and applied to assets
logging.warning("\n\n===========  Start MX policy sync ===========\n")
logging.warning('PATH2REPORT='+sys.argv[1])
PATH2REPORT = '/opt/SecureSphere/server/SecureSphere/jakarta-tomcat-secsph/webapps/SecureSphere/'+sys.argv[1]
# Example argv[1] = /WEB-INF/reptemp/ISBT_DB_Classification_Scan_Report_admin_17Sep2019_13-19-28.csv

def run():
	with open(PATH2REPORT, 'r') as f:
		i=0
		reader = csv.reader(f)
		for row in reader:
			if i==0:
				recordsCsv["headers"] = row
			else:
				recordsCsv["rows"].append(row)
			i+=1

	pipe = Popen(['aws','s3','cp',FILE_CSV_INDEX,'s3://'+BUCKET_NAME+BUCKET_KEY+FILE_CSV_INDEX], stdout=PIPE)
	output = pipe.communicate()
                

if __name__ == '__main__':
        run()

