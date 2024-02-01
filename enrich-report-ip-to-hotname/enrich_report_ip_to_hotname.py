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
logging.basicConfig(filename="enrich-report-ip-to-hotname.log", filemode='w', format='%(name)s - %(levelname)s - %(message)s')

if len(sys.argv)<2:	
	print('[ERROR] Missing argument, please specify the path to the csv report to enrich.')
	logging.warning('[ERROR] Missing argument, please specify the path to the csv report to enrich.')
	quit()

############ GLOBALS ############
PATH2REPORT = '/opt/SecureSphere/server/SecureSphere/jakarta-tomcat-secsph/webapps/SecureSphere/'+sys.argv[1]
# PATH2REPORT = sys.argv[1]
DATASETNAME = "db_hosts"
SOURCECOLNAME = "Target Server IP"
DESTCOLNAME = "Target Server Host Name"
ip_host_mapping = {}
logging.warning("\n\n===========  Start enrich report ip to hostname ===========\n")
logging.warning('DATASETNAME='+DATASETNAME)
logging.warning('PATH2REPORT='+PATH2REPORT)

NEW_CSV = PATH2REPORT.split('/').pop().split(".").pop(0)+"_enriched.csv"
open(NEW_CSV, 'w+').close()
f_index=open(NEW_CSV,"w+")

CSV_DATA = []
def run():
	with open(PATH2REPORT, 'r') as f:
		# pull down the data set
		session_id = ss.login(CONFIG["mx"]["endpoint"], CONFIG["mx"]["username"], CONFIG["mx"]["password"])
		response = ss.makeCall(CONFIG["mx"]["endpoint"],session_id, "/conf/dataSets/"+DATASETNAME+"/data")
		responseObj = response.json()
		for record in responseObj["records"]:
			ip_host_mapping[record["database_name"]] = record["server_name"]
		i=0
		reader = csv.reader(f)
		headerIndex = {}
		for row in reader:
			if i==0:
				j=0
				CSV_DATA.append('"'+'","'.join(row)+'"')
				for header in row:
					headerIndex[header] = j
					j+=1
			else:
				if row[headerIndex[DESTCOLNAME]].strip()=="":
					if row[headerIndex[SOURCECOLNAME]] in ip_host_mapping:
						row[headerIndex[DESTCOLNAME]] = ip_host_mapping[row[headerIndex[SOURCECOLNAME]]]
				else:
					row.append("N/A")				
				CSV_DATA.append('"'+'","'.join(row)+'"')
			i+=1		
		f_index.write("\n".join(CSV_DATA))
		f_index.close()
		# pipe = Popen(['sshpass','-p',SCP_PASS,'scp',CSV_DATA,SCP_LOCATION], stdout=PIPE)
		# output = pipe.communicate()
		# os.remove(CSV_DATA)

	logging.warning("\n\n===========  End enrich report ip to hostname ===========\n")

if __name__ == '__main__':
        run()