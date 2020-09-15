#!/usr/bin/python
# Version 
import os
from os.path import isfile, join
import socket
import subprocess
from subprocess import PIPE,Popen
from time import localtime, strftime
# from datetime import timedelta
import json
import requests
import urllib2
import logging
import re
import math
import codecs
import sys
from requests.auth import HTTPBasicAuth
import datetime

CONFIGFILE = 'config.json'
GATEWAYNAME = 'GATEWAYNAME'
gwSourceIp = "gwSourceIp"

try:
    with open(CONFIGFILE, 'r') as data:
        CONFIG = json.load(data)
except:
    print("Missing \""+CONFIGFILE+"\" file, create file named \""+CONFIGFILE+"\" with the following contents:\n{\n\t\"log_level\": \"debug\",\n\t\"log_file_name\": \"gateway_statistics.log\",\n\t\"environment\": \"dev\",\n\t\"is_userspace\":false,\n\t\"environment\": \"dev\",\n\t\"log_search\": {\n\t\t\"enabled\": true,\n\t\t\"files\": [{\n\t\t\t\"path\": \"/var/log/messages\",\n\t\t\t\"search_patterns\": [{\n\t\t\t\t\t\"name\":\"YOUR_EVENT_NAME\",\n\t\t\t\t\t\"pattern\":\"some text pattern\"\n\t\t\t\t}, {\n\t\t\t\t\t\"name\":\"YOUR_EVENT_NAME_2\",\n\t\t\t\t\t\"pattern\":\"some other text pattern\"\n\t\t\t\t}\n\t\t\t]\n\t\t}]\n\t},\n\t\"newrelic\": {\n\t\t\"enabled\": false,\n\t\t\"account_id\": \"ACCOUNT_ID\",\n\t\t\"api_key\": \"API_KEY\",\n\t\t\"event_type\": \"GWStats\"\n\t},\n\t\"influxdb\": {\n\t\t\"enabled\": true,\n\t\t\"host\": \"http://1.2.3.4:8086/write?db=imperva_performance_stats\"\n\t},\n\t\"syslog\": {\n\t\t\"enabled\": true,\n\t\t\"host\": \"1.2.3.4\",\n\t\t\"port\": 514\n\t}\n}")
    exit()

try:
    PATHTOLOGS = sys.argv[1]
except:
    print('Path to logs folder missing, please specify a path to logs folder. Example: python process_archive_json_stats.py "/tmp/archive_logs"')
    exit()

TIMESTAMP = strftime("%Y/%m/%d %H:%M:%S", localtime())

def run():
    if PATHTOLOGS:
        log_dirs = os.listdir(PATHTOLOGS)
        for dir in log_dirs:
            influxDefaultTags = "source="+dir+",gatewayname="+dir+","
            files = [f for f in os.listdir(PATHTOLOGS+dir) if isfile(join(PATHTOLOGS+dir, f))]
            for file in files:
                f = open(os.path.join(PATHTOLOGS+dir,file), 'r')
                log_file = f.read().split("\n")
                try:
                    influxdb_json = json.loads(log_file[0])
                except:
                    print("invalid json in file: "+file)
                date_time_obj = datetime.datetime.strptime(influxdb_json["timestamp"], '%Y/%m/%d %H:%M:%S')
                for measurement in influxdb_json:
                    if measurement!="timestamp":
                        curStat = influxdb_json[measurement]
                        for tags in curStat:
                            makeInfluxDBCall(measurement, influxDefaultTags+tags, ','.join(curStat[tags])+" "+str(int(date_time_obj.strftime('%s'))*1000000000))

def makeInfluxDBCall(measurement, tags, params):
    headers = {
        "Content-Type": "application/octet-stream",
    }
    influxdb_url = CONFIG["influxdb"]["host"]
    data = measurement+","+tags+" "+params
    # print("INFLUXDB REQUEST: "+influxdb_url+"?"+params)
    logging.warning("INFLUXDB REQUEST: "+influxdb_url+"?"+params)
    if "proxies" in CONFIG:
        proxies = {"https": "https://" + CONFIG["proxies"]["proxy_username"] + ":" + CONFIG["proxies"]["proxy_password"] + "@" + CONFIG["proxies"]["proxy_host"] + ":" + CONFIG["proxies"]["proxy_port"]}
        response = requests.post(influxdb_url, data=data, proxies=proxies, headers=headers, verify=False)
    else:
        if "username" in CONFIG["influxdb"]:
            response = requests.post(influxdb_url,auth=HTTPBasicAuth(CONFIG["influxdb"]["username"], CONFIG["influxdb"]["password"]), data=data, headers=headers, verify=False)
        else:
            response = requests.post(influxdb_url, data=data, headers=headers, verify=False)
        if (response.status_code!=204):
            logging.warning("[ERROR] Influxdb error - status_code ("+str(response.status_code)+") response: " + json.dumps(response.json()))

if __name__ == '__main__':
    run()
