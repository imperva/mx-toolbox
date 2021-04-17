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
import urllib3
import logging
import re
import math
import codecs
import sys
from requests.auth import HTTPBasicAuth
import datetime
import csv
import pyparsing

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

def run():
    if PATHTOLOGS:
        log_dirs = os.listdir(PATHTOLOGS)
        files = [f for f in os.listdir(PATHTOLOGS) if isfile(join(PATHTOLOGS, f))]
        for file in files:
            if (file != ".DS_Store"):
                print(file)
                f = open(os.path.join(PATHTOLOGS,file), 'r')
                log_file = f.read().split("\n")
                headers = pyparsing.commaSeparatedList.parseString(log_file.pop(0)).asList()
                for rowData in log_file:
                    influxDbStats = {
                        "imperva_gw_hades":{"file=/proc/hades/status":[]},
                        "imperva_gw_workers":{},
                        "imperva_gw_net":{},
                        "imperva_gw_disk":{},
                        "imperva_gw_sys":{},
                        "imperva_gw_top_cpu":{},
                        "imperva_gw_sar_cpu":{},
                        "imperva_gw_cpuload":{},
                        "imperva_sg":{},
                        "imperva_gw_meminfo":{}
                    }
                    row = pyparsing.commaSeparatedList.parseString(rowData).asList()
                    if len(row)>1:
                        jsonData = json.loads(row[0][1:-1].replace('""','"'))
                        influxDefaultTags = "source="+jsonData["gw"]+",gatewayname="+jsonData["gw"]+","
                        timestamp = row[1] 
                        if "server_group" in jsonData:
                            influxDbStats["imperva_sg"]["servergroupname="+jsonData["server_group"]+",mx_host="+jsonData["mx"]] = []
                            influxSgObj = influxDbStats["imperva_sg"]["servergroupname="+jsonData["server_group"]+",mx_host="+jsonData["mx"]]
                            for counter in jsonData["hades_counters"]:
                                influxSgObj.append(counter+"="+str(jsonData["hades_counters"][counter]))

                        else:
                            influxDbStats["imperva_gw_hades"]["file=/proc/hades/status"] = []
                            for counter in jsonData["hades_counters"]:
                                influxDbStats["imperva_gw_hades"]["file=/proc/hades/status"].append(counter+"="+str(jsonData["hades_counters"][counter]))

                            influxDbStats["imperva_gw_workers"]["file=/proc/hades/status"] = []
                            for core in jsonData["cores"]:
                                influxDbStats["imperva_gw_workers"]["worker="+core] = []
                                for stat in jsonData["cores"][core]:
                                    influxDbStats["imperva_gw_workers"]["worker="+core].append("worker_"+stat+"="+str(jsonData["cores"][core][stat]))

                            for interface in jsonData["network"]:
                                influxDbStats["imperva_gw_net"]["interface="+interface+",ipaddress="+jsonData["gw"]+",uptime="+jsonData["system"]["uptime"]] = []
                                influxNetObj = influxDbStats["imperva_gw_net"]["interface="+interface+",ipaddress="+jsonData["gw"]+",uptime="+jsonData["system"]["uptime"]]
                                for stat in jsonData["network"][interface]:
                                    interfaceObj = jsonData["network"][interface]
                                    influxNetObj.append(stat+"="+str(interfaceObj[stat]))

                            for disk in jsonData["disk"]:
                                influxDbStats["imperva_gw_disk"]["volume="+disk] = []
                                for stat in jsonData["disk"][disk]:
                                    influxDbStats["imperva_gw_disk"]["volume="+disk].append(stat+"="+str(jsonData["disk"][disk][stat]))

                            influxDbStats["imperva_gw_sys"]["mx_hostname"] = jsonData["mx"]
                            influxDbStats["imperva_gw_sys"]["model"] = jsonData["system"]["model"]
                            influxDbStats["imperva_gw_sys"]["version="+jsonData["system"]["version"]] = []
                            GWSystemObj = influxDbStats["imperva_gw_sys"]["version="+jsonData["system"]["version"]]
                            GWSystemObj.append("gw_supported_kbps="+str(jsonData["system"]["supported_kbps"]))
                            GWSystemObj.append("gw_supported_hps="+str(jsonData["system"]["supported_hps"]))
                            GWSystemObj.append("uptime="+str(jsonData["system"]["uptime"]))
                            GWSystemObj.append("mem_total="+str(jsonData["memory"]["top_mem_total"]))
                            GWSystemObj.append("mem_free="+str(jsonData["memory"]["top_mem_free"]))
                            GWSystemObj.append("mem_used="+str(jsonData["memory"]["top_mem_used"]))
                            GWSystemObj.append("swap_total="+str(jsonData["memory"]["top_swap_total"]))
                            GWSystemObj.append("swap_free="+str(jsonData["memory"]["top_swap_free"]))
                            GWSystemObj.append("swap_used="+str(jsonData["memory"]["top_swap_used"]))

                            for cpu in jsonData["cpu"]["top"]:
                                influxDbStats["imperva_gw_top_cpu"]["cpu="+cpu] = []
                                cpuObj = jsonData["cpu"]["top"][cpu]
                                for stat in cpuObj:
                                    influxDbStats["imperva_gw_top_cpu"]["cpu="+cpu].append(stat+"="+str(cpuObj[stat]))
                            
                            for stat in jsonData["cpu"]["last_sec_load"]:
                                cpu = stat.split("_").pop(0).replace("cpu","")
                                if cpu != "average":
                                    influxDbStats["imperva_gw_cpuload"]["cpu="+cpu] = []
                                    influxDbStats["imperva_gw_cpuload"]["cpu="+cpu].append("load="+str(jsonData["cpu"]["last_sec_load"][stat]))
                            
                            for core in jsonData["cores"]:
                                influxDbStats["imperva_gw_meminfo"]["core="+core] = []
                                coreObj = jsonData["cores"][core]
                                for stat in coreObj:
                                    influxDbStats["imperva_gw_meminfo"]["core="+core].append(stat+"="+str(coreObj[stat]))
                            
                            for worker in jsonData["memory"]["workers_meminfo"]:
                                for stat in jsonData["memory"]["workers_meminfo"][worker]:
                                    influxDbStats["imperva_gw_meminfo"]["core="+worker].append(stat+"="+str(jsonData["memory"]["workers_meminfo"][worker][stat]))


                    date_time_obj = datetime.datetime.strptime(jsonData["timestamp"].split(".").pop(0), '%Y-%m-%dT%H:%M:%S')
                    for measurement in influxDbStats:
                        if measurement!="timestamp":
                            curStat = influxDbStats[measurement]
                            for tags in curStat:
                                if (tags=="version="):
                                    curtags='version=NA'
                                else:
                                    curtags = tags
                                makeInfluxDBCall(measurement, influxDefaultTags+curtags, ','.join(curStat[tags])+" "+str(int(date_time_obj.strftime('%s'))*1000000000))

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
            logging.warning("[ERROR] Influxdb error - status_code ("+str(response.status_code)+") response: {}".format(response))

if __name__ == '__main__':
    run()
