#!/usr/bin/env python

import os
import socket
from subprocess import PIPE,Popen
from time import localtime, strftime
# from datetime import timedelta
import json
import requests
import urllib3
import logging
import re

############### Configs ###############
CONFIGFILE = 'config.json'
BASEDIR = '/proc/hades/'
GATEWAYNAME = os.uname()[1].split('.')[0]
TIMESTAMP = strftime("%Y/%m/%d %H:%M:%S", localtime())
pipe = Popen(['uptime'], stdout=PIPE)
# GATEWAY_UPTIME = timedelta(microseconds=round(pipe.communicate()[0].strip(),-3))
try:
    with open(CONFIGFILE, 'r') as data:
        CONFIG = json.load(data)
except:
    print("Missing \""+CONFIGFILE+"\" file, create file named \""+CONFIGFILE+"\" with the following contents:\n{\n\t\"log_level\": \"debug\",\n\t\"environment\": \"dev\",\n\t\"gw_log_search\": {\n\t\t\"enabled\": true,\n\t\t\"files\": [{\n\t\t\t\"path\": \"/var/log/messages\",\n\t\t\t\"search_patterns\": [{\n\t\t\t\t\t\"name\":\"YOUR_EVENT_NAME\",\n\t\t\t\t\t\"pattern\":\"some text pattern\"\n\t\t\t\t}, {\n\t\t\t\t\t\"name\":\"YOUR_EVENT_NAME_2\",\n\t\t\t\t\t\"pattern\":\"some other text pattern\"\n\t\t\t\t}\n\t\t\t]\n\t\t}]\n\t},\n\t\"newrelic\": {\n\t\t\"enabled\": false,\n\t\t\"account_id\": \"ACCOUNT_ID\",\n\t\t\"api_key\": \"API_KEY\",\n\t\t\"event_type\": \"GWStats\"\n\t},\n\t\"servicenow\": {\n\t\t\"enabled\": false,\n\t\t\"account_id\": \"ACCOUNT_ID\",\n\t\t\"api_key\": \"API_KEY\"\n\t},\n\t\"syslog\": {\n\t\t\"enabled\": true,\n\t\t\"host\": \"1.2.3.4\",\n\t\t\"port\": 514\n\t}\n}")
    exit()

############ ENV Settings ############
urllib3.disable_warnings()
logging.basicConfig(filename=CONFIG["log_file_name"], filemode='w', format='%(name)s - %(levelname)s - %(message)s')

# Gateway level statistic
GWStats = {
    # start a few enrichment fields to give context
    "gateway": GATEWAYNAME,
    # "gateway_uptime": GATEWAY_UPTIME,
    "timestamp": TIMESTAMP,
    # start list of all lines from status file
    "connection_sec": True,
    "http_hits_sec": True,
    "kbps": True,
    "kbps_application": True,
    "overload_connection_sec": True,
    # "wfd_successful_hits_sec": True,
    "sql_audit_phase2_events_sec": True,
    "sql_hits_sec": True,
    "overload_sql_audit_phase2_events_sec": True,
    "overload_sql_hits_sec": True
    # "hdfs_hits_sec": True,
    # "zosfile_hits_sec": True
    # "activedirectory_hits_sec": True,
    # "file_aggregated_hits_sec": True,
    # "file_hits_sec": True,
    # "kbps_fam": True,
    # "sharepoint_aggregated_hits_sec": True,
    # "sharepoint_hits_sec": True,
}

# Server Group level statistic
SGStatsTmpl = {
    # start a few enrichment fields to give context
    "gateway": GATEWAYNAME,
    # "gateway_uptime": GATEWAY_UPTIME,
    "server_group": True,
    "server_group_id": True,
    "timestamp": TIMESTAMP,
    # start list of all lines from status file
    "kbps": True,
    "http_hits_sec": True,
    "connection_sec": True,
    "wfd_successful_hits_sec": True,
    "sql_hits_sec": True,
    "sql_audit_phase2_events_sec": True,
    "hdfs_hits_sec": True,
    # "zosfile_hits_sec": True,
    # "activedirectory_hits_sec": True,
    # "file_aggregated_hits_sec": True,
    # "file_hits_sec": True,
    # "sharepoint_aggregated_hits_sec": True,
    # "sharepoint_hits_sec": True,
}

def run():
    # pull /proc/hades/status file to parse gateway level stats
    f = open(os.path.join(BASEDIR, 'status'), 'r')
    gw_status_stats = f.read().split("\n")
    statType = None

    for stat in gw_status_stats:
        if strim(stat)[0:6] != "Global" and strim(stat)[0:6] != "Worker":
            if statType=='stat':
                parseGWEventStat(stat)
            if statType=='cpu':
                parseGWCPUStat(stat)
        elif strim(stat)[0:6] == "Global":
            statType = 'stat'
        elif strim(stat)[0:6] == "Worker":
            statType = 'cpu'

    if CONFIG["gw_log_search"]["enabled"]:
        for fileconfig in CONFIG["gw_log_search"]["files"]:
            for patternconfig in fileconfig["search_patterns"]:
                matches = searchLogFile(fileconfig["path"], patternconfig["pattern"])
                GWStats[patternconfig["name"]] = "\n".join(matches)

    if CONFIG["newrelic"]["enabled"]:
        makeCallNewRelicCall(GWStats)
    # if CONFIG["servicenow"]["enabled"]:
    #     print("make servicenow call")
    #     # todo finish integration with ServiceNow
    if CONFIG["influxdb"]["enabled"]:
        makeInfluxDBCall(GWStats,"ImpervaGW","gatewayname="+GATEWAYNAME)
    if CONFIG["syslog"]["enabled"]:
        sendSyslog(GWStats)

    sg_dirs = os.listdir(BASEDIR)
    for dir in sg_dirs:
        if dir[:3]=='sg_':
            SGStats = SGStatsTmpl.copy()
            f = open(os.path.join(BASEDIR+dir,'status'), 'r')
            sg_status_stats = f.read().split("\n")
            SGStats["server_group"] = sg_status_stats[0][:sg_status_stats[0].rfind('_')]
            SGStats["server_group_id"] = sg_status_stats[0][sg_status_stats[0].rfind('_')+1:len(sg_status_stats[0])-1]
            for sg_stat in sg_status_stats[1:]:
                SGStats = parseSGStat(sg_stat, SGStats)

            if CONFIG["newrelic"]["enabled"]:
                makeCallNewRelicCall(SGStats)
            # if CONFIG["servicenow"]["enabled"]:
            #     print("make servicenow call")
            #     # todo finish integration with ServiceNow
            if CONFIG["influxdb"]["enabled"]:
                makeInfluxDBCall(GWStats,"ImpervaSG","gatewayname="+GATEWAYNAME+",servergroupname="+SGStats["server_group"])
            if CONFIG["syslog"]["enabled"]:
                sendSyslog(SGStats)

#########################################################
############### General Porpuse Functions ###############
#########################################################
def strim(str):
    return re.sub('\s\s+', ' ', str).strip()

# Parse stats and maximums
# example: 0 connection/sec (max 4 2019-03-20 05:39:56)
# [stat],[statKey],(max,[max],[max_date],[max_time])
def parseGWEventStat(stat):
    if strim(stat) != '':
        statstr = strim(stat).lower()
        statKey = statstr[statstr.index(' ')+1:statstr.index('(')-1].replace('/','_').replace(' ','_')
        statstr = statstr.replace(statstr[statstr.index(' ')+1:statstr.index('(')-1],statstr[statstr.index(' ')+1:statstr.index('(')-1].replace('/','_').replace(' ','_'))
        if statKey in GWStats:
            statAry = statstr.split(" ")
            GWStats[statKey] = int(statAry[0])
            GWStats[statKey+"_max"] = int(statAry[3])

# Parse gateway level /proc/hades/status - CPU secion
def parseGWCPUStat(stat):
    if strim(stat) != '':
        statstr = strim(stat).lower()
        CPUNum = strim(statstr.split("|")[0])
        CPUStatsAry = statstr.split("|")[1:]
        #example:  CPU# | kbps 28 (max 237244 2019-03-13 08:20:00) | packets/sec | queue length
        CPUStatKey = ["kbps","packets_sec","queue_length"]
        for CPUStat in CPUStatsAry:
            CPUStatAry = CPUStat.strip().split(' ')
            GWStats["CPU_"+CPUNum+"_kbps"] = int(CPUStatAry[0])

# Parse server group level /proc/hades/sg_[server group name]/status - stats and maximums
def parseSGStat(sg_stat,SGStats):
    sg_statstr = strim(sg_stat).lower()
    if sg_statstr != '':
        if sg_statstr.find("(") != -1:
            sg_statKey = sg_statstr[sg_statstr.index(' ')+1:sg_statstr.index('(')-1].replace('/','_').replace(' ','_')
            sg_statstr = sg_statstr.replace(sg_statstr[sg_statstr.index(' ')+1:sg_statstr.index('(')-1],sg_statstr[sg_statstr.index(' ')+1:sg_statstr.index('(')-1].replace('/','_').replace(' ','_'))
            if sg_statKey in SGStats:
                sg_statAry = sg_statstr.split(" ")
                SGStats[sg_statKey] = sg_statAry[0]
                SGStats[sg_statKey+"_max"] = sg_statAry[3]
        else:
            sg_statstr = sg_statstr.replace(sg_statstr[sg_statstr.index(' ')+1:len(sg_statstr)-sg_statstr.index(' ')+1],sg_statstr[sg_statstr.index(' ')+1:len(sg_statstr)-sg_statstr.index(' ')+1].replace('/','_').replace(' ','_'))
            sg_statAry = sg_statstr.split(" ")
            if sg_statAry[1] in SGStats:
                SGStats[sg_statAry[1]] = sg_statAry[0]
    return SGStats

def makeCallNewRelicCall(stat):
    stat["eventType"] = CONFIG["newrelic"]["event_type"]
    new_relic_url = "https://insights-collector.newrelic.com/v1/accounts/"+CONFIG["newrelic"]["account_id"]+"/events"
    headers = {
        "Content-Type": "application/json",
        "X-Insert-Key": CONFIG["newrelic"]["api_key"]
    }
    logging.warning("NEW RELIC REQUEST (" + new_relic_url + ")" + json.dumps(stat))
    if "proxies" in CONFIG:
        proxies = {"https": "https://" + CONFIG["proxies"]["proxy_username"] + ":" + CONFIG["proxies"]["proxy_password"] + "@" + CONFIG["proxies"]["proxy_host"] + ":" + CONFIG["proxies"]["proxy_port"]}
        response = requests.post(new_relic_url, json.dumps(stat), proxies=proxies, headers=headers, verify=False)
    else:
        response = requests.post(new_relic_url, json.dumps(stat), headers=headers, verify=False)

def makeInfluxDBCall(stat, measurement, tags):
    headers = {
        "Content-Type": "application/octet-stream",
    }
    influxdb_url = CONFIG["influxdb"]["host"]
    logging.warning("INFLUXDB REQUEST (" + influxdb_url + ")" + json.dumps(stat))
    data = measurement+","+tags+" "
    isFirst = True
    for key in stat:
        if key!="gateway" and key!="timestamp" and key!="server_group":
            if not isFirst:
                data +=","
            data+=key+"="+str(stat[key])
        isFirst = False
    if "proxies" in CONFIG:
        proxies = {"https": "https://" + CONFIG["proxies"]["proxy_username"] + ":" + CONFIG["proxies"]["proxy_password"] + "@" + CONFIG["proxies"]["proxy_host"] + ":" + CONFIG["proxies"]["proxy_port"]}
        response = requests.post(influxdb_url, data=data, proxies=proxies, headers=headers, verify=False)
    else:
        response = requests.post(influxdb_url, data=data, headers=headers, verify=False)
        if (response.status_code!=204):
            logging.warning("[ERROR] Influxdb error - status_code ("+str(response.status_code)+") response: " + json.dumps(response.json()))

def searchLogFile(filename, pattern):
    matches = []
    with open(filename, 'r') as file_:
        line_list = list(file_)
        line_list.reverse()
        for line in line_list:
            if line.find(pattern) != -1:
                matches.append(line)
    return(matches)

def sendSyslog(jsonstr):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.sendto(json.dumps(jsonstr), (CONFIG["syslog"]["host"], CONFIG["syslog"]["port"]))
    s.close()

if __name__ == '__main__':
    run()
