
import os
import re
import socket
from subprocess import PIPE,Popen
import time
from time import localtime, strftime
import gzip
import zlib 
import urllib
import urllib2
from urllib2 import request_host, parse_http_list
# from urllib import request, parse
# from urllib.error import HTTPError, URLError
import json
from socket import timeout
import logging
import ssl

############### Configs ###############
BASEDIR = '/proc/hades/'
GATEWAYNAME = os.uname()[1].split('.')[0]
TIMESTAMP = strftime("%Y/%m/%d %H:%M:%S", localtime())
pipe = Popen(['uptime'], stdout=PIPE)
GATEWAY_UPTIME = pipe.communicate()[0].strip()
try:
    with open(configfile, 'r') as data:
        config = json.load(data)
except:
    logging.warning("Missing \""+configfile+"\" file, create file named \""+configfile+"\" with the following contents:\n{\n\t\"license_key\":\"abc123\",\n\t\"log_level\":\"debug\",\n\t\"account_id\":\"2295794\",\n\t\"api_key\":\"abc124\",\n\t\"event_type\":\"WAFAlerts\",\n\t\"environment\":\"dev,\"\n}")
    exit()

# Gateway level statistic
GWStats = {
    # start a few enrichment fields to give context
    "gateway": GATEWAYNAME,
    "gateway_uptime": GATEWAY_UPTIME,
    "timestamp": TIMESTAMP,
    # start list of all lines from status file
    "connection_sec":"n/a",
    "http_hits_sec":"n/a",
    "kbps":"n/a",
    "kbps_application":"n/a",
    "overload_connection_sec":"n/a",
    #"wfd_successful_hits_sec":"n/a",
    "sql_audit_phase2_events_sec":"n/a",
    "sql_hits_sec":"n/a",
    "overload_sql_audit_phase2_events_sec":"n/a",
    "overload_sql_hits_sec":"n/a"
    #"hdfs_hits_sec":"n/a",
    # "zosfile_hits_sec":"n/a"
    # "activedirectory_hits_sec":"n/a",
    # "file_aggregated_hits_sec":"n/a",
    # "file_hits_sec":"n/a",
    # "kbps_fam":"n/a",
    # "sharepoint_aggregated_hits_sec":"n/a",
    # "sharepoint_hits_sec":"n/a",
}

# Server Group level statistic
SGStatsTmpl = {
    # start a few enrichment fields to give context
    "gateway": GATEWAYNAME,
    "gateway_uptime": GATEWAY_UPTIME,
    "server_group": 'n/a',
    "server_group_id": 'n/a',
    "timestamp": TIMESTAMP,
    # start list of all lines from status file
    "kbps":"n/a",
    "http_hits_sec":"n/a",
    "connection_sec":"n/a",
    "wfd_successful_hits_sec":"n/a",
    "sql_hits_sec":"n/a",
    "sql_audit_phase2_events_sec":"n/a",
    "hdfs_hits_sec":"n/a",
    # "zosfile_hits_sec":"n/a",
    # "activedirectory_hits_sec":"n/a",
    # "file_aggregated_hits_sec":"n/a",
    # "file_hits_sec":"n/a",
    # "sharepoint_aggregated_hits_sec":"n/a",
    # "sharepoint_hits_sec":"n/a",
}

def run():
    # pull /proc/hades/status file to parse gateway level stats
    f = open(os.path.join(BASEDIR,'status'), 'r')
    gw_status_stats = f.read().split("\n")
    for stat in gw_status_stats[5:14]:
        parseGWEventStat(stat)
    for stat in gw_status_stats[25:]:
        parseGWCPUStat(stat)
    gwJsonFile = JSON_FILE_PATH+JSON_FILE_NAME+".json"
    wr = open(gwJsonFile, 'w')
    wr.write(json.dumps(GWStats))
    #makeCallNewRelicCLI(NEWRELIC_SERVER, NEWRELIC_API_KEY, GWStats)
    print(GWStats)
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
                SGStats = parseSGStat(sg_stat,SGStats)
            sendSyslog(SGStats)
            # TODO send server group level stat            


############### Global Functions ###############
def strim(str):
    return re.sub('\s\s+', ' ', str).strip()

# Parse stats and maximums
# example: 0 connection/sec (max 4 2019-03-20 05:39:56)
# [stat],[statKey],(max,[max],[max_date],[max_time])
def parseGWEventStat(stat):
    statstr = strim(stat).lower()
    statKey = statstr[statstr.index(' ')+1:statstr.index('(')-1].replace('/','_').replace(' ','_')
    statstr = statstr.replace(statstr[statstr.index(' ')+1:statstr.index('(')-1],statstr[statstr.index(' ')+1:statstr.index('(')-1].replace('/','_').replace(' ','_'))
    if statKey in GWStats:
        statAry = statstr.split(" ")
        GWStats[statKey] = int(statAry[0])
        GWStats[statKey+"_max"] = int(statAry[3])
        if statAry[3]!='0':
            GWStats[statKey+"_max_time"] = statAry[4]+" "+statAry[5][:-1]
        else:
            GWStats[statKey+"_max_time"] = 'n/a'

# Parse gateway level /proc/hades/status - CPU secion
def parseGWCPUStat(stat):
    statstr = strim(stat).lower()
    if statstr!='':
        CPUNum = statstr.split("|")[0]
        CPUStatsAry = statstr.split("|")[1:]
        # CPU# | kbps 28 (max 237244 2019-03-13 08:20:00) | packets/sec | queue length
        CPUStatKey = ["kbps","packets_sec","queue_length"]
        for CPUStat in CPUStatsAry:
            CPUStatAry = CPUStat.strip().split(' ')
            GWStats["CPU_"+CPUNum+"_kbps"] = int(CPUStatAry[0])
            GWStats["CPU_"+CPUNum+"_kbps_max"] = int(CPUStatAry[2])
            if CPUStatAry[2]!='0':
                GWStats["CPU_"+CPUNum+"_kbps_max_time"] = CPUStatAry[3]+" "+CPUStatAry[4][:-1]
            else:
                GWStats["CPU_"+CPUNum+"_kbps_max_time"] = 'n/a'

# Parse server group level /proc/hades/sg_[server group name]/status - stats and maximums
def parseSGStat(sg_stat,SGStats):
    sg_statstr = strim(sg_stat).lower()
    if sg_statstr!='':
        if sg_statstr.find("(") != -1:
            sg_statKey = sg_statstr[sg_statstr.index(' ')+1:sg_statstr.index('(')-1].replace('/','_').replace(' ','_')
            sg_statstr = sg_statstr.replace(sg_statstr[sg_statstr.index(' ')+1:sg_statstr.index('(')-1],sg_statstr[sg_statstr.index(' ')+1:sg_statstr.index('(')-1].replace('/','_').replace(' ','_'))
            if sg_statKey in SGStats:
                sg_statAry = sg_statstr.split(" ")
                SGStats[sg_statKey] = sg_statAry[0]
                SGStats[sg_statKey+"_max"] = sg_statAry[3]
                if sg_statAry[3]!='0':
                    SGStats[sg_statKey+"_max_time"] = sg_statAry[4]+" "+sg_statAry[5][:-1]
                else:
                    SGStats[sg_statKey+"_max_time"] = 'n/a'
        else:
            sg_statstr = sg_statstr.replace(sg_statstr[sg_statstr.index(' ')+1:len(sg_statstr)-sg_statstr.index(' ')+1],sg_statstr[sg_statstr.index(' ')+1:len(sg_statstr)-sg_statstr.index(' ')+1].replace('/','_').replace(' ','_'))
            sg_statAry = sg_statstr.split(" ")
            SGStats[sg_statAry[1]] = sg_statAry[0]
    return SGStats

def makeCallNewRelicCLI(param):
    new_relic_url = "https://insights-collector.newrelic.com/v1/accounts/"+config["account_id"]+"/events"
    headers = {
        "Content-Type": "application/json",
        "X-Insert-Key": config["api_key"]
    }

def sendSyslog(jsonstr):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.sendto(json.dumps(jsonstr),(SYSLOG_SERVER, SYSLOG_PORT))
    s.close()

if __name__ == '__main__':
    run()
