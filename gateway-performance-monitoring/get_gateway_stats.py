#!/usr/bin/env python
import os
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

############### Configs ###############
CONFIGFILE = '/var/user-data/config.json'
BASEDIR = '/proc/hades/'
GATEWAYNAME = os.uname()[1].split('.')[0]
TIMESTAMP = strftime("%Y/%m/%d %H:%M:%S", localtime())
gwSourceIp = "n/a"
with open('/opt/SecureSphere/etc/bootstrap.xml', 'r') as content_file:
    content = content_file.read()
    m = re.search('(name=).?(management).? .*',content)
    sourceIpStr = m.group(0)
    gwSourceIp = sourceIpStr[sourceIpStr.index('address-v4="')+12:sourceIpStr.index('" address-v6=')-3]
influxDefaultTags = "source="+gwSourceIp+",gatewayname="+GATEWAYNAME+","

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

# convention is: {"measurement_name": {"tagname=tagvalue":["array=0","of=1","metrics=1"]}, ...  }
# imperva_gw_hades example: {"notag":["kbps=0","kbps_max=0","kbps_application=0","kbps_application_max=0"...]}
# imperva_gw_workers example: {"worker=0":["worker_kbps=0","worker_kbps_max=0","worker_packets_sec=0"...]}
# imperva_gw_net example: {"interface=eth0":["speed=10000","rx_packets=3766875","rx_errors=0","rx_dropped=0"...]}
# imperva_gw_disk example: {"volume=/var":["disk_capacity=41284928","disk_used=6989272","disk_available=32198504"...]}
# imperva_gw_sys example: {"model=V2500":["uptime=2796","gw_supported_kbps=2000","gw_supported_hps=9000","mem_total=3926948"...]}
# imperva_sg example: {"servergroupname=Mongo DB":["kbps=10","kbps_max=100","connections_sec=10","connectiions_sec_max=100"...]}

influxDbStats = {
    "imperva_gw_hades":{"file=/proc/hades/status":[]},
    "imperva_gw_workers":{},
    "imperva_gw_net":{},
    "imperva_gw_disk":{},
    "imperva_gw_sys":{},
    "imperva_sg":{}
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
    getNetworkStats()
    getDiskStats()
    getSysStats()

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
    if CONFIG["syslog"]["enabled"]:
        sendSyslog(GWStats)

    sg_dirs = os.listdir(BASEDIR)
    for dir in sg_dirs:
        if dir[:3]=='sg_':
            SGStats = SGStatsTmpl.copy()
            f = open(os.path.join(BASEDIR+dir,'status'), 'r')
            sg_status_stats = f.read().split("\n")
            servergroupname = sg_status_stats[0][:sg_status_stats[0].rfind('_')].lower().replace(" ","_")
            influxDbStats["imperva_sg"]["servergroupname="+servergroupname] = []
            SGStats["server_group"] = servergroupname
            SGStats["server_group_id"] = sg_status_stats[0][sg_status_stats[0].rfind('_')+1:len(sg_status_stats[0])-1]
            for sg_stat in sg_status_stats[1:]:
                SGStats = parseSGStat(servergroupname, sg_stat, SGStats)

            if CONFIG["newrelic"]["enabled"]:
                makeCallNewRelicCall(SGStats)
            # if CONFIG["servicenow"]["enabled"]:
            #     print("make servicenow call")
            #     # todo finish integration with ServiceNow
            if CONFIG["syslog"]["enabled"]:
                sendSyslog(SGStats)

    if CONFIG["influxdb"]["enabled"]:
        for measurement in influxDbStats:
            curStat = influxDbStats[measurement]
            for tags in curStat:
                makeInfluxDBCall(measurement, influxDefaultTags+tags, ','.join(curStat[tags]))

#########################################################
############### General Porpuse Functions ###############
#########################################################
def strim(str):
    return re.sub('\s\s+', ' ', str).strip()

def getNetworkStats():
    pipe = Popen(['ls','/sys/class/net'], stdout=PIPE)
    output = pipe.communicate()
    interfaces = str(output[0]).split("\n")
    for ifacename in interfaces:
        if(ifacename[:3]=="eth"):
            influxDbStats["imperva_gw_net"]["interface="+ifacename] = []
            influxIfaceStatAry = influxDbStats["imperva_gw_net"]["interface="+ifacename]
            pipe = Popen(['ifconfig',ifacename], stdout=PIPE)
            ifconfigoutput = pipe.communicate()
            for iface in ifconfigoutput[0].strip().split("\n"):
                iface = iface.strip()
                if (iface[:11]=="RX packets:"):
                    rxAry = iface[11:].split(" ")
                    influxIfaceStatAry.append("rx_packets="+rxAry[0])
                    influxIfaceStatAry.append("rx_errors="+rxAry[1][rxAry[1].find(':')+1:])
                    influxIfaceStatAry.append("rx_dropped="+rxAry[2][rxAry[2].find(':')+1:])
                    influxIfaceStatAry.append("rx_overruns="+rxAry[3][rxAry[3].find(':')+1:])
                    influxIfaceStatAry.append("rx_frame="+rxAry[4][rxAry[4].find(':')+1:])
                elif (iface[:11]=="TX packets:"):
                    txAry = iface[11:].split(" ")
                    influxIfaceStatAry.append("tx_packets="+txAry[0])
                    influxIfaceStatAry.append("tx_errors="+txAry[1][txAry[1].find(':')+1:])
                    influxIfaceStatAry.append("tx_dropped="+txAry[2][txAry[2].find(':')+1:])
                    influxIfaceStatAry.append("tx_overruns="+txAry[3][txAry[3].find(':')+1:])
                    influxIfaceStatAry.append("tx_carrier="+txAry[4][txAry[4].find(':')+1:])
                elif (iface[:11]=="collisions:"):
                    colAry = iface[11:].split(" ")
                    influxIfaceStatAry.append("collisions="+colAry[0])
                elif (iface[:9]=="RX bytes:"):
                    rxAry = iface[9:].split(" ")
                    txBytesAry = rxAry[5].split(":")
                    influxIfaceStatAry.append("rx_bytes="+rxAry[0])
                    influxIfaceStatAry.append("tx_bytes="+txBytesAry[1])

def getDiskStats():
    pipe = Popen(['df'], stdout=PIPE)
    output = pipe.communicate()
    df = str(output[0]).split("\n")
    sda1Ary = ' '.join(df[4].split()).split(" ")
    influxDbStats["imperva_gw_disk"]["volume="+sda1Ary[5]] = ["disk_capacity="+sda1Ary[1],"disk_used="+sda1Ary[2],"disk_available="+sda1Ary[3]]
    sysvgDataAry = ' '.join(df[6].split()).split(" ")
    influxDbStats["imperva_gw_disk"]["volume="+sysvgDataAry[4]] = ["disk_capacity="+sysvgDataAry[0],"disk_used="+sysvgDataAry[1],"disk_available="+sysvgDataAry[2]]
    sysvgVarAry = ' '.join(df[8].split()).split(" ")
    influxDbStats["imperva_gw_disk"]["volume="+sysvgVarAry[4]] = ["disk_capacity="+sysvgVarAry[0],"disk_used="+sysvgVarAry[1],"disk_available="+sysvgVarAry[2]]

def getSysStats():
    pipe = Popen(['impctl','platform','show'], stdout=PIPE)
    output = pipe.communicate()
    sysRecord = str(output[0]).split("\n")
    modelAry = ' '.join(sysRecord[4].split()).split(" ")
    versionAry = ' '.join(sysRecord[5].split()).split(" ")
    influxDbStats["imperva_gw_sys"]["model="+modelAry[1]+",version="+versionAry[1]] = []
    sysStat = influxDbStats["imperva_gw_sys"]["model="+modelAry[1]+",version="+versionAry[1]]
    sysStat.append("gw_supported_kbps="+gwSizingStats[modelAry[1]]["gw_supported_kbps"])
    sysStat.append("gw_supported_hps="+gwSizingStats[modelAry[1]]["gw_supported_hps"])

    pipe = Popen(['cat','/proc/uptime'], stdout=PIPE)
    output = pipe.communicate()
    uptimeAry = str(output[0]).split("\n")
    uptime = str(uptimeAry[0]).split(" ")
    sysStat.append("uptime="+uptime[0][:-3])
    pipe = Popen(['top','-bn','1'], stdout=PIPE)
    output = pipe.communicate()
    topRecord = str(output[0]).split("\n")
    memDataAry = ' '.join(topRecord[4].split()).split(" ")
    swapDataAry = ' '.join(topRecord[5].split()).split(" ")
    sysStat.append("mem_total="+memDataAry[1][:-1])
    sysStat.append("mem_used="+memDataAry[3][:-1])
    sysStat.append("mem_free="+memDataAry[5][:-1])
    sysStat.append("mem_buffers="+memDataAry[7][:-1])
    sysStat.append("swap_total="+swapDataAry[1][:-1])
    sysStat.append("swap_used="+swapDataAry[3][:-1])
    sysStat.append("swap_free="+swapDataAry[5][:-1])
    sysStat.append("swap_cached="+swapDataAry[7][:-1])

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
            influxDbStats["imperva_gw_hades"]["file=/proc/hades/status"].append(statKey+"="+str(int(statAry[0])))
            influxDbStats["imperva_gw_hades"]["file=/proc/hades/status"].append(statKey+"_max="+str(int(statAry[3])))

# Parse gateway level /proc/hades/status - CPU secion
def parseGWCPUStat(stat):
    if strim(stat) != '':
        statstr = strim(stat).lower()
        CPUNum = strim(statstr.split("|")[0])
        if (CPUNum.isdigit()):
            CPUStatsAry = statstr.split("|")[1:]
            influxDbStats["imperva_gw_workers"]["worker="+CPUNum] = []
            #example:  CPU# | kbps 28 (max 237244 2019-03-13 08:20:00) | packets/sec | queue length
            CPUStatKey = ["kbps","packets_sec","queue_length"]
            for index, CPUStat in enumerate(CPUStatsAry, start=0):
                CPUStatAry = CPUStat.strip().split(' ')
                GWStats["CPU_"+CPUNum+"_kbps"] = int(CPUStatAry[0])
                influxDbStats["imperva_gw_workers"]["worker="+CPUNum].append("worker_"+CPUStatKey[index]+"="+CPUStatAry[0])
                influxDbStats["imperva_gw_workers"]["worker="+CPUNum].append("worker_"+CPUStatKey[index]+"_max="+CPUStatAry[2])

# Parse server group level /proc/hades/sg_[server group name]/status - stats and maximums
def parseSGStat(servergroupname,sg_stat,SGStats):
    sg_statstr = strim(sg_stat).lower()
    if sg_statstr != '':
        if sg_statstr.find("(") != -1:
            sg_statKey = sg_statstr[sg_statstr.index(' ')+1:sg_statstr.index('(')-1].replace('/','_').replace(' ','_')
            sg_statstr = sg_statstr.replace(sg_statstr[sg_statstr.index(' ')+1:sg_statstr.index('(')-1],sg_statstr[sg_statstr.index(' ')+1:sg_statstr.index('(')-1].replace('/','_').replace(' ','_'))
            if sg_statKey in SGStats:
                sg_statAry = sg_statstr.split(" ")
                SGStats[sg_statKey] = sg_statAry[0]
                SGStats[sg_statKey+"_max"] = sg_statAry[3]
                influxDbStats["imperva_sg"]["servergroupname="+servergroupname].append(sg_statKey+"="+sg_statAry[0])
                influxDbStats["imperva_sg"]["servergroupname="+servergroupname].append(sg_statKey+"_max="+sg_statAry[3])
        else:
            sg_statstr = sg_statstr.replace(sg_statstr[sg_statstr.index(' ')+1:len(sg_statstr)-sg_statstr.index(' ')+1],sg_statstr[sg_statstr.index(' ')+1:len(sg_statstr)-sg_statstr.index(' ')+1].replace('/','_').replace(' ','_'))
            sg_statAry = sg_statstr.split(" ")
            if sg_statAry[1] in SGStats:
                SGStats[sg_statAry[1]] = sg_statAry[0]
                influxDbStats["imperva_sg"]["servergroupname="+servergroupname].append(sg_statAry[1]+"="+sg_statAry[0])
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

def makeInfluxDBCall(measurement, tags, params):
    headers = {
        "Content-Type": "application/octet-stream",
    }
    influxdb_url = CONFIG["influxdb"]["host"]
    data = measurement+","+tags+" "+params
    logging.warning("INFLUXDB REQUEST: "+influxdb_url+"?"+params)
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

gwSizingStats = {
    # Physical Appliances
    "X2500":{"gw_supported_kbps":"62500","gw_supported_hps":"5000"},    
    "X4500":{"gw_supported_kbps":"125000","gw_supported_hps":"9000"},
    "X6500":{"gw_supported_kbps":"250000","gw_supported_hps":"18000"},
    "X8500":{"gw_supported_kbps":"625000","gw_supported_hps":"36000"},
    "X10k":{"gw_supported_kbps":"1250000","gw_supported_hps":"72000"},
    # Virtual Appliances
    "V2500":{"gw_supported_kbps":"62500","gw_supported_hps":"5000"},
    "V4500":{"gw_supported_kbps":"125000","gw_supported_hps":"9000"},
    "V6500":{"gw_supported_kbps":"250000","gw_supported_hps":"18000"},
    # AWS Appliances
    "AV1000":{"gw_supported_kbps":"12500","gw_supported_hps":"2500"},
    "AV2500":{"gw_supported_kbps":"62500","gw_supported_hps":"5000"},
    "AV4500":{"gw_supported_kbps":"125000","gw_supported_hps":"9000"},
    "AV6500":{"gw_supported_kbps":"250000","gw_supported_hps":"18000"},
    # Azure Appliances
    "MV1000":{"gw_supported_kbps":"12500","gw_supported_hps":"2500"},
    "MV2500":{"gw_supported_kbps":"62500","gw_supported_hps":"5000"},
    "MV4500":{"gw_supported_kbps":"125000","gw_supported_hps":"9000"},
    "MV6500":{"gw_supported_kbps":"250000","gw_supported_hps":"18000"}
}

def sendSyslog(jsonstr):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.sendto(json.dumps(jsonstr), (CONFIG["syslog"]["host"], CONFIG["syslog"]["port"]))
    s.close()

if __name__ == '__main__':
    run()
