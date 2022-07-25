#!/usr/bin/python
# Version 
import os
import socket
import subprocess
from subprocess import PIPE,Popen
from time import localtime, strftime
# from datetime import timedelta
import datetime
import json
import requests
import urllib2
import logging
import re
import math
import codecs
from requests.auth import HTTPBasicAuth
import logging.handlers

# REQUESTS_CA_BUNDLE=FILENAME

############### Configs ###############
CONFIGFILE = '/var/user-data/config.json'
GATEWAYNAME = os.uname()[1].split('.')[0]
# TIMESTAMP = strftime("%Y/%m/%d %H:%M:%S", localtime())
TIMESTAMP = datetime.datetime.now().isoformat()
gwSourceIp = "n_a"
with open('/opt/SecureSphere/etc/bootstrap.xml', 'r') as content_file:
    content = content_file.read()
    m = re.search('(name=).?(management).? .*',content)
    sourceIpStr = m.group(0)
    gwSourceIp = sourceIpStr[sourceIpStr.index('address-v4="')+12:sourceIpStr.index('" address-v6=')-3]
influxDefaultTags = "source="+gwSourceIp+",gatewayname="+GATEWAYNAME+","
GWMODEL = ""
CONNECTIONTIMEOUT = 5 # in seconds
global logHostAvailable
logHostAvailable = {
    "newrelic":True,
    "influxdb":True,
    "syslog":True,
    "sonar":True
}
try:
    with open(CONFIGFILE, 'r') as data:
        CONFIG = json.load(data)
except:
    print("Missing \""+CONFIGFILE+"\" file, create file named \""+CONFIGFILE+"\" with the following contents:\n{\n\t\"log_level\": \"WARNING\",\n\t\"log_file_name\": \"gateway_statistics.log\",\n\t\"environment\": \"dev\",\n\t\"is_userspace\": false, \n\t\"gateway_mx_host_display_name\": \"your_gateway_mx_hostname_here\",\n\t\"log_search\": {\n\t\t\"enabled\": false,\n\t\t\"files\": [{\n\t\t\t\"path\": \"/var/log/messages\",\n\t\t\t\"search_patterns\": [{\n\t\t\t\t\t\"name\":\"YOUR_EVENT_NAME\",\n\t\t\t\t\t\"pattern\":\"some text pattern\"\n\t\t\t\t}, {\n\t\t\t\t\t\"name\":\"YOUR_EVENT_NAME_2\",\n\t\t\t\t\t\"pattern\":\"some other text pattern\"\n\t\t\t\t}\n\t\t\t]\n\t\t}]\n\t},\n\t\"newrelic\": {\n\t\t\"enabled\": false,\n\t\t\"account_id\": \"ACCOUNT_ID\",\n\t\t\"api_key\": \"API_KEY\",\n\t\t\"event_type\": \"GWStats\"\n\t},\n\t\"influxdb\": {\n\t\t\"enabled\": false,\n\t\t\"host\": \"http://1.2.3.4:8086/write?db=imperva_performance_stats\"\n\t},\n\t\"syslog\": {\n\t\t\"enabled\": false,\n\t\t\"endpoints\":[\n\t\t\t{\n\t\t\t\t\"host\": \"1.2.3.4\",\n\t\t\t\t\"protocol\": \"TCP\",\n\t\t\t\t\"port\": 514,\n\t\t\t\t\"facility\":21\n\t\t\t},\n\t\t\t{\n\t\t\t\t\"host\": \"1.2.3.5\",\n\t\t\t\t\"protocol\": \"UDP\",\n\t\t\t\t\"port\": 515,\n\t\t\t\t\"facility\":21\n\t\t\t}\t\t]\n\t},\n\t\"sonar\": {\n\t\t\"enabled\": false,\n\t\t\"endpoints\":[\n\t\t\t{\n\t\t\t\t\"host\": \"your.sonar.hostname\",\n\t\t\t\t\"port\": 10667,\n\t\t\t\t\"facility\":21\n\t\t\t}\n\t\t]\n\t}\n}")
    exit()
if CONFIG["is_userspace"]:
    BASEDIR = "/opt/SecureSphere/etc/proc/hades/"
else:
    BASEDIR = '/proc/hades/'
    # urllib3.disable_warnings()

############ ENV Settings ############
logging.basicConfig(filename=CONFIG["log_file_name"], filemode='w', format='%(name)s - %(levelname)s - %(message)s', level=getattr(logging, CONFIG["log_level"].upper()))

# Gateway level statistic
GWStats = {
    # start a few enrichment fields to give context
    "event_type": "gw",
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
    "event_type": "sg",
    "gw": GATEWAYNAME,
    "server_group": True,
    "server_group_id": True,
    "timestamp": TIMESTAMP,
    # start list of all lines from status file
    "system":{},
    "hades_counters":{
        "kbps": True,
        "http_hits_sec": True,
        "connection_sec": True,
        "wfd_successful_hits_sec": True,
        "sql_hits_sec": True,
        "sql_audit_phase2_events_sec": True,
        "hdfs_hits_sec": True
        # "zosfile_hits_sec": True,
        # "activedirectory_hits_sec": True,
        # "file_aggregated_hits_sec": True,
        # "file_hits_sec": True,
        # "sharepoint_aggregated_hits_sec": True,
        # "sharepoint_hits_sec": True,
    }
}

GWSonarStats = {
    "gw": GATEWAYNAME,
    "event_type": "gw",
    "timestamp": TIMESTAMP,
    "cpu":{
        "top":{},
        "sar":{},
        "last_sec_load":{},
        "last_min_load": {}
    },
    "cores":{},
    "disk":{},
    "hades_counters":{},
    "memory":{},
    "network":{},
    "system":{},
    "log_search":{}
}

# convention is: {"measurement_name": {"tagname=tagvalue":["array=0","of=1","metrics=1"]}, ...  }
# imperva_gw_hades example: {"notag":["kbps=0","kbps_max=0","kbps_application=0","kbps_application_max=0"...]}
# imperva_gw_workers example: {"worker=0":["worker_kbps=0","worker_kbps_max=0","worker_packets_sec=0"...]}
# imperva_gw_net example: {"interface=eth0":["speed=10000","rx_packets=3766875","rx_errors=0","rx_dropped=0"...]}
# imperva_gw_disk example: {"volume=/var":["disk_capacity=41284928","disk_used=6989272","disk_available=32198504"...]}
# imperva_gw_sys example: {"model=V2500":["uptime=2796","gw_supported_kbps=2000","gw_supported_hps=9000","mem_total=3926948"...]}
# imperva_sg example: {"servergroupname=Mongo DB":["kbps=10","kbps_max=100","connections_sec=10","connectiions_sec_max=100"...]}

influxDbStats = {
    "imperva_gw_hades":{
        "file={0}".format(os.path.join(BASEDIR, 'status')): [],
        "file={0}".format(os.path.join(BASEDIR, 'counters')): []
    },
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

def run():
    # pull <BASEDIR>/status file to parse gateway level stats
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
    parseGWMeminfoStats()

    counters_file = os.path.join(BASEDIR, 'counters')
    pipe = Popen(['cat', counters_file], stdout=PIPE)
    output = pipe.communicate()
    m = re.findall('(total number of requests.*)',output[0].lower())
    for counterStat in m:
        counterStatAry = counterStat.lower().split("(gw)")
        statKey = counterStatAry[0].strip().replace(" ","_")
        counterStatValAry = counterStatAry[1].strip().replace(":","").replace("(","").replace(")","").split()
        statVal = counterStatValAry[0]
        statTotal = counterStatValAry[1].split("=").pop()
        GWStats["imperva_gw_"+statKey] = int(statVal)
        GWStats["imperva_gw_"+statKey+"_total"] = int(statTotal)
        influxDbStats["imperva_gw_hades"]["file={0}".format(counters_file)].append(statKey+"="+str(statVal))
        influxDbStats["imperva_gw_hades"]["file={0}".format(counters_file)].append(statKey+"_total="+str(statTotal))
        GWSonarStats["hades_counters"][statKey] = statVal
        GWSonarStats["hades_counters"][statKey+"_total"] = statTotal
        
    getDiskStats()
    getSysStats()
    getNetworkStats()

    if CONFIG["log_search"]["enabled"]:
        for fileconfig in CONFIG["log_search"]["files"]:
            for patternconfig in fileconfig["search_patterns"]:
                matches = searchLogFile(fileconfig["path"], patternconfig["pattern"])
                match = "\n".join(matches).replace('"',"'")
                if match!="":
                    GWStats[patternconfig["name"]] = match
                    GWSonarStats["log_search"][patternconfig["name"]] = match

    if CONFIG["newrelic"]["enabled"]:
        logging.debug("processing newrelic request: "+json.dumps(GWStats))
        makeCallNewRelicCall(GWStats)
    # if CONFIG["servicenow"]["enabled"]:
    #     print("make servicenow call")
    #     # todo finish integration with ServiceNow
    if CONFIG["syslog"]["enabled"]:
        logging.debug("processing syslog request: "+json.dumps(GWStats))
        sendSyslog(GWStats)
    if CONFIG["sonar"]["enabled"]:
        logging.debug("processing sonar request: "+json.dumps(GWSonarStats))
        sendSonar(GWSonarStats)    

    sg_dirs = os.listdir(BASEDIR)
    for dir in sg_dirs:
        if dir[:3]=='sg_':
            SGStats = SGStatsTmpl.copy()
            f = open(os.path.join(BASEDIR+dir,'status'), 'r')
            sg_status_stats = f.read().split("\n")
            servergroupname = sg_status_stats[0][:sg_status_stats[0].rfind('_')].lower().replace(" ","_")
            influxDbStats["imperva_sg"]["servergroupname="+servergroupname+",mx_host="+MXHOST] = []
            SGStats["mx"] = MXHOST
            SGStats["server_group"] = servergroupname
            SGStats["server_group_id"] = sg_status_stats[0][sg_status_stats[0].rfind('_')+1:len(sg_status_stats[0])-1]
            for sg_stat in sg_status_stats[1:]:
                SGStats = parseSGStat(servergroupname, sg_stat, SGStats)

            if CONFIG["newrelic"]["enabled"]:
                logging.debug("processing newrelic server group request: "+json.dumps(SGStats))
                makeCallNewRelicCall(SGStats)
            # if CONFIG["servicenow"]["enabled"]:
            #     print("make servicenow call")
            #     # todo finish integration with ServiceNow
            if CONFIG["syslog"]["enabled"]:
                logging.debug("processing syslog server group request: "+json.dumps(SGStats))
                sendSyslog(SGStats)
            if CONFIG["sonar"]["enabled"]:
                logging.debug("processing sonar server group request: "+json.dumps(SGStats))
                sendSonar(SGStats)
    if CONFIG["influxdb"]["enabled"]:
        logging.debug("processing influxdb requests: "+json.dumps(influxDbStats))
        for measurement in influxDbStats:
            curStat = influxDbStats[measurement]
            for tags in curStat:
                makeInfluxDBCall(measurement, influxDefaultTags+tags, ','.join(curStat[tags]))

#########################################################
############### General Porpuse Functions ###############
#########################################################
def strim(str):
    return re.sub('\s\s+', ' ', str).strip()

def tuplize(values, expected_length, default_value=0):
    """
    Verifies the amount of elements in the 'values' list matches the specified expected length and
    returns them as a tuple. In case of a mismatch, the function returns a correctly sized tuple
    populated with the specified default value
    """
    return tuple(values) if len(values) == expected_length else (default_value, ) * expected_length

def to_influxdb_stats(stats_dict):
    """
    Converts a dictionary into an InfluxDB-compatible list of stringified stats. Example:
    {'a': 1, 'b': 2, 'c': 3} --> ['a=1', 'b=2', 'c=3']
    """
    return ['{0}={1}'.format(k, v) for k, v in stats_dict.items()]

def getNetworkStats():
    def getSocketConnectFailureStats():
        input, output, error = os.popen3("grep \"\\[\\!] socket connect\" %s | awk 'BEGIN {ORS = \" \"} {print $(NF-1)}'" % os.path.join(BASEDIR, 'counters'))
        failed, bad_state, unknown = tuplize(output.read().split(), expected_length=3)
        return {'socket_connect_failed': failed, 'socket_connect_bad_state': bad_state, 'socket_connect_unknown_server': unknown}

    def getMaxSocketQueuesStats():
        input, output, error = os.popen3("/usr/sbin/ss -t state established | awk '(NR==2){max_recv=$1; max_send=$2}; (NR>2){max_recv = ($1 > max_recv ? $1 : max_recv); max_send = ($2 > max_send ? $2 : max_send)} END {print max_recv, max_send}'")
        recv, send = tuplize(output.read().split(), expected_length=2)
        return {'max_recv_queue': recv, 'max_send_queue': send}

    # General socket stats - not directly associated with a particular interface
    influx_all_if_stats = influxDbStats["imperva_gw_net"]["interface=all"] = []
    influx_all_if_stats.extend(to_influxdb_stats(getMaxSocketQueuesStats()))
    influx_all_if_stats.extend(to_influxdb_stats(getSocketConnectFailureStats()))

    basedir = "/sys/class/net/"
    input, ifaceoutput, error = os.popen3("ls "+basedir)
    for ifacename in ifaceoutput.read().split("\n"):
        if(ifacename.strip()!=""):
            if(ifacename[:3]=="eth"):
                pipe = Popen(['/sbin/ifconfig',ifacename], stdout=PIPE)
                ifconfigoutput = pipe.communicate()
                ipaddress = "n/a"
                for iface in ifconfigoutput[0].strip().split("\n"):
                    iface = ' '.join(iface.replace(":"," ").split())
                    if (iface[:5].lower()=="inet "):
                        ipaddress = iface[5:].replace("addr:","").split(" ").pop(0)
                        break
                influxDbStats["imperva_gw_net"]["interface="+ifacename+",ipaddress="+ipaddress+",uptime="+UPTIME] = []
                influxIfaceStatAry = influxDbStats["imperva_gw_net"]["interface="+ifacename+",ipaddress="+ipaddress+",uptime="+UPTIME]
                GWSonarStats["network"][ifacename] = {}
                input, statoutput, error = os.popen3("ls "+basedir+ifacename+"/statistics/")
                for stat in statoutput.read().split("\n"):
                    if stat.strip() !="":
                        input, output, error = os.popen3("cat "+basedir+ifacename+'/statistics/'+stat)
                        val = output.read().strip()
                        influxIfaceStatAry.append(stat+"="+val)
                        GWStats["interface_"+ifacename+"_"+stat] = int(val)
                        GWSonarStats["network"][ifacename][stat] = int(val)

def getDiskStats():
    pipe = Popen(['cat','/proc/mounts'], stdout=PIPE)
    output = pipe.communicate()
    mountsAry = str(output[0]).split("\n")
    for mount in mountsAry:
        if mount.strip()!="":
            mountAry = mount.replace(","," ").split(" ")
            if mountAry[1][:1]=="/":
                pipe = Popen(['df',mountAry[1]], stdout=PIPE)
                output = pipe.communicate()
                mountStats = str(output[0]).split("\n")
                mountStats.pop(0)
                mountStatsAry = ' '.join(mountStats).replace("\n"," ").split()
                influxDbStats["imperva_gw_disk"]["volume="+mountAry[1]] = []
                influxIfaceStatAry = influxDbStats["imperva_gw_disk"]["volume="+mountAry[1]]
                influxIfaceStatAry.append("disk_capacity="+mountStatsAry[1])
                influxIfaceStatAry.append("disk_used="+mountStatsAry[2])
                influxIfaceStatAry.append("disk_available="+mountStatsAry[3])
                GWStats["disk_volume"+mountAry[1]+"_disk_capacity"] = int(mountStatsAry[1])
                GWStats["disk_volume"+mountAry[1]+"_disk_used"] = int(mountStatsAry[2])
                GWStats["disk_volume"+mountAry[1]+"_disk_available"] = int(mountStatsAry[3])
                GWSonarStats["disk"][mountAry[1]] = {}
                GWSonarStats["disk"][mountAry[1]]["disk_capacity"] = int(mountStatsAry[1])
                GWSonarStats["disk"][mountAry[1]]["disk_used"] = int(mountStatsAry[2])
                GWSonarStats["disk"][mountAry[1]]["disk_available"] = int(mountStatsAry[3])

def getSysStats():
    with open('/opt/SecureSphere/etc/bootstrap.xml', 'r') as content_file:
        content = content_file.read()
        global MXHOST
        if "gateway_mx_host_display_name" in CONFIG:
            MXHOST = CONFIG["gateway_mx_host_display_name"]
        else:
            m = re.search(r'server.*\shost=\"(.*)\"\sreal-host',content)
            MXHOST = m.group(1)

        GWStats["mx_host"] = MXHOST
        influxDbStats["imperva_gw_sys"]["mx_hostname="+MXHOST] = []
        GWSonarStats["mx"] = MXHOST
        sysStat = influxDbStats["imperva_gw_sys"]["mx_hostname="+MXHOST]
        
        m = re.search(r'(appliance)\s(tag=).*',content)
        modelStr = m.group(0)
        model = modelStr[modelStr.index('appliance tag=')+15:modelStr.index('" name=')]
        global GWMODEL
        GWMODEL = model
        influxDbStats["imperva_gw_sys"]["model="+model] = []        
        sysStat = influxDbStats["imperva_gw_sys"]["model="+model]
        GWSonarStats["system"]["model"] = GWMODEL
        
        pipe = Popen(['/opt/SecureSphere/etc/impctl/bin/platform/show'], stdout=PIPE)
        output = pipe.communicate()
        for stat in output[0].split("\n"):
            if stat.strip()!="":
                statAry = stat.split(" ")
                key = statAry.pop(0)
                val = statAry.pop()
                influxDbStats["imperva_gw_sys"][key+"="+val] = []
                sysStat = influxDbStats["imperva_gw_sys"][key+"="+val]
                GWSonarStats["system"][key] = val
        
        sysStat.append("gw_supported_kbps="+gwSizingStats[model]["gw_supported_kbps"])
        sysStat.append("gw_supported_hps="+gwSizingStats[model]["gw_supported_hps"])
        GWStats["gw_supported_kbps"] = int(gwSizingStats[model]["gw_supported_kbps"])
        GWStats["gw_supported_hps"] = int(gwSizingStats[model]["gw_supported_hps"])
        GWSonarStats["system"]["supported_kbps"] = int(gwSizingStats[model]["gw_supported_kbps"])
        GWSonarStats["system"]["supported_hps"] = int(gwSizingStats[model]["gw_supported_hps"])        
        
        global UPTIME
        input, output, error = os.popen3("cat /proc/uptime")
        UPTIME = output.read().strip().split(" ").pop(0).split(".").pop(0)
        sysStat.append("uptime="+UPTIME)
        GWStats["uptime"] = UPTIME
        GWSonarStats["system"]["uptime"] = UPTIME

        # Get latest successful configuration revision message
        input, output, error = os.popen3("cat /opt/SecureSphere/etc/logs/GatewayLog/GatewayLog.html | awk '/applied successfully/ {line=$0} END{print line}' | grep -E -o '[0-9]+'")
        revision_update_data = output.read().split()
        current_revision_index = -2
        sysStat.append("current_revision=" + revision_update_data[current_revision_index])

        pipe = Popen(['top','-bn','2'], stdout=PIPE)
        output = pipe.communicate()
        topOutputAry = str(output[0]).split("top - ").pop().split("\n")
        for stat in topOutputAry:
            stat = stat.lower().replace("%"," ").replace("kib ","").replace("k","")
            statType = stat.split(":").pop(0).lower().strip()
            statsAry = ' '.join(stat.split(":").pop().lower().strip().split()).split(",")
            if statType[:3]=="mem" or statType[:4]=="swap":
                for curStat in statsAry:
                    statAry = curStat.strip().split()
                    statMeasurement = statAry[1][:5].replace(".","").strip()
                    if statMeasurement=="total" or statMeasurement=="used" or statMeasurement=="free":
                        sysStat.append(statType+"_"+statMeasurement+"="+statAry[0])
                        GWStats["top_"+statType+"_"+statMeasurement] = float(statAry[0])
                        GWSonarStats["memory"]["top_"+statType+"_"+statMeasurement] = float(statAry[0])
            elif statType[:3]=="cpu":
                cpu = statType.replace("cpu","")
                GWSonarStats["cpu"]["top"][cpu] = {}
                influxDbStats["imperva_gw_top_cpu"]["cpu="+cpu] = []
                GWCpuStatAry = influxDbStats["imperva_gw_top_cpu"]["cpu="+cpu]
                for cpuStat in statsAry:
                    statAry = cpuStat.strip().split()
                    GWCpuStatAry.append(topCpuAttrMap[statAry[1]]+"="+statAry[0])
                    GWStats["top_"+statType.lower()+"_"+topCpuAttrMap[statAry[1]]] = float(statAry[0])                    
                    GWSonarStats["cpu"]["top"][cpu][topCpuAttrMap[statAry[1]]] = float(statAry[0])
            elif "load average" in stat:
                last_min_average = stat.split("load average: ").pop(1).split(",").pop(0).strip()
                lastSecAry = influxDbStats["imperva_gw_top_cpu"]["cpu=all"] = []                
                lastSecAry.append("last_min_load_average="+str(last_min_average))
                GWStats["cpuload_last_min_load_average"] = float(last_min_average)
                GWSonarStats["cpu"]["last_min_load"]["average"] = float(last_min_average)

        try:
            # @TODO implement sonar stat for sar
            pipe = Popen(['/usr/bin/sar','-P','ALL','1','1'], stdout=PIPE)
            output = pipe.communicate()
            sarOutputAry = str(output[0]).strip().split("Average:").pop(0).split("\n")
            sarOutputAry.pop(0)
            sarOutputAry.pop(0)
            sarStatIndexes = sarOutputAry.pop(0)
            sarStatIndexAry = ' '.join(sarStatIndexes.replace(" AM","").replace(" PM","").split()).replace("%","").split(" ")
            for i, stat in enumerate(sarOutputAry, start=1):
                statAry = ' '.join(stat.replace(" AM","").replace(" PM","").split()).split(' ')
                if len(statAry) > 1:
                    if statAry[1][:3].upper()!="CPU":
                        influxDbStats["imperva_gw_sar_cpu"]["cpu="+statAry[1].lower()] = []
                        GWCpuStatAry = influxDbStats["imperva_gw_sar_cpu"]["cpu="+statAry[1].lower()]
                        for j in range(len(statAry)):
                            curIndexName = sarStatIndexAry[j]
                            if j>1:
                                cpuStat = statAry[j]
                                GWCpuStatAry.append(curIndexName+"="+cpuStat)
                                GWStats["sar_cpu"+statAry[2].lower()+"_"+curIndexName] = float("{0:.2f}".format(float(cpuStat)))
        except:
            logging.error("Missing package: sar command not found")

        pipe = Popen(['cat',BASEDIR+'cpuload'], stdout=PIPE)
        output = pipe.communicate()
        cpuloadOutputAry = str(output[0]).strip().split("\n\n")

        for stat in cpuloadOutputAry[1].split("\n"):
            if stat[:4]!="last":
                statAry = ' '.join(stat.split()).split(":")
                GWStats["cpuload_last_sec_"+statAry[0].replace(" ","_")] = int(statAry[1].strip())
                GWSonarStats["cpu"]["last_sec_load"][statAry[0].replace(" ","_").replace("_load","")] = int(statAry[1].strip())
                if stat[:7!="average"]:
                    cpuNum = statAry[0].replace("cpu","").split().pop(0)
                    influxDbStats["imperva_gw_cpuload"]["cpu="+cpuNum] = []
                    lastSecAry = influxDbStats["imperva_gw_cpuload"]["cpu="+cpuNum]
                    lastSecAry.append("load="+str(int(statAry[1].strip())))
                # if stat[:7]=="average":
                #     influxDbStats["imperva_gw_cpuload"]["cpu=all"] = []
                #     lastSecAry = influxDbStats["imperva_gw_cpuload"]["cpu=all"]
                #     lastSecAry.append("load="+str(int(statAry[1].strip())))
                # else:
                #     cpuNum = statAry[0].replace("cpu","").split().pop(0)
                #     influxDbStats["imperva_gw_cpuload"]["cpu="+cpuNum] = []
                #     lastSecAry = influxDbStats["imperva_gw_cpuload"]["cpu="+cpuNum]
                #     lastSecAry.append("load="+str(int(statAry[1].strip())))

# Parse stats and maximums
# example: 0 connection/sec (max 4 2019-03-20 05:39:56)
# [stat],[statKey],(max,[max],[max_date],[max_time])
def parseGWEventStat(stat):
    status_file = os.path.join(BASEDIR, 'status')
    if strim(stat) != '':
        statstr = strim(stat).lower()
        statKey = statstr[statstr.index(' ')+1:statstr.index('(')-1].replace('/','_').replace(' ','_')
        statstr = statstr.replace(statstr[statstr.index(' ')+1:statstr.index('(')-1],statstr[statstr.index(' ')+1:statstr.index('(')-1].replace('/','_').replace(' ','_'))
        if statKey in GWStats:
            statAry = statstr.split(" ")
            GWStats[statKey] = int(statAry[0])
            GWStats[statKey+"_max"] = int(statAry[3])
            influxDbStats["imperva_gw_hades"]["file={0}".format(status_file)].append(statKey+"="+str(int(statAry[0])))
            influxDbStats["imperva_gw_hades"]["file={0}".format(status_file)].append(statKey+"_max="+str(int(statAry[3])))
            GWSonarStats["hades_counters"][statKey] = int(statAry[0])
            GWSonarStats["hades_counters"][statKey+"_max"] = int(statAry[3])

# Parse gateway level <BASEDIR>/status - CPU section
def parseGWCPUStat(stat):
    if strim(stat) != '':
        statstr = strim(stat).lower()
        CoreNum = strim(statstr.split("|")[0])
        if (CoreNum.isdigit()):
            CoreStatsAry = statstr.split("|")[1:]
            influxDbStats["imperva_gw_workers"]["worker="+CoreNum] = []
            #example:  CPU# | kbps 28 (max 237244 2019-03-13 08:20:00) | packets/sec | queue length
            CoreStatKey = ["kbps","packets_sec","queue_length"]
            GWSonarStats["cores"][str(CoreNum)] = {}
            for index, CoreStat in enumerate(CoreStatsAry, start=0):
                CoreStatAry = CoreStat.strip().split(' ')
                GWStats["core_"+CoreNum+"_"+CoreStatKey[index]] = int(CoreStatAry[0])
                GWStats["core_"+CoreNum+"_"+CoreStatKey[index]+"_max"] = int(CoreStatAry[2])
                influxDbStats["imperva_gw_workers"]["worker="+CoreNum].append("worker_"+CoreStatKey[index]+"="+CoreStatAry[0])
                influxDbStats["imperva_gw_workers"]["worker="+CoreNum].append("worker_"+CoreStatKey[index]+"_max="+CoreStatAry[2])
                GWSonarStats["cores"][str(CoreNum)][CoreStatKey[index]] = CoreStatAry[0]
                GWSonarStats["cores"][str(CoreNum)][CoreStatKey[index]+"_max"] = CoreStatAry[2]                

def parseGWMeminfoStats():
    GWSonarStats["memory"]["workers_meminfo"] = {}
    pipe = Popen(['cat',BASEDIR+"meminfo"], stdout=PIPE)
    output = pipe.communicate()
    meminfoOutputAry = str(output[0]).split("top - ").pop().split("\n")
    for stat in meminfoOutputAry:
        if ("vrange" in stat.lower() and "worker" in stat.lower()):
            statAry = stat.split(" ").pop(0).split("/")
            CoreNum = stat[-1]
            influxDbStats["imperva_gw_meminfo"]["core="+CoreNum] = []
            GWStats["meminfo_core_"+CoreNum+"_current"] = int(statAry[0])
            GWStats["meminfo_core_"+CoreNum+"_max"] = int(statAry[1])
            GWStats["meminfo_core_"+CoreNum+"_available"] = int(statAry[2])
            influxDbStats["imperva_gw_meminfo"]["core="+CoreNum].append("current="+statAry[0])
            influxDbStats["imperva_gw_meminfo"]["core="+CoreNum].append("max="+statAry[1])
            influxDbStats["imperva_gw_meminfo"]["core="+CoreNum].append("available="+statAry[2])
            GWSonarStats["memory"]["workers_meminfo"][str(CoreNum)] = {}
            GWSonarStats["memory"]["workers_meminfo"][str(CoreNum)]["current"] = statAry[0]
            GWSonarStats["memory"]["workers_meminfo"][str(CoreNum)]["max"] = statAry[1]
            GWSonarStats["memory"]["workers_meminfo"][str(CoreNum)]["available"] = statAry[2]

# Parse server group level <BASEDIR>/sg_[server group name]/status - stats and maximums
def parseSGStat(servergroupname,sg_stat,SGStats):
    sg_statstr = strim(sg_stat).lower()
    if sg_statstr != '':
        if sg_statstr.find("(") != -1:
            sg_statKey = sg_statstr[sg_statstr.index(' ')+1:sg_statstr.index('(')-1].replace('/','_').replace(' ','_')
            sg_statstr = sg_statstr.replace(sg_statstr[sg_statstr.index(' ')+1:sg_statstr.index('(')-1],sg_statstr[sg_statstr.index(' ')+1:sg_statstr.index('(')-1].replace('/','_').replace(' ','_'))
            if sg_statKey in SGStats["hades_counters"]:
                sg_statAry = sg_statstr.split(" ")
                SGStats["hades_counters"][sg_statKey] = sg_statAry[0]
                SGStats["hades_counters"][sg_statKey+"_max"] = sg_statAry[3]
                influxDbStats["imperva_sg"]["servergroupname="+servergroupname+",mx_host="+MXHOST].append(sg_statKey+"="+sg_statAry[0])
                influxDbStats["imperva_sg"]["servergroupname="+servergroupname+",mx_host="+MXHOST].append(sg_statKey+"_max="+sg_statAry[3])
        else:
            sg_statstr = sg_statstr.replace(sg_statstr[sg_statstr.index(' ')+1:len(sg_statstr)-sg_statstr.index(' ')+1],sg_statstr[sg_statstr.index(' ')+1:len(sg_statstr)-sg_statstr.index(' ')+1].replace('/','_').replace(' ','_'))
            sg_statAry = sg_statstr.split(" ")
            if sg_statAry[1] in SGStats["hades_counters"]:
                SGStats["hades_counters"][sg_statAry[1]] = sg_statAry[0]
                influxDbStats["imperva_sg"]["servergroupname="+servergroupname+",mx_host="+MXHOST].append(sg_statAry[1]+"="+sg_statAry[0])
    return SGStats

def makeCallNewRelicCall(stat):
    if (logHostAvailable["newrelic"]==True):
        stat["eventType"] = CONFIG["newrelic"]["event_type"]
        new_relic_url = "https://insights-collector.newrelic.com/v1/accounts/"+CONFIG["newrelic"]["account_id"]+"/events"
        headers = CONFIG["newrelic"].get("headers", {
            "Content-Type": "application/json",
            "X-Insert-Key": CONFIG["newrelic"]["api_key"]
        })
        if "X-Insert-Key" not in headers: 
            headers["X-Insert-Key"] = CONFIG["newrelic"]["api_key"]
        logging.info("NEW RELIC REQUEST (" + new_relic_url + ")" + json.dumps(stat))
        if "proxies" in CONFIG:
            try: 
                proxies = {"https": "https://" + CONFIG["proxies"]["proxy_username"] + ":" + CONFIG["proxies"]["proxy_password"] + "@" + CONFIG["proxies"]["proxy_host"] + ":" + CONFIG["proxies"]["proxy_port"]}
                requests.post(new_relic_url, json.dumps(stat), proxies=proxies, headers=headers, verify=False, timeout=(CONNECTIONTIMEOUT,15))
            except requests.exceptions.RequestException as e:
                logging.error("requests timeout error: {0}".format(e))
                logging.error("newrelic host unreachable, aborting subsequent calls to newrelic")
                logHostAvailable["newrelic"] = False
        else:
            try:
                requests.post(new_relic_url, json.dumps(stat), headers=headers, verify=False, timeout=(3,15))
            except requests.exceptions.RequestException as e:
                logging.error("requests timeout error: {0}".format(e))
                logging.error("newrelic host unreachable, aborting subsequent calls to newrelic")
                logHostAvailable["newrelic"] = False

def makeInfluxDBCall(measurement, tags, params):
    if (logHostAvailable["influxdb"]==True):
        influxdb_url = CONFIG["influxdb"]["host"]
        headers = CONFIG["influxdb"].get("headers", {
            "Content-Type": "text/plain; charset=utf-8" if "/v2/" in influxdb_url else "application/octet-stream",
        })
        data = measurement+","+tags+" "+params
        logging.info("INFLUXDB REQUEST: "+influxdb_url+"?"+data)
        if "proxies" in CONFIG:
            proxies = {"https": "https://" + CONFIG["proxies"]["proxy_username"] + ":" + CONFIG["proxies"]["proxy_password"] + "@" + CONFIG["proxies"]["proxy_host"] + ":" + CONFIG["proxies"]["proxy_port"]}
            try: 
                response = requests.post(influxdb_url, data=data, proxies=proxies, headers=headers, verify=False, timeout=(CONNECTIONTIMEOUT,15))
                if (response.status_code!=204):
                    logging.error("Influxdb error - status_code ("+str(response.status_code)+") response: " + json.dumps(response.json()))
            except requests.exceptions.RequestException as e:
                logging.error("requests timeout error: {0}".format(e))
                logging.error("influxdb host unreachable, aborting subsequent calls to influxdb")
                logHostAvailable["influxdb"] = False
        
        else:
            if "username" in CONFIG["influxdb"]:
                try: 
                    response = requests.post(influxdb_url,auth=HTTPBasicAuth(CONFIG["influxdb"]["username"], CONFIG["influxdb"]["password"]), data=data, headers=headers, verify=False, timeout=(CONNECTIONTIMEOUT,15))
                    if (response.status_code!=204):
                        logging.error("Influxdb error - status_code ("+str(response.status_code)+") response: " + json.dumps(response.json()))
                except requests.exceptions.RequestException as e:
                    logging.error("[ERROR] requests timeout error: {0}".format(e))
                    logging.error("influxdb host unreachable, aborting subsequent calls to influxdb")
                    logHostAvailable["influxdb"] = False
            else:
                try: 
                    response = requests.post(influxdb_url, data=data, headers=headers, verify=False, timeout=(CONNECTIONTIMEOUT,15))
                    if (response.status_code!=204):
                        logging.warning("[ERROR] Influxdb error - status_code ("+str(response.status_code)+") response: " + json.dumps(response.json()))
                except requests.exceptions.RequestException as e:
                    logging.error("[ERROR] requests timeout error: {0}".format(e))
                    logging.error("influxdb host unreachable, aborting subsequent calls to influxdb")
                    logHostAvailable["influxdb"] = False

def sendSyslog(jsonObj):
    if (logHostAvailable["syslog"]==True):
        for syslogEndpoint in CONFIG["syslog"]["endpoints"]:
            logging.info("SYSLOG REQUEST: "+json.dumps(jsonObj))
            try:
                logger = logging.getLogger('Logger')
                logger.setLevel(logging.INFO)
                handler = logging.handlers.SysLogHandler(address = (syslogEndpoint["host"], syslogEndpoint["port"]),facility=syslogEndpoint["facility"],socktype=(socket.SOCK_STREAM if syslogEndpoint["protocol"]=="TCP" else socket.SOCK_DGRAM))
                logger.addHandler(handler)
                logger.info(jsonObj)
            except Exception as e:
                logging.error("syslog failed")
                logging.error(e)

def sendSonar(jsonObj):
    if (logHostAvailable["sonar"]==True):
        for sonarEndpoint in CONFIG["sonar"]["endpoints"]:
            try:
                logger = logging.getLogger('Logger')
                logger.setLevel(logging.INFO)
                handler = logging.handlers.SysLogHandler(address = (sonarEndpoint["host"], sonarEndpoint["port"]),facility=sonarEndpoint["facility"],socktype=socket.SOCK_STREAM)
                logger.addHandler(handler)
                logger.info(json.dumps(jsonObj)+"\n")
            except Exception as e:
                logging.error("syslog failed")
                logging.error(e)

def searchLogFile(filename, pattern):
    matches = []
    with open(filename, 'r') as file_:
        line_list = list(file_)
        line_list.reverse()
        for line in line_list:
            if ''.join(i for i in line if ord(i)<128).find(pattern) != -1:
                matches.append(line)
    return(matches)

topCpuAttrMap = {
    "us":"user",
    "sy":"system",
    "ni":"nice",
    "id":"idle",
    "wa":"wait",
    "hi":"hardware",
    "si":"software",
    "st":"steal_time"
}

gwSizingStats = {
    # Physical Appliances
    "X2500":{"gw_supported_kbps":"500000","gw_supported_hps":"5000"},
    "X4500":{"gw_supported_kbps":"1000000","gw_supported_hps":"9000"},
    "X6500":{"gw_supported_kbps":"2000000","gw_supported_hps":"18000"},
    "X8500":{"gw_supported_kbps":"5000000","gw_supported_hps":"36000"},
    # Physical Appliances 10 series
    "X10K":{"gw_supported_kbps":"10000000","gw_supported_hps":"72000"},
    "X2510":{"gw_supported_kbps":"500000","gw_supported_hps":"5000"},
    "X4510":{"gw_supported_kbps":"1000000","gw_supported_hps":"9000"},
    "X6510":{"gw_supported_kbps":"2000000","gw_supported_hps":"18000"},
    "X8510":{"gw_supported_kbps":"5000000","gw_supported_hps":"36000"},
    # Physical Appliances 20 series
    "X10K2":{"gw_supported_kbps":"10000000","gw_supported_hps":"72000"},
    "X2520":{"gw_supported_kbps":"500000","gw_supported_hps":"5000"},
    "X4520":{"gw_supported_kbps":"1000000","gw_supported_hps":"9000"},
    "X6520":{"gw_supported_kbps":"2000000","gw_supported_hps":"18000"},
    "X8520":{"gw_supported_kbps":"5000000","gw_supported_hps":"36000"},
    # Virtual Appliances
    "V1000":{"gw_supported_kbps":"100000","gw_supported_hps":"2500"},
    "V2500":{"gw_supported_kbps":"500000","gw_supported_hps":"5000"},
    "V4500":{"gw_supported_kbps":"1000000","gw_supported_hps":"9000"},
    "V6500":{"gw_supported_kbps":"2000000","gw_supported_hps":"18000"},
    # AWS Appliances
    "AV1000":{"gw_supported_kbps":"100000","gw_supported_hps":"2500"},
    "AV2500":{"gw_supported_kbps":"500000","gw_supported_hps":"5000"},
    "AV4500":{"gw_supported_kbps":"1000000","gw_supported_hps":"9000"},
    "AV6500":{"gw_supported_kbps":"2000000","gw_supported_hps":"18000"},
    # Azure Appliances
    "MV1000":{"gw_supported_kbps":"100000","gw_supported_hps":"2500"},
    "MV2500":{"gw_supported_kbps":"500000","gw_supported_hps":"5000"},
    "MV4500":{"gw_supported_kbps":"1000000","gw_supported_hps":"9000"},
    "MV6500":{"gw_supported_kbps":"2000000","gw_supported_hps":"18000"}
}

if __name__ == '__main__':
    run()