#!/usr/bin/python
import os
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

############### Configs ###############
CONFIGFILE = '/var/user-data/config.json'
GATEWAYNAME = os.uname()[1].split('.')[0]
TIMESTAMP = strftime("%Y/%m/%d %H:%M:%S", localtime())
gwSourceIp = "n/a"
with open('/opt/SecureSphere/etc/bootstrap.xml', 'r') as content_file:
    content = content_file.read()
    m = re.search('(name=).?(management).? .*',content)
    sourceIpStr = m.group(0)
    gwSourceIp = sourceIpStr[sourceIpStr.index('address-v4="')+12:sourceIpStr.index('" address-v6=')-3]
influxDefaultTags = "source="+gwSourceIp+",gatewayname="+GATEWAYNAME+","
GWMODEL = ""
try:
    with open(CONFIGFILE, 'r') as data:
        CONFIG = json.load(data)
except:
    print("Missing \""+CONFIGFILE+"\" file, create file named \""+CONFIGFILE+"\" with the following contents:\n{\n\t\"log_level\": \"debug\",\n\t\"environment\": \"dev\",\n\t\"gw_log_search\": {\n\t\t\"enabled\": true,\n\t\t\"files\": [{\n\t\t\t\"path\": \"/var/log/messages\",\n\t\t\t\"search_patterns\": [{\n\t\t\t\t\t\"name\":\"YOUR_EVENT_NAME\",\n\t\t\t\t\t\"pattern\":\"some text pattern\"\n\t\t\t\t}, {\n\t\t\t\t\t\"name\":\"YOUR_EVENT_NAME_2\",\n\t\t\t\t\t\"pattern\":\"some other text pattern\"\n\t\t\t\t}\n\t\t\t]\n\t\t}]\n\t},\n\t\"newrelic\": {\n\t\t\"enabled\": false,\n\t\t\"account_id\": \"ACCOUNT_ID\",\n\t\t\"api_key\": \"API_KEY\",\n\t\t\"event_type\": \"GWStats\"\n\t},\n\t\"servicenow\": {\n\t\t\"enabled\": false,\n\t\t\"account_id\": \"ACCOUNT_ID\",\n\t\t\"api_key\": \"API_KEY\"\n\t},\n\t\"syslog\": {\n\t\t\"enabled\": true,\n\t\t\"host\": \"1.2.3.4\",\n\t\t\"port\": 514\n\t}\n}")
    exit()
if CONFIG["is_userspace"]:
    BASEDIR = "/opt/SecureSphere/etc/proc/hades/"
else:
    BASEDIR = '/proc/hades/'
    # urllib3.disable_warnings()

############ ENV Settings ############
logging.basicConfig(filename=CONFIG["log_file_name"], filemode='w', format='%(name)s - %(levelname)s - %(message)s')

# Gateway level statistic
GWStats = {
    # start a few enrichment fields to give context
    "event_type": "gateway",
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
    "event_type": "server_group",
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
    "imperva_gw_hades_cpu":{},
    "imperva_gw_top_cpu":{},
    "imperva_gw_sar_cpu":{},
    "imperva_gw_cpuload":{},
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
    getDiskStats()
    getSysStats()
    getNetworkStats()

    if CONFIG["gw_log_search"]["enabled"]:
        for fileconfig in CONFIG["gw_log_search"]["files"]:
            for patternconfig in fileconfig["search_patterns"]:
                matches = searchLogFile(fileconfig["path"], patternconfig["pattern"])
                GWStats[patternconfig["name"]] = "\n".join(matches).replace('"',"'")

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
    if CONFIG["failopen"]["enabled"]:
        pipe = Popen(['top'], stdout=PIPE)
        output = pipe.communicate()

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
        if(ifacename!=""):
            if(ifacename[:3]=="eth"):
                influxDbStats["imperva_gw_net"]["interface="+ifacename] = []
                influxIfaceStatAry = influxDbStats["imperva_gw_net"]["interface="+ifacename]
                pipe = Popen(['/sbin/ifconfig',ifacename], stdout=PIPE)
                ifconfigoutput = pipe.communicate()
                for iface in ifconfigoutput[0].strip().split("\n"):
                    iface = ' '.join(iface.replace(":"," ").split())
                    if GWMODEL[:2].lower()=="av":
                        if (iface[:10].lower()=="rx packets"):
                            rxAry = iface[11:].split(" ")
                            influxIfaceStatAry.append("rx_packets="+rxAry[0])
                            influxIfaceStatAry.append("rx_bytes="+rxAry[2])
                            GWStats["interface_"+ifacename+"_rx_packets"] = int(rxAry[0])
                            GWStats["interface_"+ifacename+"_rx_bytes"] = int(rxAry[2])
                        elif (iface[:9].lower()=="rx errors"):
                            rxAry = iface[10:].split(" ")
                            influxIfaceStatAry.append("rx_errors="+rxAry[0])
                            influxIfaceStatAry.append("rx_dropped="+rxAry[2])
                            influxIfaceStatAry.append("rx_overruns="+rxAry[4])
                            influxIfaceStatAry.append("rx_frame="+rxAry[6])
                            GWStats["interface_"+ifacename+"_rx_errors"] = int(rxAry[0])
                            GWStats["interface_"+ifacename+"_rx_dropped"] = int(rxAry[2])
                            GWStats["interface_"+ifacename+"_rx_overruns"] = int(rxAry[4])
                            GWStats["interface_"+ifacename+"_rx_frame"] = int(rxAry[6])
                        elif (iface[:10].lower()=="tx packets"):
                            txAry = iface[11:].split(" ")
                            influxIfaceStatAry.append("tx_packets="+txAry[0])
                            influxIfaceStatAry.append("tx_bytes="+txAry[2])
                            GWStats["interface_"+ifacename+"_tx_packets"] = int(txAry[0])
                            GWStats["interface_"+ifacename+"_tx_bytes"] = int(txAry[2])
                        elif (iface[:9].lower()=="tx errors"):
                            txAry = iface[10:].split(" ")
                            influxIfaceStatAry.append("tx_errors="+txAry[0])
                            influxIfaceStatAry.append("tx_dropped="+txAry[2])
                            influxIfaceStatAry.append("tx_overruns="+txAry[4])
                            influxIfaceStatAry.append("tx_carrier="+txAry[6])
                            influxIfaceStatAry.append("collisions="+txAry[8])
                            GWStats["interface_"+ifacename+"_tx_errors"] = int(txAry[0])
                            GWStats["interface_"+ifacename+"_tx_dropped"] = int(txAry[2])
                            GWStats["interface_"+ifacename+"_tx_overruns"] = int(txAry[4])
                            GWStats["interface_"+ifacename+"_tx_carrier"] = int(txAry[6])                            
                            GWStats["interface_"+ifacename+"_collisions"] = int(txAry[8])
                        elif (iface[:8].lower()=="rx bytes"):
                            recordAry = iface[9:].split(" ")
                            influxIfaceStatAry.append("rx_bytes="+recordAry[0])
                            influxIfaceStatAry.append("tx_bytes="+recordAry[5])
                            GWStats["interface_"+ifacename+"_rx_bytes"] = int(recordAry[0])
                            GWStats["interface_"+ifacename+"_tx_bytes"] = int(recordAry[5])
                    else:
                        if (iface[:10].lower()=="rx packets"):
                            rxAry = iface[11:].split(" ")
                            influxIfaceStatAry.append("rx_packets="+rxAry[0])
                            influxIfaceStatAry.append("rx_errors="+rxAry[2])
                            influxIfaceStatAry.append("rx_dropped="+rxAry[4])
                            influxIfaceStatAry.append("rx_overruns="+rxAry[6])
                            influxIfaceStatAry.append("rx_frame="+rxAry[8])
                            GWStats["interface_"+ifacename+"_rx_packets"] = int(rxAry[0])
                            GWStats["interface_"+ifacename+"_rx_errors"] = int(rxAry[2])
                            GWStats["interface_"+ifacename+"_rx_dropped"] = int(rxAry[4])
                            GWStats["interface_"+ifacename+"_rx_overruns"] = int(rxAry[6])
                            GWStats["interface_"+ifacename+"_rx_frame"] = int(rxAry[8])
                        elif (iface[:10].lower()=="tx packets"):
                            txAry = iface[11:].split(" ")
                            influxIfaceStatAry.append("tx_packets="+txAry[0])
                            influxIfaceStatAry.append("tx_errors="+txAry[2])
                            influxIfaceStatAry.append("tx_dropped="+txAry[4])
                            influxIfaceStatAry.append("tx_overruns="+txAry[6])
                            influxIfaceStatAry.append("tx_carrier="+txAry[8])
                            GWStats["interface_"+ifacename+"_tx_packets"] = int(txAry[0])
                            GWStats["interface_"+ifacename+"_tx_errors"] = int(txAry[2])
                            GWStats["interface_"+ifacename+"_tx_dropped"] = int(txAry[4])
                            GWStats["interface_"+ifacename+"_tx_overruns"] = int(txAry[6])
                            GWStats["interface_"+ifacename+"_tx_carrier"] = int(txAry[8])
                        elif (iface[:10].lower()=="collisions"):
                            colAry = iface[11:].split(" ")
                            influxIfaceStatAry.append("collisions="+colAry[0])
                            GWStats["interface_"+ifacename+"_collisions"] = int(colAry[0])
                        elif (iface[:8].lower()=="rx bytes"):
                            recordAry = iface[9:].split(" ")
                            influxIfaceStatAry.append("rx_bytes="+recordAry[0])
                            influxIfaceStatAry.append("tx_bytes="+recordAry[5])
                            GWStats["interface_"+ifacename+"_rx_bytes"] = int(recordAry[0])
                            GWStats["interface_"+ifacename+"_tx_bytes"] = int(recordAry[5])

def getDiskStats():
    pipe = Popen(['cat','/proc/mounts'], stdout=PIPE)
    output = pipe.communicate()
    mountsAry = str(output[0]).split("\n")
    for mount in mountsAry:
        if mount.strip()!="":
            mountAry = mount.split(" ")
            if mountAry[1][:1]=="/":
                pipe = Popen(['df',mountAry[1]], stdout=PIPE)
                output = pipe.communicate()
                mountStats = str(output[0]).split("\n")
                mountStats.pop(0)
                mountStatsAry = ' '.join(mountStats).replace("\n"," ").split()
                influxDbStats["imperva_gw_disk"]["volume="+mountStatsAry[5]] = []
                influxIfaceStatAry = influxDbStats["imperva_gw_disk"]["volume="+mountStatsAry[5]]
                influxIfaceStatAry.append("disk_capacity="+mountStatsAry[1])
                influxIfaceStatAry.append("disk_used="+mountStatsAry[2])
                influxIfaceStatAry.append("disk_available="+mountStatsAry[3])
                GWStats["disk_volume"+mountStatsAry[5]+"_disk_capacity"] = int(mountStatsAry[1])
                GWStats["disk_volume"+mountStatsAry[5]+"_disk_used"] = int(mountStatsAry[2])
                GWStats["disk_volume"+mountStatsAry[5]+"_disk_available"] = int(mountStatsAry[3])

def getSysStats():
    with open('/opt/SecureSphere/etc/bootstrap.xml', 'r') as content_file:
        content = content_file.read()
        m = re.search('(appliance)\s(tag=).*',content)
        modelStr = m.group(0)
        model = modelStr[modelStr.index('appliance tag=')+15:modelStr.index('" name=')]
        global GWMODEL
        GWMODEL = model 
        # TODO: Go back and find a way to get version numver, impctl does not work in cron
        influxDbStats["imperva_gw_sys"]["model="+model] = []        
        sysStat = influxDbStats["imperva_gw_sys"]["model="+model]
        sysStat.append("gw_supported_kbps="+gwSizingStats[model]["gw_supported_kbps"])
        sysStat.append("gw_supported_hps="+gwSizingStats[model]["gw_supported_hps"])
        GWStats["gw_supported_kbps"] = int(gwSizingStats[model]["gw_supported_kbps"])
        GWStats["gw_supported_hps"] = int(gwSizingStats[model]["gw_supported_hps"])
        pipe = Popen(['cat','/proc/uptime'], stdout=PIPE)
        output = pipe.communicate()
        uptimeAry = str(output[0]).split("\n")
        uptime = str(uptimeAry[0]).split(" ")
        sysStat.append("uptime="+uptime[0][:-3])
        GWStats["uptime"] = uptime[0][:-3]
        pipe = Popen(['top','-bn','1'], stdout=PIPE)
        output = pipe.communicate()
        topOutputAry = str(output[0]).split("\n")
        for stat in topOutputAry:
            if stat[:4]=="Mem:":
                statAry = ' '.join(stat.split()).split(' ')
                sysStat.append("mem_total="+statAry[1][:-1])
                sysStat.append("mem_used="+statAry[3][:-1])
                sysStat.append("mem_free="+statAry[5][:-1])
                sysStat.append("mem_buffers="+statAry[7][:-1])
                GWStats["mem_total"] = int(statAry[1][:-1])
                GWStats["mem_used"] = int(statAry[3][:-1])
                GWStats["mem_free"] = int(statAry[5][:-1])
                GWStats["mem_buffers"] = int(statAry[7][:-1])
            elif stat[:5]=="Swap:":
                statAry = ' '.join(stat.split()).split(' ')
                sysStat.append("swap_total="+statAry[1][:-1])
                sysStat.append("swap_used="+statAry[3][:-1])
                sysStat.append("swap_free="+statAry[5][:-1])
                sysStat.append("swap_cached="+statAry[7][:-1])
                GWStats["swap_total"] = int(statAry[1][:-1])
                GWStats["swap_used"] = int(statAry[3][:-1])
                GWStats["swap_free"] = int(statAry[5][:-1])
                GWStats["swap_cached"] = int(statAry[7][:-1])
            elif stat[:3].lower()=="cpu":
                cpuStatsAry = ' '.join(stat.replace(":"," ").replace(",",", ").replace(",","").split()).split(" ")
                influxDbStats["imperva_gw_top_cpu"]["cpu="+cpuStatsAry[0].lower()] = []
                GWCpuStatAry = influxDbStats["imperva_gw_top_cpu"]["cpu="+cpuStatsAry[0].lower()]
                for cpuStat in cpuStatsAry[1:]:
                    cpuStatAry = cpuStat.split("%")
                    GWCpuStatAry.append(topCpuAttrMap[cpuStatAry[1]]+"="+cpuStatAry[0])
                    GWStats["top_"+cpuStatsAry[0].lower()+"_"+topCpuAttrMap[cpuStatAry[1]]] = float(cpuStatAry[0])
                # statAry = ' '.join(stat.split()).split(' ')
                # sysStat.append("top_cpu1_="+gwSizingStats[model]["gw_supported_kbps"])

        pipe = Popen(['sar','-P','ALL','0'], stdout=PIPE)
        output = pipe.communicate()
        sarOutputAry = str(output[0]).split("\n")
        sarOutputAry.pop(0)
        sarOutputAry.pop(0)
        # print(sarOutputAry)
        sarStatIndexes = sarOutputAry.pop(0)
        sarStatIndexAry = ' '.join(sarStatIndexes.split()).replace("%","").split(" ")
        for i, stat in enumerate(sarOutputAry, start=1):
            statAry = ' '.join(stat.split()).split(' ')
            if len(statAry) > 1:
                if statAry[2][:3].upper()!="CPU":
                    influxDbStats["imperva_gw_sar_cpu"]["cpu="+statAry[2].lower()] = []
                    GWCpuStatAry = influxDbStats["imperva_gw_sar_cpu"]["cpu="+statAry[2].lower()]
                    offset = 3 # remove first few from list
                    for j in range(len(statAry)-offset):
                        cpuStat = statAry[j+offset]
                        GWCpuStatAry.append(sarStatIndexAry[j+offset]+"="+cpuStat)
                        GWStats["sar_cpu"+statAry[2].lower()+"_"+sarStatIndexAry[j+offset]] = round(float(cpuStat),2)

        pipe = Popen(['cat','/proc/hades/cpuload'], stdout=PIPE)
        output = pipe.communicate()
        cpuloadOutputAry = str(output[0]).strip().split("\n\n")

        influxDbStats["imperva_gw_cpuload"]["last_30_sec"] = []
        last30SecAry = influxDbStats["imperva_gw_cpuload"]["last_30_sec"]
        for stat in cpuloadOutputAry[0].split("\n"):
            if stat[:4]!="last":
                statAry = ' '.join(stat.split()).split(":")
                last30SecAry.append(statAry[0].replace(" ","_")+"="+str(int(statAry[1].strip())))
                GWStats["cpuload_last_30_sec_"+statAry[0].replace(" ","_")] = int(statAry[1].strip())

        influxDbStats["imperva_gw_cpuload"]["last_sec"] = []
        lastSecAry = influxDbStats["imperva_gw_cpuload"]["last_sec"]
        for stat in cpuloadOutputAry[1].split("\n"):
            if stat[:4]!="last":
                statAry = ' '.join(stat.split()).split(":")
                lastSecAry.append(statAry[0].replace(" ","_")+"="+str(int(statAry[1].strip())))
                GWStats["cpuload_last_sec_"+statAry[0].replace(" ","_")] = int(statAry[1].strip())

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
                GWStats["cpu_"+CPUNum+"_"+CPUStatKey[index]] = int(CPUStatAry[0])
                GWStats["cpu_"+CPUNum+"_"+CPUStatKey[index]+"_max"] = int(CPUStatAry[2])
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
    # print("INFLUXDB REQUEST: "+influxdb_url+"?"+params)
    logging.warning("INFLUXDB REQUEST: "+influxdb_url+"?"+params)
    if "proxies" in CONFIG:
        proxies = {"https": "https://" + CONFIG["proxies"]["proxy_username"] + ":" + CONFIG["proxies"]["proxy_password"] + "@" + CONFIG["proxies"]["proxy_host"] + ":" + CONFIG["proxies"]["proxy_port"]}
        response = requests.post(influxdb_url, data=data, proxies=proxies, headers=headers, verify=False)
    else:
        if "username" in CONFIG["influxdb"]:
            response = requests.post(influxdb_url, auth=HTTPBasicAuth(CONFIG["influxdb"]["username"], CONFIG["influxdb"]["password"]), data=data, headers=headers, verify=False)
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
    "X10K":{"gw_supported_kbps":"10000000","gw_supported_hps":"72000"},
    "X2510":{"gw_supported_kbps":"500000","gw_supported_hps":"5000"},
    "X4510":{"gw_supported_kbps":"1000000","gw_supported_hps":"9000"},
    "X6510":{"gw_supported_kbps":"2000000","gw_supported_hps":"18000"},
    "X8510":{"gw_supported_kbps":"5000000","gw_supported_hps":"36000"},
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

def sendSyslog(jsonObj):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect((CONFIG["syslog"]["host"], CONFIG["syslog"]["port"]))
        s.sendall(b'{0}'.format(json.dumps(jsonObj)))
        s.close()
    except socket.error as msg:
        logging.warning("sendSyslog() exception: "+msg)

if __name__ == '__main__':
    run()
