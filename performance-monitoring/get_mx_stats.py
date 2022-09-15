#!/usr/bin/python
import os
import socket
import subprocess
from subprocess import PIPE,Popen
from time import localtime, strftime
import datetime
import json
import requests
import urllib2
import logging
import re
import math
import codecs
import re
import sys
from requests.auth import HTTPBasicAuth
import syslog 
import logging.handlers

############### Examples ###############
# Add the following to contab -e to get OS stats every minute, and MX system level stats every 6 hours
# * * * * * /usr/bin/python /var/user-data/get_mx_stats.py
# 0 */6 * * * /usr/bin/python /var/user-data/get_mx_stats.py get_server_stats

############### Configs ###############
CONFIGFILE = '/var/user-data/config.json'
MXNAME = os.uname()[1].split('.')[0]
# TIMESTAMP = strftime("%Y/%m/%d %H:%M:%S", localtime())
TIMESTAMP = datetime.datetime.now().isoformat()
MXSourceIp = "n/a"
with open('/opt/SecureSphere/etc/bootstrap.xml', 'r') as content_file:
    content = content_file.read()
    m = re.search('(name=).?(management).? .*',content)
    sourceIpStr = m.group(0)
    MXSourceIp = sourceIpStr[sourceIpStr.index('address-v4="')+12:sourceIpStr.index('" address-v6=')-3]
influxDefaultTags = "source="+MXSourceIp+",mxname="+MXNAME+","
MXMODEL = ""
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

# MX level statistics
MXStats = {
    "mx": MXNAME,
    "event_type": "mx",
    "timestamp": TIMESTAMP
}

MXSonarStats = {
    "mx": MXNAME,
    "event_type": "mx",
    "timestamp": TIMESTAMP,
    "policies":{},
    "gateways":{},
    "disk":{},
    "memory":{},
    "cpu":{
        "top":{},
        "sar":{},
        "last_min_load": {}
    },
    "network":{},
    "log_search":{},
    "system":{}
}

AgentStats = {}

influxDbStats = {
    "imperva_mx":{},
    "imperva_gw":{},
    "imperva_agents":{},
    "imperva_audit_policies":{},
    "imperva_mx_net":{},
    "imperva_mx_disk":{},
    "imperva_mx_sys":{},
    "imperva_mx_top_cpu":{},
    "imperva_mx_sar_cpu":{}
}

def run():
    if (len(sys.argv)>1):
        if (sys.argv[1]=="get_server_stats"):
            getMXServerStats()
    getDiskStats()
    getSysStats()
    getNetworkStats()

    if CONFIG["log_search"]["enabled"]:
        for fileconfig in CONFIG["log_search"]["files"]:
            for patternconfig in fileconfig["search_patterns"]:
                matches = searchLogFile(fileconfig["path"], patternconfig["pattern"])
                match = "\n".join(matches).replace('"',"'")
                if match!="":
                    MXStats[patternconfig["name"]] = match
                    MXSonarStats["log_search"][patternconfig["name"]] = match

    if CONFIG["newrelic"]["enabled"]:
        logging.debug("processing newrelic request: "+json.dumps(MXStats))
        makeCallNewRelicCall(MXStats)
    if CONFIG["syslog"]["enabled"]:
        logging.debug("processing syslog request: "+json.dumps(MXStats))
        sendSyslog(MXStats)
    if CONFIG["sonar"]["enabled"]:
        logging.debug("processing sonar request: "+json.dumps(MXSonarStats))
        sendSonar(MXSonarStats)
        for agent_name in AgentStats:
            sendSonar(AgentStats[agent_name])
    if CONFIG["influxdb"]["enabled"]:
        logging.debug("processing influxdb requests: "+json.dumps(influxDbStats))
        for measurement in influxDbStats:
            curStat = influxDbStats[measurement]
            for tags in curStat:
                makeInfluxDBCall(measurement, influxDefaultTags+tags, ','.join(curStat[tags]))
    # if CONFIG["servicenow"]["enabled"]:
    #     print("make servicenow call")
    #     # todo finish integration with ServiceNow
    
#########################################################
############### General Porpuse Functions ###############
#########################################################
def strim(str):
    return re.sub('\s\s+', ' ', str).strip()

def getMXServerStats():
    input, output, error = os.popen3('/opt/SecureSphere/etc/impctl/bin/support/server/show --scale-info')
    serverStatsStr = re.sub(r"-----.*-----", '----------', str(output.read().strip()))
    serverStatsAry = serverStatsStr.strip().split("----------")
    # remove first 2 entries that contain no useful stats
    serverStatsAry.pop(0)
    serverStatsAry.pop(0)
    # parse out last enty containing MX summary totals
    mxTotalsAry = serverStatsAry.pop().strip().split("\n")

    influxDbStats["imperva_mx"]["mx_name="+MXNAME] = []
    influxMXStatAry = influxDbStats["imperva_mx"]["mx_name="+MXNAME]
    for stat in mxTotalsAry:
        statAry = stat.split(":")
        influxMXStatAry.append(statAry[0].lower().replace(" ","_")+"="+statAry[1].strip())
    while len(serverStatsAry)>0:
        gwSummaryStats = serverStatsAry.pop(0)
        gwSummaryStatsAry = ' '.join(gwSummaryStats.strip().split()).strip().split()
        gwUtilStatsAry = serverStatsAry.pop(0).strip().split("\n")
        # Parse out gateway stat, example: Gateway: gatewaynamehere 0 Agents 0 SG 0 IP Audit: 1% /2% V4500(Sniffing) RUNNING Kbps: 15184 (338032) Ipu: (773) Hps: 738 (50092) ((3591))
        gw_name = gwSummaryStatsAry[1].strip()
        gw_model = gwSummaryStatsAry[11].split("(").pop(0).strip()
        gw_config = gwSummaryStatsAry[11].replace(")","").split("(").pop().strip()
        gw_status = gwSummaryStatsAry[12].strip()

        influxDbStats["imperva_gw"]["mx_name="+MXNAME+",gw_name="+gw_name+",gw_model="+gw_model+",gw_config="+gw_config+",gw_status="+gw_status] = []
        influxGWStatAry = influxDbStats["imperva_gw"]["mx_name="+MXNAME+",gw_name="+gw_name+",gw_model="+gw_model+",gw_config="+gw_config+",gw_status="+gw_status]
        influxGWStatAry.append("gw_audit_utilization_percent="+("0" if gwSummaryStatsAry[9].strip()=="%" else gwSummaryStatsAry[9].replace("%","").strip()))
        influxGWStatAry.append("gw_load_kbps="+re.findall(r"Kbps:.([0-9]*\S\w*)", gwSummaryStats).pop().strip())
        influxGWStatAry.append("gw_load_kbps_max="+re.findall(r"Kbps:.[0-9]*\S\w*.+?\(([0-9]*)", gwSummaryStats).pop().strip())
        influxGWStatAry.append("gw_load_hps="+re.findall(r"Hps:.([0-9]*\S\w*)", gwSummaryStats).pop().split(":").pop().strip())
        influxGWStatAry.append("gw_load_hps_max="+re.findall(r"Hps:.[0-9]*\S\w*.+?\(([0-9]*)", gwSummaryStats).pop().strip())
        
        MXSonarStats["gateways"][gw_name] = {}
        MXSonarStats["gateways"][gw_name]["audit_utilization_percent"] = ("0" if gwSummaryStatsAry[9].strip()=="%" else gwSummaryStatsAry[9].replace("%","").strip())
        MXSonarStats["gateways"][gw_name]["load_kbps"] = re.findall(r"Kbps:.([0-9]*\S\w*)", gwSummaryStats).pop().strip()
        MXSonarStats["gateways"][gw_name]["load_kbps_max"] = re.findall(r"Kbps:.[0-9]*\S\w*.+?\(([0-9]*)", gwSummaryStats).pop().strip()
        MXSonarStats["gateways"][gw_name]["load_hps"] = re.findall(r"Hps:.([0-9]*\S\w*)", gwSummaryStats).pop().split(":").pop().strip()
        MXSonarStats["gateways"][gw_name]["load_hps_max"] = re.findall(r"Hps:.[0-9]*\S\w*.+?\(([0-9]*)", gwSummaryStats).pop().strip()        
        
        # Parse out agent stat, example: Gateway: gateway_name_here 0 Agents 0 SG 0 IP Audit: 1% /2% V4500(Sniffing) RUNNING Kbps: 15184 (338032) Ipu: (773) Hps: 738 (50092) ((3591))
        if (''.join(gwUtilStatsAry)!=""):
            while len(gwUtilStatsAry)>0:
                stat = gwUtilStatsAry.pop(0)
                statAry = ' '.join(stat.strip().split()).split()

                if (statAry[0]=="Agent:"):
                    agent_name = statAry[1]
                    agent_id = statAry[3]
                    agent_status = str(statAry[8].lower())                    
                    agent_status_int = 0
                    if ("running" in agent_status and "errors" in agent_status):
                        agent_status_int = 4
                    elif ("bad" in agent_status and "connectivity" in agent_status):
                        agent_status_int = 6
                    elif ("running" in agent_status):
                        agent_status_int = 5
                    elif ("disabled" in agent_status):
                        agent_status_int = 2
                    elif ("gateway" in agent_status and "disconnected" in agent_status):
                        agent_status_int = 1
                    elif ("disconnected" in agent_status):
                        agent_status_int = 3
                    
                    influxDbStats["imperva_agents"]["mx_name="+MXNAME+",gw_name="+gw_name+",agent_name="+agent_name+",agent_status="+agent_status] = []
                    influxAgentStatAry = influxDbStats["imperva_agents"]["mx_name="+MXNAME+",gw_name="+gw_name+",agent_name="+agent_name+",agent_status="+agent_status]
                    influxAgentStatAry.append("agent_channels="+statAry[5])
                    influxAgentStatAry.append("agent_cores="+statAry[7])
                    influxAgentStatAry.append("agent_load_kpbs="+statAry[10])
                    influxAgentStatAry.append("agent_load_kpbs_max="+statAry[11].replace("(","").replace(")",""))
                    influxAgentStatAry.append("agent_load_ipu="+statAry[13])
                    influxAgentStatAry.append("agent_load_ipu_max="+statAry[14].replace("(","").replace(")",""))
                    influxAgentStatAry.append("agent_load_hps="+statAry[16])
                    influxAgentStatAry.append("agent_load_hps_max="+statAry[17].replace("(","").replace(")",""))
                    influxAgentStatAry.append("agent_load_percent="+("0" if statAry[18].strip()=="%" else statAry[18].replace("%","").strip()))
                    influxAgentStatAry.append("agent_id="+str(agent_id))
                    influxAgentStatAry.append("agent_status_int="+str(agent_status_int))

                    AgentStats[agent_name] = {"agent_name":agent_name,"event_type":"agent","counters":{}}
                    AgentStats[agent_name]["timestamp"] = TIMESTAMP
                    AgentStats[agent_name]["agent_id"] = str(agent_id)
                    AgentStats[agent_name]["mx"] = MXNAME
                    AgentStats[agent_name]["gw"] = gw_name
                    AgentStats[agent_name]["status"] = agent_status
                    AgentStats[agent_name]["status_int"] = agent_status_int
                    AgentStats[agent_name]["counters"]["channels"] = statAry[5]
                    AgentStats[agent_name]["counters"]["cores"] = statAry[7]
                    AgentStats[agent_name]["counters"]["load_kpbs"] = statAry[10]
                    AgentStats[agent_name]["counters"]["load_kpbs_max"] = statAry[11].replace("(","").replace(")","")
                    AgentStats[agent_name]["counters"]["load_ipu"] = statAry[13]
                    AgentStats[agent_name]["counters"]["load_ipu_max"] = statAry[14].replace("(","").replace(")","")
                    AgentStats[agent_name]["counters"]["load_hps"] = statAry[16]
                    AgentStats[agent_name]["counters"]["load_hps_max"] = statAry[17].replace("(","").replace(")","")
                    AgentStats[agent_name]["counters"]["load_percent"] = ("0" if statAry[18].strip()=="%" else statAry[18].replace("%","").strip())

                elif (statAry[0]=="(!)"):
                    if (statAry[1]=="ApplicativePacketLoss"):
                        influxGWStatAry.append("gateway_daily_packet_loss="+statAry[3].split("/").pop(0))
                        influxGWStatAry.append("gateway_daily_packet_loss_percent="+statAry[4].replace("%",""))
                        influxGWStatAry.append("gateway_daily_total_packets="+statAry[3].split("/").pop())
                        influxGWStatAry.append("gateway_weekly_packet_loss="+statAry[6].split("/").pop(0))
                        influxGWStatAry.append("gateway_weekly_packet_loss_percent="+statAry[7].replace("%",""))
                        influxGWStatAry.append("gateway_weekly_total_packets="+statAry[6].split("/").pop())
                        MXSonarStats["gateways"][gw_name]["daily_packet_loss"] = statAry[3].split("/").pop(0)
                        MXSonarStats["gateways"][gw_name]["daily_packet_loss_percent"] = statAry[4].replace("%","")
                        MXSonarStats["gateways"][gw_name]["daily_total_packets"] = statAry[3].split("/").pop()
                        MXSonarStats["gateways"][gw_name]["weekly_packet_loss"] = statAry[6].split("/").pop(0)
                        MXSonarStats["gateways"][gw_name]["weekly_packet_loss_percent"] = statAry[7].replace("%","")
                        MXSonarStats["gateways"][gw_name]["weekly_total_packets"] = statAry[6].split("/").pop()

                elif (statAry[0]=="(A)"):
                    audit_policy_name = re.findall(r"\(A\) (.*)\s[0-9]+/[0-9]+", stat).pop().strip()
                    # [0-9].*\/.*[0-9]\s
                    # .[0-9]*\.[0-9].*\%
                    influxDbStats["imperva_audit_policies"]["mx_name="+MXNAME+",gw_name="+gw_name+",audit_policy_name="+audit_policy_name.replace(" ","_")] = []
                    influxAuditPolicyStatAry = influxDbStats["imperva_audit_policies"]["mx_name="+MXNAME+",gw_name="+gw_name+",audit_policy_name="+audit_policy_name.replace(" ","_")]
                    influxAuditPolicyStatAry.append("audit_events_phase1="+re.findall(r"([0-9]+)/[0-9]+", stat).pop().strip())
                    influxAuditPolicyStatAry.append("audit_events_phase2="+re.findall(r"[0-9]+/([0-9]+)", stat).pop().strip())
                    influxAuditPolicyStatAry.append("audit_policy_percent="+re.findall(r"([-+]?[0-9]*\.?[0-9]*)\%", stat).pop().strip())
                    MXSonarStats["policies"][audit_policy_name] = {}
                    MXSonarStats["policies"][audit_policy_name]["audit_events_phase1"] = re.findall(r"([0-9]+)/[0-9]+", stat).pop().strip()
                    MXSonarStats["policies"][audit_policy_name]["audit_events_phase2"] = re.findall(r"[0-9]+/([0-9]+)", stat).pop().strip()
                    MXSonarStats["policies"][audit_policy_name]["audit_policy_percent"] = re.findall(r"([-+]?[0-9]*\.?[0-9]*)\%", stat).pop().strip()


def getNetworkStats():
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
                influxDbStats["imperva_mx_net"]["interface="+ifacename+",ipaddress="+ipaddress+",uptime="+UPTIME] = []
                influxIfaceStatAry = influxDbStats["imperva_mx_net"]["interface="+ifacename+",ipaddress="+ipaddress+",uptime="+UPTIME]
                MXSonarStats["network"][ifacename] = {}
                input, statoutput, error = os.popen3("ls "+basedir+ifacename+"/statistics/")
                for stat in statoutput.read().split("\n"):
                    if stat.strip() !="":
                        input, output, error = os.popen3("cat "+basedir+ifacename+'/statistics/'+stat)
                        val = output.read().strip()
                        influxIfaceStatAry.append(stat+"="+val)
                        MXStats["interface_"+ifacename+"_"+stat] = int(val)
                        MXSonarStats["network"][ifacename][stat] = int(val)
    
def getDiskStats():
    pipe = Popen(['cat','/proc/mounts'], stdout=PIPE)
    output = pipe.communicate()
    mountsAry = str(output[0]).split("\n")
    for mount in mountsAry:
        if mount.strip()!="":
            mountAry = mount.replace(","," ").split(" ")
            if mountAry[1][:1]=="/":
                pipe = Popen(['df',mountAry[1]], stdout=PIPE)
                MXSonarStats["disk"][mountAry[1]] = {}
                output = pipe.communicate()
                mountStats = str(output[0]).split("\n")
                mountStats.pop(0)
                mountStatsAry = ' '.join(mountStats).replace("\n"," ").split()
                influxDbStats["imperva_mx_disk"]["volume="+mountAry[1]] = []
                influxIfaceStatAry = influxDbStats["imperva_mx_disk"]["volume="+mountAry[1]]
                influxIfaceStatAry.append("disk_capacity="+mountStatsAry[1])
                influxIfaceStatAry.append("disk_used="+mountStatsAry[2])
                influxIfaceStatAry.append("disk_available="+mountStatsAry[3])
                MXStats["disk_volume"+mountAry[1]+"_disk_capacity"] = int(mountStatsAry[1])
                MXStats["disk_volume"+mountAry[1]+"_disk_used"] = int(mountStatsAry[2])
                MXStats["disk_volume"+mountAry[1]+"_disk_available"] = int(mountStatsAry[3])
                MXSonarStats["disk"][mountAry[1]]["disk_capacity"] = int(mountStatsAry[1])
                MXSonarStats["disk"][mountAry[1]]["disk_used"] = int(mountStatsAry[2])
                MXSonarStats["disk"][mountAry[1]]["disk_available"] = int(mountStatsAry[3])

def getSysStats():
    with open('/opt/SecureSphere/etc/bootstrap.xml', 'r') as content_file:
        content = content_file.read()
        m = re.search('(appliance)\s(tag=).*',content)
        modelStr = m.group(0)
        model = modelStr[modelStr.index('appliance tag=')+15:modelStr.index('" name=')]
        global MXMODEL
        MXMODEL = model
        influxDbStats["imperva_mx_sys"]["model="+model] = []        
        sysStat = influxDbStats["imperva_mx_sys"]["model="+model]

        

        pipe = Popen(['/opt/SecureSphere/etc/impctl/bin/platform/show'], stdout=PIPE)
        output = pipe.communicate()
        for stat in output[0].split("\n"):
            if stat.strip()!="":
                statAry = stat.split(" ")
                key = statAry.pop(0)
                val = statAry.pop()
                MXSonarStats["system"][key] = val
                influxDbStats["imperva_mx_sys"][key+"="+val] = []
                sysStat = influxDbStats["imperva_mx_sys"][key+"="+val]
                MXStats[key] = val
        
        global UPTIME
        input, output, error = os.popen3("cat /proc/uptime")
        UPTIME = output.read().strip().split(" ").pop(0).split(".").pop(0)
    
        sysStat.append("uptime="+UPTIME)
        MXStats["uptime"] = UPTIME
        MXSonarStats["system"]["uptime"] = UPTIME
        pipe = Popen(['top','-bn','2'], stdout=PIPE)
        output = pipe.communicate()
        topOutputAry = str(output[0]).split("top - ").pop().split("\n")
        for stat in topOutputAry:
            stat = stat.lower().replace("%"," ").replace("kib ","").replace("k","")
            statType = stat.split(":").pop(0).lower().strip()
            statsAry = ' '.join(stat.split(":").pop().lower().strip().split()).split(",")
            if statType[:3]=="mem" or statType[:4]=="swap":
                MXSonarStats["memory"][statType] = {}
                for curStat in statsAry:
                    statAry = curStat.strip().split()
                    statMeasurement = statAry[1][:5].replace(".","").strip()
                    if statMeasurement=="total" or statMeasurement=="used" or statMeasurement=="free":
                        sysStat.append(statType+"_"+statMeasurement+"="+statAry[0])
                        MXStats["top_"+statType+"_"+statMeasurement] = float(statAry[0])
                        MXSonarStats["memory"][statType][statMeasurement] = float(statAry[0])
            elif statType[:3]=="cpu":
                cpu = statType.replace("cpu","")
                MXSonarStats["cpu"]["top"][cpu] = {}
                influxDbStats["imperva_mx_top_cpu"]["cpu="+cpu] = []
                MXCpuStatAry = influxDbStats["imperva_mx_top_cpu"]["cpu="+cpu]
                for cpuStat in statsAry:
                    statAry = cpuStat.strip().split()
                    MXCpuStatAry.append(topCpuAttrMap[statAry[1]]+"="+statAry[0])
                    MXStats["top_"+statType.lower()+"_"+topCpuAttrMap[statAry[1]]] = float(statAry[0])
                    MXSonarStats["cpu"]["top"][cpu][topCpuAttrMap[statAry[1]]] = float(statAry[0])
            elif "load average" in stat:
                last_min_average = stat.split("load average: ").pop(1).split(",").pop(0).strip()
                lastSecAry = influxDbStats["imperva_mx_top_cpu"]["cpu=all"] = []                
                lastSecAry.append("last_min_load_average="+str(last_min_average))
                MXStats["cpuload_last_min_load_average"] = float(last_min_average)
                MXSonarStats["cpu"]["last_min_load"]["average"] = float(last_min_average)

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
                        influxDbStats["imperva_mx_sar_cpu"]["cpu="+statAry[1].lower()] = []
                        MXCpuStatAry = influxDbStats["imperva_mx_sar_cpu"]["cpu="+statAry[1].lower()]
                        for j in range(len(statAry)):
                            curIndexName = sarStatIndexAry[j]
                            if j>1:
                                cpuStat = statAry[j]
                                MXCpuStatAry.append(curIndexName+"="+cpuStat)
                                MXStats["sar_cpu"+statAry[2].lower()+"_"+curIndexName] = float("{0:.2f}".format(float(cpuStat)))
        except:
            logging.error("Missing package: sar command not found")

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
        # print("INFLUXDB REQUEST: "+influxdb_url+"?"+params)
        logging.info("INFLUXDB REQUEST: "+influxdb_url+"?"+params)
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
            try:
                logger = logging.getLogger('Logger')
                logger.setLevel(logging.INFO)
                handler = logging.handlers.SysLogHandler(address=(syslogEndpoint["host"],syslogEndpoint["port"]),facility=syslogEndpoint["facility"],socktype=(socket.SOCK_STREAM if syslogEndpoint["protocol"]=="TCP" else socket.SOCK_DGRAM))
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
                logging.error("sendSonar() logging.handlers.SysLogHandler() failed")
                logging.error(e)
                try:
                    logging.warning("retrying with socket connection: ")
                    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    s.connect((sonarEndpoint["host"], sonarEndpoint["port"]))
                    s.sendall(b'{0}'.format(json.dumps(jsonObj)+"\n"))
                    s.close()
                except socket.error as msg:
                    logging.warning("sendSonar() exception: ")
                    logging.warning(msg)                    

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

if __name__ == '__main__':
    run()

