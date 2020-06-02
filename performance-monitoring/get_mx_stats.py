#!/usr/bin/python
import os
import socket
import subprocess
from subprocess import PIPE,Popen
from time import localtime, strftime
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

############### Examples ###############
# Add the following to contab -e to get OS stats every minute, and MX system level stats every 6 hours
# * * * * * /usr/bin/python /var/user-data/get_mx_stats.py
# 0 */6 * * * /usr/bin/python /var/user-data/get_mx_stats.py get_server_stats

############### Configs ###############
CONFIGFILE = '/var/user-data/config.json'
MXNAME = os.uname()[1].split('.')[0]
TIMESTAMP = strftime("%Y/%m/%d %H:%M:%S", localtime())
MXSourceIp = "n/a"
with open('/opt/SecureSphere/etc/bootstrap.xml', 'r') as content_file:
    content = content_file.read()
    m = re.search('(name=).?(management).? .*',content)
    sourceIpStr = m.group(0)
    MXSourceIp = sourceIpStr[sourceIpStr.index('address-v4="')+12:sourceIpStr.index('" address-v6=')-3]
influxDefaultTags = "source="+MXSourceIp+",mxname="+MXNAME+","
MXMODEL = ""
try:
    with open(CONFIGFILE, 'r') as data:
        CONFIG = json.load(data)
except:
    print("Missing \""+CONFIGFILE+"\" file, create file named \""+CONFIGFILE+"\" with the following contents:\n{\n\t\"log_level\": \"debug\",\n\t\"environment\": \"dev\",\n\t\"log_search\": {\n\t\t\"enabled\": true,\n\t\t\"files\": [{\n\t\t\t\"path\": \"/var/log/messages\",\n\t\t\t\"search_patterns\": [{\n\t\t\t\t\t\"name\":\"YOUR_EVENT_NAME\",\n\t\t\t\t\t\"pattern\":\"some text pattern\"\n\t\t\t\t}, {\n\t\t\t\t\t\"name\":\"YOUR_EVENT_NAME_2\",\n\t\t\t\t\t\"pattern\":\"some other text pattern\"\n\t\t\t\t}\n\t\t\t]\n\t\t}]\n\t},\n\t\"newrelic\": {\n\t\t\"enabled\": false,\n\t\t\"account_id\": \"ACCOUNT_ID\",\n\t\t\"api_key\": \"API_KEY\",\n\t\t\"event_type\": \"MXStats\"\n\t},\n\t\"servicenow\": {\n\t\t\"enabled\": false,\n\t\t\"account_id\": \"ACCOUNT_ID\",\n\t\t\"api_key\": \"API_KEY\"\n\t},\n\t\"syslog\": {\n\t\t\"enabled\": true,\n\t\t\"host\": \"1.2.3.4\",\n\t\t\"port\": 514\n\t}\n}")
    exit()
if CONFIG["is_userspace"]:
    BASEDIR = "/opt/SecureSphere/etc/proc/hades/"
else:
    BASEDIR = '/proc/hades/'
    # urllib3.disable_warnings()

############ ENV Settings ############
logging.basicConfig(filename=CONFIG["log_file_name"], filemode='w', format='%(name)s - %(levelname)s - %(message)s')

# MX level statistics
MXStats = {
    "mx": MXNAME,
    "timestamp": TIMESTAMP
}

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
                MXStats[patternconfig["name"]] = "\n".join(matches).replace('"',"'")

    if CONFIG["newrelic"]["enabled"]:
        makeCallNewRelicCall(MXStats)
    if CONFIG["syslog"]["enabled"]:
        sendSyslog(MXStats)
    if CONFIG["influxdb"]["enabled"]:
        for measurement in influxDbStats:
            curStat = influxDbStats[measurement]
            for tags in curStat:
                makeInfluxDBCall(measurement, influxDefaultTags+tags, ','.join(curStat[tags]))
    if CONFIG["servicenow"]["enabled"]:
        print("make servicenow call")
        # todo finish integration with ServiceNow
    
#########################################################
############### General Porpuse Functions ###############
#########################################################
def strim(str):
    return re.sub('\s\s+', ' ', str).strip()

def getMXServerStats():
    pipe = Popen(['/opt/SecureSphere/etc/impctl/bin/support/server/show','--scale-info'], stdout=PIPE)
    # pipe = Popen(['cat',sys.argv[1]], stdout=PIPE)
    output = pipe.communicate()
    serverStatsStr = re.sub(r"-----.*-----", '----------', str(output[0].strip()))
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
        # influxGWStatAry.append("gw_load_ipu="+gwSummaryStatsAry[16].replace("(","").replace(")","").strip())
        influxGWStatAry.append("gw_load_hps="+re.findall(r"Hps:.([0-9]*\S\w*)", gwSummaryStats).pop().split(":").pop().strip())
        influxGWStatAry.append("gw_load_hps_max="+re.findall(r"Hps:.[0-9]*\S\w*.+?\(([0-9]*)", gwSummaryStats).pop().strip())
        # influxGWStatAry.append("gw_load_hps_max2="+gwSummaryStatsAry[20].replace("(","").replace(")","").strip())

        # Parse out agent stat, example: Gateway: gateway_name_here 0 Agents 0 SG 0 IP Audit: 1% /2% V4500(Sniffing) RUNNING Kbps: 15184 (338032) Ipu: (773) Hps: 738 (50092) ((3591))
        if (''.join(gwUtilStatsAry)!=""):
            while len(gwUtilStatsAry)>0:
                stat = gwUtilStatsAry.pop(0)
                statAry = ' '.join(stat.strip().split()).split()
                if (statAry[0]=="Agent:"):
                    agent_name = statAry[1]
                    agent_status = statAry[8]
                    agent_id = statAry[3]
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
                elif (statAry[0]=="(!)"):
                    if (statAry[1]=="ApplicativePacketLoss"):
                        influxGWStatAry.append("gateway_daily_packet_loss="+statAry[3].split("/").pop(0))
                        influxGWStatAry.append("gateway_daily_packet_loss_percent="+statAry[4].replace("%",""))
                        influxGWStatAry.append("gateway_daily_total_packets="+statAry[3].split("/").pop())
                        influxGWStatAry.append("gateway_weekly_packet_loss="+statAry[6].split("/").pop(0))
                        influxGWStatAry.append("gateway_weekly_packet_loss_percent="+statAry[7].replace("%",""))
                        influxGWStatAry.append("gateway_weekly_total_packets="+statAry[6].split("/").pop())
                elif (statAry[0]=="(A)"):
                    audit_policy_name = re.findall(r"\(A\) (.*)\s[0-9]+/[0-9]+", stat).pop().strip().replace(" ","_")
                    # [0-9].*\/.*[0-9]\s
                    # .[0-9]*\.[0-9].*\%
                    influxDbStats["imperva_audit_policies"]["mx_name="+MXNAME+",gw_name="+gw_name+",audit_policy_name="+audit_policy_name] = []
                    influxAuditPolicyStatAry = influxDbStats["imperva_audit_policies"]["mx_name="+MXNAME+",gw_name="+gw_name+",audit_policy_name="+audit_policy_name]
                    influxAuditPolicyStatAry.append("audit_policy_events="+re.findall(r"([0-9]+)/[0-9]+", stat).pop().strip())
                    influxAuditPolicyStatAry.append("audit_policy_percent="+re.findall(r"([-+]?[0-9]*\.?[0-9]*)\%", stat).pop().strip())
                    influxAuditPolicyStatAry.append("audit_total="+re.findall(r"[0-9]+/([0-9]+)", stat).pop().strip())

def getNetworkStats():
    pipe = Popen(['ls','/sys/class/net'], stdout=PIPE)
    output = pipe.communicate()
    interfaces = str(output[0]).split("\n")
    for ifacename in interfaces:
        if(ifacename!=""):
            if(ifacename[:3]=="eth"):
                influxDbStats["imperva_mx_net"]["interface="+ifacename] = []
                influxIfaceStatAry = influxDbStats["imperva_mx_net"]["interface="+ifacename]
                pipe = Popen(['/sbin/ifconfig',ifacename], stdout=PIPE)
                ifconfigoutput = pipe.communicate()
                for iface in ifconfigoutput[0].strip().split("\n"):
                    iface = ' '.join(iface.replace(":"," ").split())
                    if MXMODEL[:2].lower()=="av":
                        if (iface[:10].lower()=="rx packets"):
                            rxAry = iface[11:].split(" ")
                            influxIfaceStatAry.append("rx_packets="+rxAry[0])
                            influxIfaceStatAry.append("rx_bytes="+rxAry[2])
                            MXStats["interface_"+ifacename+"_rx_packets"] = int(rxAry[0])
                            MXStats["interface_"+ifacename+"_rx_bytes"] = int(rxAry[2])
                        elif (iface[:9].lower()=="rx errors"):
                            rxAry = iface[10:].split(" ")
                            influxIfaceStatAry.append("rx_errors="+rxAry[0])
                            influxIfaceStatAry.append("rx_dropped="+rxAry[2])
                            influxIfaceStatAry.append("rx_overruns="+rxAry[4])
                            influxIfaceStatAry.append("rx_frame="+rxAry[6])
                            MXStats["interface_"+ifacename+"_rx_errors"] = int(rxAry[0])
                            MXStats["interface_"+ifacename+"_rx_dropped"] = int(rxAry[2])
                            MXStats["interface_"+ifacename+"_rx_overruns"] = int(rxAry[4])
                            MXStats["interface_"+ifacename+"_rx_frame"] = int(rxAry[6])
                        elif (iface[:10].lower()=="tx packets"):
                            txAry = iface[11:].split(" ")
                            influxIfaceStatAry.append("tx_packets="+txAry[0])
                            influxIfaceStatAry.append("tx_bytes="+txAry[2])
                            MXStats["interface_"+ifacename+"_tx_packets"] = int(txAry[0])
                            MXStats["interface_"+ifacename+"_tx_bytes"] = int(txAry[2])
                        elif (iface[:9].lower()=="tx errors"):
                            txAry = iface[10:].split(" ")
                            influxIfaceStatAry.append("tx_errors="+txAry[0])
                            influxIfaceStatAry.append("tx_dropped="+txAry[2])
                            influxIfaceStatAry.append("tx_overruns="+txAry[4])
                            influxIfaceStatAry.append("tx_carrier="+txAry[6])
                            influxIfaceStatAry.append("collisions="+txAry[8])
                            MXStats["interface_"+ifacename+"_tx_errors"] = int(txAry[0])
                            MXStats["interface_"+ifacename+"_tx_dropped"] = int(txAry[2])
                            MXStats["interface_"+ifacename+"_tx_overruns"] = int(txAry[4])
                            MXStats["interface_"+ifacename+"_tx_carrier"] = int(txAry[6])                            
                            MXStats["interface_"+ifacename+"_collisions"] = int(txAry[8])
                        elif (iface[:8].lower()=="rx bytes"):
                            recordAry = iface[9:].split(" ")
                            influxIfaceStatAry.append("rx_bytes="+recordAry[0])
                            influxIfaceStatAry.append("tx_bytes="+recordAry[5])
                            MXStats["interface_"+ifacename+"_rx_bytes"] = int(recordAry[0])
                            MXStats["interface_"+ifacename+"_tx_bytes"] = int(recordAry[5])
                    else:
                        if (iface[:10].lower()=="rx packets"):
                            rxAry = iface[11:].split(" ")
                            influxIfaceStatAry.append("rx_packets="+rxAry[0])
                            influxIfaceStatAry.append("rx_errors="+rxAry[2])
                            influxIfaceStatAry.append("rx_dropped="+rxAry[4])
                            influxIfaceStatAry.append("rx_overruns="+rxAry[6])
                            influxIfaceStatAry.append("rx_frame="+rxAry[8])
                            MXStats["interface_"+ifacename+"_rx_packets"] = int(rxAry[0])
                            MXStats["interface_"+ifacename+"_rx_errors"] = int(rxAry[2])
                            MXStats["interface_"+ifacename+"_rx_dropped"] = int(rxAry[4])
                            MXStats["interface_"+ifacename+"_rx_overruns"] = int(rxAry[6])
                            MXStats["interface_"+ifacename+"_rx_frame"] = int(rxAry[8])
                        elif (iface[:10].lower()=="tx packets"):
                            txAry = iface[11:].split(" ")
                            influxIfaceStatAry.append("tx_packets="+txAry[0])
                            influxIfaceStatAry.append("tx_errors="+txAry[2])
                            influxIfaceStatAry.append("tx_dropped="+txAry[4])
                            influxIfaceStatAry.append("tx_overruns="+txAry[6])
                            influxIfaceStatAry.append("tx_carrier="+txAry[8])
                            MXStats["interface_"+ifacename+"_tx_packets"] = int(txAry[0])
                            MXStats["interface_"+ifacename+"_tx_errors"] = int(txAry[2])
                            MXStats["interface_"+ifacename+"_tx_dropped"] = int(txAry[4])
                            MXStats["interface_"+ifacename+"_tx_overruns"] = int(txAry[6])
                            MXStats["interface_"+ifacename+"_tx_carrier"] = int(txAry[8])
                        elif (iface[:10].lower()=="collisions"):
                            colAry = iface[11:].split(" ")
                            influxIfaceStatAry.append("collisions="+colAry[0])
                            MXStats["interface_"+ifacename+"_collisions"] = int(colAry[0])
                        elif (iface[:8].lower()=="rx bytes"):
                            recordAry = iface[9:].split(" ")
                            influxIfaceStatAry.append("rx_bytes="+recordAry[0])
                            influxIfaceStatAry.append("tx_bytes="+recordAry[5])
                            MXStats["interface_"+ifacename+"_rx_bytes"] = int(recordAry[0])
                            MXStats["interface_"+ifacename+"_tx_bytes"] = int(recordAry[5])

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
                influxDbStats["imperva_mx_disk"]["volume="+mountStatsAry[5]] = []
                influxIfaceStatAry = influxDbStats["imperva_mx_disk"]["volume="+mountStatsAry[5]]
                influxIfaceStatAry.append("disk_capacity="+mountStatsAry[1])
                influxIfaceStatAry.append("disk_used="+mountStatsAry[2])
                influxIfaceStatAry.append("disk_available="+mountStatsAry[3])
                MXStats["disk_volume"+mountStatsAry[5]+"_disk_capacity"] = int(mountStatsAry[1])
                MXStats["disk_volume"+mountStatsAry[5]+"_disk_used"] = int(mountStatsAry[2])
                MXStats["disk_volume"+mountStatsAry[5]+"_disk_available"] = int(mountStatsAry[3])

def getSysStats():
    with open('/opt/SecureSphere/etc/bootstrap.xml', 'r') as content_file:
        content = content_file.read()
        m = re.search('(appliance)\s(tag=).*',content)
        modelStr = m.group(0)
        model = modelStr[modelStr.index('appliance tag=')+15:modelStr.index('" name=')]
        global MXMODEL
        MXMODEL = model
        # TODO: Go back and find a way to get version numver, impctl does not work in cron
        influxDbStats["imperva_mx_sys"]["model="+model] = []        
        sysStat = influxDbStats["imperva_mx_sys"]["model="+model]
        pipe = Popen(['cat','/proc/uptime'], stdout=PIPE)
        output = pipe.communicate()
        uptimeAry = str(output[0]).split("\n")
        uptime = str(uptimeAry[0]).split(" ")
        sysStat.append("uptime="+uptime[0][:-3])
        MXStats["uptime"] = uptime[0][:-3]
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
                        MXStats["top_"+statType+"_"+statMeasurement] = float(statAry[0])
            elif statType[:3]=="cpu":
                cpu = statType.replace("cpu","")
                influxDbStats["imperva_mx_top_cpu"]["cpu="+cpu] = []
                MXCpuStatAry = influxDbStats["imperva_mx_top_cpu"]["cpu="+cpu]
                for cpuStat in statsAry:
                    statAry = cpuStat.strip().split()
                    MXCpuStatAry.append(topCpuAttrMap[statAry[1]]+"="+statAry[0])
                    MXStats["top_"+statType[0].lower()+"_"+topCpuAttrMap[statAry[1]]] = float(statAry[0])

        try:
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
            print("sar command not found")

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
        requests.post(new_relic_url, json.dumps(stat), proxies=proxies, headers=headers, verify=False)
    else:
        requests.post(new_relic_url, json.dumps(stat), headers=headers, verify=False)

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
