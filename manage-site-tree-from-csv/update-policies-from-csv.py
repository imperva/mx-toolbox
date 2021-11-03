#!/usr/bin/env python

import ss
import sys
import json
import csv
import requests
import logging
import urllib
from subprocess import PIPE,Popen
import pyparsing


############ ENV Settings ############
logging.basicConfig(filename="update_policies_from_csv.log", filemode='w', format='%(name)s - %(levelname)s - %(message)s')

############ GLOBALS ############
CONFIGFILE = 'config.json'
CONFIG = {}

try:
    with open(CONFIGFILE, 'r') as data:
        CONFIG = json.load(data)
except:
    print("Missing \""+CONFIGFILE+"\" file, create file named \""+CONFIGFILE+"\" with the following contents:\n{\n\t\"log_level\": \"debug\",\n\t\"log_file_name\": \"gateway_statistics.log\",\n\t\"environment\": \"dev\",\n\t\"is_userspace\":false,\n\t\"environment\": \"dev\",\n\t\"log_search\": {\n\t\t\"enabled\": true,\n\t\t\"files\": [{\n\t\t\t\"path\": \"/var/log/messages\",\n\t\t\t\"search_patterns\": [{\n\t\t\t\t\t\"name\":\"YOUR_EVENT_NAME\",\n\t\t\t\t\t\"pattern\":\"some text pattern\"\n\t\t\t\t}, {\n\t\t\t\t\t\"name\":\"YOUR_EVENT_NAME_2\",\n\t\t\t\t\t\"pattern\":\"some other text pattern\"\n\t\t\t\t}\n\t\t\t]\n\t\t}]\n\t},\n\t\"newrelic\": {\n\t\t\"enabled\": false,\n\t\t\"account_id\": \"ACCOUNT_ID\",\n\t\t\"api_key\": \"API_KEY\",\n\t\t\"event_type\": \"GWStats\"\n\t},\n\t\"influxdb\": {\n\t\t\"enabled\": true,\n\t\t\"host\": \"http://1.2.3.4:8086/write?db=imperva_performance_stats\"\n\t},\n\t\"syslog\": {\n\t\t\"enabled\": true,\n\t\t\"host\": \"1.2.3.4\",\n\t\t\"port\": 514\n\t}\n}")
    exit()

if len(sys.argv)<2:
	print("[ERROR] Missing argument, please specify the path to the csv to import. \n  Example: python update-policies-from-csv.py /path/to/my_policies.csv")
	logging.warning("[ERROR] Missing argument, please specify the path to the csv to import. Example: python update-policies-from-csv.py /path/to/my_policies.csv")
	quit()

try:
    CSV_FILE_PATH = sys.argv[1]
except:
    print('Path to csv is missing, please specify a path to csv file you are looking to import. Example: python import-waf-site-tree-from-csv.py "path/to/my_policies.csv"')
    exit()

def run():
    policies = ss.ParseCsvWafPolicies(CSV_FILE_PATH)
    mx_host = CONFIG["mx"]["endpoint"]
    session_id = ss.login(mx_host, CONFIG["mx"]["username"], CONFIG["mx"]["password"])

    for policy_name in policies:
        policyConfig = policies[policy_name]
        if (policyConfig["policy_type"] in ss.policyMapping):
            response = ss.makeCall(mx_host, session_id, "/conf/policies/security/" + ss.policyMapping[policyConfig["policy_type"]] + "/" + policy_name)
            if (response.status_code == 200):
                policyObj = response.json()
                del policyObj["applyTo"]                
                logging.warning("Process policy '"+policy_name+"' policy type '"+policyConfig["policy_type"]+"'")
                baseLevelSettingPolicies = {"Web Application Custom","Web Service Custom"}
                ruleListSettingPolicies = {"HTTP Protocol Signatures", "HTTP/1.x Protocol Validation", "HTTP/2 Protocol Validation", "Stream Signature", "Web Application Signatures","Web Service Correlated Validation"}
                if policyConfig["policy_type"] in ruleListSettingPolicies:
                    for policyRule in policyObj["rules"]:
                        if (policyRule["name"].strip() in policyConfig["rules"]):
                            curPolicyConfig = policyConfig["rules"][policyRule["name"].strip()]
                            rule_action = "block" if "block" in curPolicyConfig["rule_action"].lower() else "none"
                            rule_enabled = True if "enabled" in curPolicyConfig["rule_enabled"].lower() else False
                            rule_severity = curPolicyConfig["rule_severity"].lower() if "noalert" not in curPolicyConfig["rule_severity"].lower().replace(" ","") else "noAlert"
                            policyRule["enabled"] = rule_enabled
                            policyRule["severity"] = rule_severity
                            policyRule["action"] = rule_action
                        else:
                            logging.warning("Policy rule '"+policyRule["name"]+"' for policy '"+policy_name+"' not found, ignoring csv policy rule")
                    print("Updating policy '"+policy_name+"'")
                    updateResponse = ss.makeCall(mx_host, session_id, "/conf/policies/security/" + ss.policyMapping[policyConfig["policy_type"]] + "/" + policy_name,"PUT",json.dumps(policyObj))
                    if (updateResponse.status_code != 200):
                        responseObj = updateResponse.json()
                        print(json.dumps(responseObj))
                elif policyConfig["policy_type"] in baseLevelSettingPolicies:
                    curPolicyConfig = policyConfig["rules"]["Custom Violation"]
                    rule_action = "block" if "block" in curPolicyConfig["rule_action"].lower() else "none"
                    rule_enabled = True if "enabled" in curPolicyConfig["rule_enabled"].lower() else False
                    rule_severity = curPolicyConfig["rule_severity"].lower() if "noalert" not in curPolicyConfig["rule_severity"].lower().replace(" ","") else "noAlert"
                    reqObj = {
                        "enabled": rule_enabled, 
                        "severity": rule_severity, 
                        "action": rule_action
                    }
                    print("Updating policy '"+policy_name+"'")
                    updateResponse = ss.makeCall(mx_host, session_id, "/conf/policies/security/" + ss.policyMapping[policyConfig["policy_type"]] + "/" + policy_name,"PUT",json.dumps(reqObj))
                    if (updateResponse.status_code != 200):
                        responseObj = updateResponse.json()
                        print(json.dumps(responseObj))

                ## if policy["policy_type"]=="Firewall Policy":
                ##     print("process '"+policy_name+"' - Firewall Policy")    
                ## elif policy["policy_type"]=="Web Profile Policies":
                ##     print("process '"+policy_name+"' - Web Profile Policies")        
                ### elif policyConfig["policy_type"]=="Network Protocol Validation":
                ###     print("process '"+policy_name+"' - Network Protocol Validation")
                ### elif policyConfig["policy_type"]=="Snippet Injection Policy":
                ###     print("process '"+policy_name+"' - Snippet Injection Policy")        
                ### elif policy["policy_type"]=="Web Worm":
                ###     print("process '"+policy_name+"' - Web Worm")
                else:
                    print("Unsupported policy type '"+policyConfig["policy_type"]+"' for policy '"+policy_name+"'")
            else:
                print("ERROR: "+json.dumps(policyObj))
        else:
            print("Unsupported policy type '"+policyConfig["policy_type"]+"' for policy '"+policy_name+"'")

if __name__ == '__main__':
    run()
