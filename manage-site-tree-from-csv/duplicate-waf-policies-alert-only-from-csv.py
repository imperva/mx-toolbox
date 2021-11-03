#!/usr/bin/env python

import ss
import os
import sys
import json
import csv
import requests
import logging
import urllib
from subprocess import PIPE,Popen
import pyparsing

############ ENV Settings ############
logging.basicConfig(filename="duplicate_waf_policies_alert_only_from_csv.log", filemode='w', format='%(name)s - %(levelname)s - %(message)s')

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
	print("[ERROR] Missing argument, please specify the path to the csv to import. \n  Example: python duplicate-waf-policies-alert-only-from-csv.py /path/to/my_policies.csv")
	logging.warning("[ERROR] Missing argument, please specify the path to the csv to import. Example: python duplicate-waf-policies-alert-only-from-csv.py /path/to/my_policies.csv")
	quit()

try:
    CSV_FILE_PATH = sys.argv[1]
except:
    print('Path to csv is missing, please specify a path to csv file you are looking to import. Example: python duplicate-waf-policies-alert-only-from-csv.py "path/to/my_policies.csv"')
    exit()

def run():
    mx_host = CONFIG["mx"]["endpoint"]
    session_id = ss.login(mx_host, CONFIG["mx"]["username"], CONFIG["mx"]["password"])

    # Retrieve site tree data structure
    siteTree = ss.getSiteTree(mx_host, session_id)
    # print(json.dumps(siteTree))
    
    # Creating policy dependencies: table groups, ip groups
    dataset_path = "export/datasets/"
    for datasetFile in os.popen('ls '+dataset_path).readlines():
        try:
            f = open(dataset_path+datasetFile.strip(), 'r', encoding='utf-8-sig')
            datasetObj = json.loads(f.read())
        except:
            print("error parsing file '"+dataset_path+datasetFile.strip()+"'")        
        print("Upserting table group '"+datasetObj["name"]+"'")
        responseObj = ss.upsertDataset(mx_host, session_id, datasetObj["obj"])

    ipgroups_path = "export/ipgroups/"
    for ipgroupFile in os.popen('ls '+ipgroups_path).readlines():
        try:
            f = open(ipgroups_path+ipgroupFile.strip(), 'r', encoding='utf-8-sig')
            ipgroupObj = json.loads(f.read())
        except:
            print("error parsing file '"+ipgroups_path+ipgroupFile.strip()+"'")
        print("Upserting IP group '"+ipgroupObj["name"]+"'")
        responseObj = ss.upsertIPGroup(mx_host, session_id, ipgroupObj["obj"])

    ## Load policies from csv
    policies = ss.ParseCsvWafPolicies(CSV_FILE_PATH)
    # Hydrate siteTree object with policies initializing each policy to false/unapplied
    for policy_name in policies:
        policy = policies[policy_name]
        if (policy["policy_level"].lower()=="network"):
            for site_name in siteTree:
                site = siteTree[site_name]
                for server_group_name in site["serverGroups"]:
                    site["serverGroups"][server_group_name]["policies"][policy_name] = {
                        "policy_level":policy["policy_level"],
                        "policy_type":policy["policy_type"],
                        "applied":False
                    }
        elif (policy["policy_level"].lower()=="web service"):
            for site_name in siteTree:
                site = siteTree[site_name]
                for server_group_name in site["serverGroups"]:
                    serverGroup = site["serverGroups"][server_group_name]
                    for service_name in serverGroup["services"]:
                        serverGroup["services"][service_name]["policies"][policy_name] = {
                            "policy_level":policy["policy_level"],
                            "policy_type":policy["policy_type"],
                            "applied":False
                        }
        elif (policy["policy_level"].lower()=="web application"):
            for site_name in siteTree:
                site = siteTree[site_name]
                for server_group_name in site["serverGroups"]:
                    serverGroup = site["serverGroups"][server_group_name]
                    for service_name in serverGroup["services"]:
                        service = serverGroup["services"][service_name]
                        for application_name in service["applications"]:
                            service["applications"][application_name]["policies"][policy_name] = {
                                "policy_level":policy["policy_level"],
                                "policy_type":policy["policy_type"],
                                "applied":False
                            }
        else:
            print("Unsupported policy type '"+policy["policy_level"]+"' for policy '"+policy_name+"'")
    
    # Check to see if policies exist
    # Create if the policy is missing, else check applyTo to set policy in siteTree
    for policy_name in policies:
        policy = policies[policy_name]
        policy["applyTo"] = []
        if policy["policy_type"] in ss.policyMapping:
            policyResponse = ss.makeCall(mx_host, session_id, "/conf/policies/security/" + ss.policyMapping[policy["policy_type"]] + "/" + policy_name)
            if (policyResponse.status_code==200):
                policy["exists"] = True
                policyResponseObj = policyResponse.json()
                for applyTo in policyResponseObj["applyTo"]:
                    if "webApplicationName" in applyTo:
                        site_name = applyTo["siteName"]
                        server_group_name = applyTo["serverGroupName"]
                        service_name = applyTo["webServiceName"]
                        application_name = applyTo["webApplicationName"]
                        siteTree[site_name]["serverGroups"][server_group_name]["services"][service_name]["applications"][application_name]["policies"][policy_name]["applied"] = True
                    elif "webServiceName" in applyTo:
                        site_name = applyTo["siteName"]
                        server_group_name = applyTo["serverGroupName"]
                        service_name = applyTo["webServiceName"]
                        siteTree[site_name]["serverGroups"][server_group_name]["services"][service_name]["policies"][policy_name]["applied"] = True
                    else:
                        site_name = applyTo["siteName"]
                        server_group_name = applyTo["serverGroupName"]
                        siteTree[site_name]["serverGroups"][server_group_name]["policies"][policy_name]["applied"] = True
            elif(policyResponse.status_code==406):
                policy["exists"] = False
                policy_path = 'export/policies/'
                print("Policy '"+policy_name+"' not found, creating base policy not applied to any assets")
                try:
                    f = open(policy_path+policy_name.replace("/","_")+".json", 'r', encoding='utf-8-sig')
                    curPolicyObj = json.loads(f.read())
                    # Creating base policy in block mode, and empty applyTo array
                    curPolicyObj["obj"]["applyTo"] = []
                    createResponse = ss.makeCall(mx_host, session_id, "/conf/policies/security/" + ss.policyMapping[curPolicyObj["type"]] + "/" + policy_name,"POST",json.dumps(curPolicyObj["obj"]))
                except:
                    print("error parsing file '"+policy_path+policy_name.replace("/","_")+".json'")
                
            else:
                print("API Error - (status_code:"+str(policyResponse.status_code)+" "+json.dumps(policyResponse.json()))
        else: 
            print("Unsupported policy type '"+policy["policy_type"]+"' for policy '"+policy_name+"'")

    for site_name in siteTree:
        site = siteTree[site_name]
        for server_group_name in site["serverGroups"]:
            serverGroup = site["serverGroups"][server_group_name]            
            for sg_policy_name in serverGroup["policies"]:
                cur_sg_policy = serverGroup["policies"][sg_policy_name]
                if (cur_sg_policy["applied"]==False):
                    policies[sg_policy_name]["applyTo"].append({
                        "operation":"add",
                        "siteName": site_name,
                        "serverGroupName": server_group_name
                    })
            for service_name in serverGroup["services"]:
                service = serverGroup["services"][service_name]
                for svc_policy_name in service["policies"]:
                    cur_svc_policy = service["policies"][svc_policy_name]
                    if (cur_svc_policy["applied"]==False):
                        policies[svc_policy_name]["applyTo"].append({
                            "operation":"add",
                            "siteName": site_name,
                            "serverGroupName": server_group_name,
                            "webServiceName": service_name
                        })
                for application_name in service["applications"]:
                    application = service["applications"][application_name]
                    for app_policy_name in application["policies"]:
                        cur_app_policy = application["policies"][app_policy_name]
                        if (cur_app_policy["applied"]==False):
                            policies[policy_name]["applyTo"].append({
                                "operation":"add",
                                "siteName": site_name,
                                "serverGroupName": server_group_name,
                                "webServiceName": service_name,
                                "webApplicationName": application_name
                            })
    
    # Iterate through policies, and if any site tree assets found that did not have this policy applied, create alert only version and apply to missing assets
    for policy_name in policies:
        curPolicyObj = policies[policy_name]
        if (len(curPolicyObj["applyTo"])>0):
            if curPolicyObj["policy_type"] in ss.policyMapping:
                print("Creating policy '"+policy_name+"_alertonly', setting action to none, and applying to site tree assets missing this policy")
                createResponse = ss.makeCall(mx_host, session_id, "/conf/policies/security/"+ss.policyMapping[curPolicyObj["policy_type"]] + "/" + policy_name+"_alertonly","POST",json.dumps({"cloneFrom":policy_name}))
                getPolicyResponse = ss.makeCall(mx_host, session_id, "/conf/policies/security/"+ss.policyMapping[curPolicyObj["policy_type"]] + "/" + policy_name+"_alertonly")
                getPolicyResponseObj = getPolicyResponse.json()
                if "rules" in getPolicyResponseObj:
                    for rule in getPolicyResponseObj["rules"]:
                        rule["action"] = "none"
                    updateObj = {
                        "rules":getPolicyResponseObj["rules"],
                        "applyTo":curPolicyObj["applyTo"]
                    }
                else:
                    updateObj = {
                        "action":"none",
                        "applyTo":curPolicyObj["applyTo"]
                    }
                updateResponse = ss.makeCall(mx_host, session_id, "/conf/policies/security/"+ss.policyMapping[curPolicyObj["policy_type"]] + "/" + policy_name+"_alertonly","PUT",json.dumps(updateObj))
            
if __name__ == '__main__':
    run()