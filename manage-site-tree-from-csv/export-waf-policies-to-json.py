#!/usr/bin/env python

import ss
import sys
import json
import csv
import logging
import urllib
import requests
from requests.utils import requote_uri
import os

############ ENV Settings ############
logging.basicConfig(filename='export_waf_policies_to_json.log', filemode='w', format='%(name)s - %(levelname)s - %(message)s')

############ GLOBALS ############
CONFIGFILE = 'config.json'
CONFIG = {}
DATASETS = {}
SIGNATURES = {}
IPGROUPS = {}
ALLPOLICIES = {}

try:
    with open(CONFIGFILE, 'r') as data:
        CONFIG = json.load(data)
except:
    print("Missing \""+CONFIGFILE+"\" file, create file named \""+CONFIGFILE+"\" with the following contents:\n{\n\t\"log_level\": \"debug\",\n\t\"log_file_name\": \"gateway_statistics.log\",\n\t\"environment\": \"dev\",\n\t\"is_userspace\":false,\n\t\"environment\": \"dev\",\n\t\"log_search\": {\n\t\t\"enabled\": true,\n\t\t\"files\": [{\n\t\t\t\"path\": \"/var/log/messages\",\n\t\t\t\"search_patterns\": [{\n\t\t\t\t\t\"name\":\"YOUR_EVENT_NAME\",\n\t\t\t\t\t\"pattern\":\"some text pattern\"\n\t\t\t\t}, {\n\t\t\t\t\t\"name\":\"YOUR_EVENT_NAME_2\",\n\t\t\t\t\t\"pattern\":\"some other text pattern\"\n\t\t\t\t}\n\t\t\t]\n\t\t}]\n\t},\n\t\"newrelic\": {\n\t\t\"enabled\": false,\n\t\t\"account_id\": \"ACCOUNT_ID\",\n\t\t\"api_key\": \"API_KEY\",\n\t\t\"event_type\": \"GWStats\"\n\t},\n\t\"influxdb\": {\n\t\t\"enabled\": true,\n\t\t\"host\": \"http://1.2.3.4:8086/write?db=imperva_performance_stats\"\n\t},\n\t\"syslog\": {\n\t\t\"enabled\": true,\n\t\t\"host\": \"1.2.3.4\",\n\t\t\"port\": 514\n\t}\n}")
    exit()

if len(sys.argv)<2:
	print("[ERROR] Missing argument, please specify the path to the csv to import. \n  Example: python export-waf-policies-to-json.py /path/to/my_waf_policies.csv")
	logging.warning("[ERROR] Missing argument, please specify the path to the csv to import. Example: python export-waf-policies-to-json.py /path/to/my_waf_policies.csv")
	quit()

# Parse CSV into dictionary with policy type and applied to assets
logging.warning("\n\n===========  Start WAF policy export ===========\n")
logging.warning('CSV_FILE_PATH='+sys.argv[1])
# Example argv[1] = /WEB-INF/reptemp/Sync_Security_Policies_Report_admin_15Apr2019_04-40-59.csv (all policies)
# Example argv[1] = /WEB-INF/reptemp/Sync_Security_Policies_Report_admin_15Apr2019_05-25-06.csv (web policies)

try:
    CSV_FILE_PATH = sys.argv[1]
except:
    print('Path to csv is missing, please specify a path to csv file you are looking to import. Example: python export-waf-policies-to-json.py "path/to/yourfile.csv"')
    exit()

# with open(CONFIGFILE, 'r') as f:
	# reader = csv.reader(f)
	# for row in reader:
	# 	if row[0] != "Policy Name":
	# 		sourcePolicies[row[0]] = {"policyType": row[1]}
sourcePolicies = ss.ParseCsvWafPolicies(CSV_FILE_PATH)

def run():
	mx_host = CONFIG["mx"]["endpoint"]
	session_id = ss.login(mx_host, CONFIG["mx"]["username"], CONFIG["mx"]["password"])
	# Iterate through each policy and pull out normalized list of datasets, ipGroups, and signatures
	for policy_name in sourcePolicies:
		policy_attr = sourcePolicies[policy_name]
		policy_type = policy_attr["policy_type"]
		if policy_type in ss.policyMapping:
			policy_resource = ss.policyMapping[policy_type]
			#print(ss.policyMapping[policyAttr["policyType"]])
			logging.warning("Retrieving policy_type \""+policy_type+"\" policy_name \""+policy_name+"\" from MX - REQUEST: \nGET /conf/policies/security/"+ss.policyMapping[policy_type]+"/"+policy_name)
			response = ss.makeCall(mx_host, session_id, "/conf/policies/security/"+ss.policyMapping[policy_type]+"/"+requote_uri(policy_name))
			if response.status_code==404:
				policy_attr["isok"] = False
			else:
				policyObj = response.json()
				ALLPOLICIES[policy_name] = policyObj
				policy_attr["policy_obj"] = policyObj
				policy_attr["isok"] = True
				logging.warning("RESPONSE: \n"+str(policyObj))
				# No API call for Anti-scraping, Network Protocol Validation, ATO Cloud Protection, OCSP Protocol Validation, ATO Dictionary Protection, Bot Mitigation, Cookie Signing Validation, or web worm policies
				# firewallPolicies
				# httpProtocolPolicies
				# http2ProtocolPolicies
				# webCorrelationPolicies
				# snippetInjectionPolicies
				# webApplicationSignaturesPolicies - signatures in predicates and exceptiosn
				# httpProtocolSignaturesPolicies
				# snippetInjectionPolicies
				# streamSignaturesPolicies
				# webApplicationSignaturesPolicies
				# webProfilePolicies

				# check for rules->ipGroup in firewallPolicies
				if "rules" in policyObj:
					for rule in policyObj["rules"]:
						if "ipGroup" in rule:
							if rule["ipGroup"] not in ss.ignoreADCIpGroups:
								# print("Capturing IPGroup \"" + rule["ipGroup"] + "\" for policy " + policy_name)
								logging.warning("Capturing IPGroup \"" + rule["ipGroup"] + "\" for policy " + policy_name)
								IPGROUPS[rule["ipGroup"]] = False
							else:
								# print("Ignoring IPGroup \"" + rule["ipGroup"] + "\" for policy " + policy_name)
								logging.warning("Ignoring IPGroup \"" + rule["ipGroup"] + "\" for policy " + policy_name)
				# IPGROUPS[ipGroup] = ss.getIPGroup(AUTH["ENDPOINT"], primary_session_id, ipGroup)

				# check for exceptions->predicates->ipGroups in httpProtocolPolicies, http2ProtocolPolicies, webCorrelationPolicies, snippetInjectionPolicies
				if "exceptions" in policyObj:
					for exception in policyObj["exceptions"]:
						if "predicates" in exception:
							for predicate in exception["predicates"]:
								if "ipGroups" in predicate:
									for ipGroup in predicate["ipGroups"]:
										if ipGroup not in ss.ignoreADCIpGroups:
											# print("Capturing IPGroup \"" + ipGroup + "\" for policy " + policy_name)
											logging.warning("Capturing IPGroup \"" + ipGroup + "\" for policy " + policy_name)
											IPGROUPS[ipGroup] = False
										else:
											# print("Ignoring IPGroup \"" + ipGroup + "\" for policy " + policy_name)
											logging.warning("Ignoring IPGroup \"" + ipGroup + "\" for policy " + policy_name)
				# check matchCriteria - webApplicationCustomPolicies, webServiceCustomPolicies
				if "matchCriteria" in policyObj:
					for mc in policyObj["matchCriteria"]:
						# matchCriteria->lookupDatasetSearch->searchInLookupDataset
						# matchCriteria->enrichmentData->searchInLookupDataset
						if mc["type"] == "lookupDatasetSearch" or mc["type"] == "enrichmentData":
							if "searchInLookupDataset" in mc:
								for dataset in mc["searchInLookupDataset"]:
									# print("Capturing lookupDatasetSearch dataset \"" + dataset + "\" for policy " + policy_name)
									logging.warning("Capturing enrichmentData searchInLookupDataset dataset \"" + dataset + "\" for policy " + policy_name)
									DATASETS[dataset] = False
							if "lookupDatasetSearch" in mc:
								for dataset in mc["lookupDatasetSearch"]:
									# print("Capturing lookupDatasetSearch dataset \"" + dataset + "\" for policy " + policy_name)
									logging.warning("Capturing lookupDatasetSearch dataset \"" + dataset + "\" for policy " + policy_name)
									DATASETS[dataset] = False
								# DATASETS[dataset] = ss.getDataset(AUTH["ENDPOINT"], primary_session_id, dataset)
						# matchCriteria->datasetAttributeLookup[]->searchInLookupDataset
						elif mc["type"] == "datasetAttributeLookup":
							for dataset in mc["searchInLookupDataset"]:
								if dataset not in ss.ignoreADCDatasets:
									# print("Capturing searchInLookupDataset dataset \"" + dataset + "\" for policy " + policy_name)
									logging.warning("Capturing searchInLookupDataset dataset \"" + dataset + "\" for policy " + policy_name)
									DATASETS[dataset] = False
								else:
									# print("Ignoring dataset \"" + dataset + "\" for policy " + policy_name)
									logging.warning("Capturing dataset \"" + dataset + "\" for policy " + policy_name)
									# DATASETS[dataset] = ss.getDataset(AUTH["ENDPOINT"], primary_session_id, dataset)
									# logging.warning("Retrieving \""+dataset+"\" dataset for policy "+policy_name)
							# matchCriteria->datasetAttributeLookup->lookupDataset
							if dataset not in ss.ignoreADCDatasets:
								# print("Capturing lookupDataset dataset \"" + mc["lookupDataset"] + "\" for policy " + policy_name)
								logging.warning("Capturing lookupDataset dataset \"" + mc["lookupDataset"] + "\" for policy " + policy_name)
								DATASETS[mc["lookupDataset"]] = False
							else:
								# print("Ignoring lookupDataset dataset \"" + mc["lookupDataset"] + "\" for policy " + policy_name)
								logging.warning("Ignoring lookupDataset dataset \"" + mc["lookupDataset"] + "\" for policy " + policy_name)
							# DATASETS[mc["lookupDataset"]] = ss.getDataset(AUTH["ENDPOINT"], primary_session_id, mc["lookupDataset"])
							# logging.warning("Retrieving \"" + mc["lookupDataset"] + "\" dataset for policy " + policy_name)
						elif mc["type"] == "signatures":
							# sourcePolicies[policy_name]["isok"] = False
							for signature in mc["signatures"]:
								policy_attr["isok"] = False
								SIGNATURES[signature["name"]] = False
								logging.warning("Retrieving \""+signature["name"]+"\" signature for policy "+policy_name)
								# print(mc["type"])
						# matchCriteria->sourceIpAddresses[]
						# matchCriteria->proxyIpAddresses[]
						elif mc["type"] == "sourceIpAddresses" or mc["type"] == "proxyIpAddresses":
							for ipGroup in mc["ipGroups"]:
								if ipGroup not in ss.ignoreADCIpGroups:
									# print("Capturing sourceIpAddresses ipGroup \"" + ipGroup + "\" for policy " + policy_name)
									logging.warning("Capturing sourceIpAddresses ipGroup \"" + ipGroup + "\" for policy " + policy_name)
									IPGROUPS[ipGroup] = False
								else:
									# print("Ignoring sourceIpAddresses ipGroup \"" + ipGroup + "\" for policy " + policy_name)
									logging.warning("Ignoring sourceIpAddresses ipGroup \"" + ipGroup + "\" for policy " + policy_name)
								# logging.warning("Retrieving IPGroup ("+ipGroup+") for policy " + policy_name)
								# IPGROUPS[ipGroup] = ss.getIPGroup(AUTH["ENDPOINT"], primary_session_id, ipGroup)
		else:
			policy_attr["isok"] = False
			print("Unsupported policy type \"" + policy_type + "\", skipping policy policy \"" + policy_name + "\"")
			logging.warning("Unsupported policy type \"" + policy_type + "\", skipping policy policy \"" + policy_name + "\"")

	# load normalized list of datasets
	for dataset in DATASETS:
		logging.warning("Retrieving \"" + dataset + "\" dataset")
		DATASETS[dataset] = ss.getDataset(mx_host, session_id, dataset)

	# load normalized list of ipGroups
	for ipGroup in IPGROUPS:
		IPGROUPS[ipGroup] = ss.getIPGroup(mx_host, session_id, ipGroup)

	# signatures are not supported at this time, no method of retrieving list of signatures from system stream signatures

	# Export each to disk in json format
	os.makedirs("export/datasets",exist_ok = True)
	for dataset_name in DATASETS:
		ss.WriteFile("export/datasets/"+dataset_name.replace("/","_")+".json", json.dumps({"name":dataset_name,"obj":DATASETS[dataset_name]}))
	
	os.makedirs("export/signatures",exist_ok = True)
	for signatures_name in SIGNATURES:
		ss.WriteFile("export/signatures/"+signatures_name.replace("/","_")+".json", json.dumps({"name":signatures_name,"obj":SIGNATURES[signatures_name]}))

	os.makedirs("export/ipgroups",exist_ok = True)
	for ipgroup_name in IPGROUPS:
		ss.WriteFile("export/ipgroups/"+ipgroup_name.replace("/","_")+".json", json.dumps({"name":ipgroup_name,"obj":IPGROUPS[ipgroup_name]}))

	os.makedirs("export/policies",exist_ok = True)
	for policy_name in ALLPOLICIES:
		ss.WriteFile("export/policies/"+policy_name.replace("/","_")+".json", json.dumps({"name":policy_name,"obj":ALLPOLICIES[policy_name]}))
	
if __name__ == '__main__':
	run()


