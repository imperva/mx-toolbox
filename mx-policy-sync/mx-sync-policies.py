#!/usr/bin/env python

import ss
import sys
import json
import csv
import logging
import urllib

############ ENV Settings ############
logging.basicConfig(filename='mx-sync.log', filemode='w', format='%(name)s - %(levelname)s - %(message)s')

############ GLOBALS ############
sourcePolicies = {}
AUTH = {}
try:
	with open('config.json', 'r') as data:
		AUTH = json.load(data)
except:
	logging.warning("Missing \"config.json\" file, create file named config.json with the following contents:\n{\n\t\"ENDPOINT\": \"https://127.0.0.1:8083\",\n\t\"REGION\": \"us-east-1\",\n\t\"USERNAME\": \"admin\",\n\t\"PASSWORD\": \"yourpassword\"\n}")
	exit()
MX_SYNC_DATASET = '{"dataset-name":"mx_sync_log","columns":[{"name":"key","key":true},{"name":"type","key":false},{"name":"name","key":false},{"name":"status","key":false},{"name":"timestamp","key":false}]}'
MX_SYNC_LOG_RECORDS = {"records": []}
AWSREGIONS = ["us-west-1"]

MXs = ss.get_mx_instances_by_tagname('impv', 'mx-sync', AWSREGIONS)

DATASETS = {}
SIGNATURES = {}
IPGROUPS = {}
ALLPOLICIES = {}

# Parse CSV into dictionary with policy type and applied to assets
logging.warning("\n\n===========  Start MX policy sync ===========\n")
logging.warning('PATH2REPORT='+sys.argv[1])
PATH2REPORT = '/opt/SecureSphere/server/SecureSphere/jakarta-tomcat-secsph/webapps/SecureSphere/'+sys.argv[1]
# Example argv[1] = /WEB-INF/reptemp/Sync_Security_Policies_Report_admin_15Apr2019_04-40-59.csv (all policies)
# Example argv[1] = /WEB-INF/reptemp/Sync_Security_Policies_Report_admin_15Apr2019_05-25-06.csv (web policies)

with open(PATH2REPORT, 'r') as f:
	reader = csv.reader(f)
	for row in reader:
		if row[0] != "Policy Name":
			sourcePolicies[row[0]] = {"policyType": row[1]}

def run():
	primary_session_id = ss.login(AUTH["ENDPOINT"], AUTH["USERNAME"], AUTH["PASSWORD"])
	ss.initMxSyncLog(AUTH["ENDPOINT"], primary_session_id, MX_SYNC_DATASET)
	# Iterate through each policy and pull out normalized list of datasets, ipGroups, and signatures
	for policy_name in sourcePolicies:
		policyAttr = sourcePolicies[policy_name]
		if policyAttr["policyType"] in ss.policyMapping:
			#print(ss.policyMapping[policyAttr["policyType"]])
			logging.warning("Retrieving policyType \""+policyAttr["policyType"]+"\" policyName \""+policy_name+"\" from primary MX - REQUEST: \nGET /conf/policies/security/"+ss.policyMapping[policyAttr["policyType"]]+"/"+policy_name)
			response = ss.makeCall(AUTH["ENDPOINT"], primary_session_id, "/conf/policies/security/"+ss.policyMapping[policyAttr["policyType"]]+"/"+urllib.quote(policy_name))
			if response.status_code==404:
				policyAttr["isok"] = False
			else:
				policyObj = response.json()
				ALLPOLICIES[policy_name] = policyObj
				sourcePolicies[policy_name]["config.json"] = policyObj
				sourcePolicies[policy_name]["isok"] = True
				logging.warning("RESPONSE: \n"+str(policyObj))
				# No API call for anti-scraping
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
				curPolicyType = ss.policyMapping[policyAttr["policyType"]]
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
							for dataset in mc["searchInLookupDataset"]:
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
							sourcePolicies[policy_name]["isok"] = False
							# 	for signature in mc["signatures"]:
							# 		sourcePolicies[policy_name]["isok"] = False
							# 		SIGNATURES[signature["name"]] = False
							# 		logging.warning("Retrieving \""+signature["name"]+"\" signature for policy "+policy_name)
							# 	# print(mc["type"])
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
			policyAttr["isok"] = False
			logging.warning("Unsupported policy type \"" + policyAttr["policyType"] + "\", skipping policy policy \"" + policy_name + "\"")

	# load normalized list of datasets
	for dataset in DATASETS:
		logging.warning("Retrieving \"" + dataset + "\" dataset")
		DATASETS[dataset] = ss.getDataset(AUTH["ENDPOINT"], primary_session_id, dataset)
	# load normalized list of ipGroups
	for ipGroup in IPGROUPS:
		IPGROUPS[ipGroup] = ss.getIPGroup(AUTH["ENDPOINT"], primary_session_id, ipGroup)

	for MX in MXs:
		cur_session_id = ss.login(MX["ENDPOINT"], AUTH["USERNAME"], AUTH["PASSWORD"])
		# Migrate datasets
		for dataset in DATASETS:
			MX_SYNC_LOG_RECORDS["records"].append(ss.upsertDataset(MX["ENDPOINT"], cur_session_id, DATASETS[dataset]))
		for ipGroup in IPGROUPS:
			MX_SYNC_LOG_RECORDS["records"].append(ss.upsertIPGroup(MX["ENDPOINT"], cur_session_id, IPGROUPS[ipGroup]))

		for policy_name in sourcePolicies:
			policyAttr = sourcePolicies[policy_name]
			try:
				if policyAttr["policyType"] in ss.policyMapping:
					#print(ss.policyMapping)
					for asset in policyAttr["config.json"]["applyTo"]:
						asset["serverGroupName"] = asset["serverGroupName"].replace(AUTH["REGION"], MX["REGION"])
					MX_SYNC_LOG_RECORDS["records"].append(ss.upsertWebPolicy(MX["ENDPOINT"], cur_session_id, policy_name, policyAttr))
			except KeyError as e:
				logging.warning("KeyError:"+str(e))

		ss.logout(MX["ENDPOINT"], cur_session_id)
	datasetObj = json.loads(MX_SYNC_DATASET)
	ss.makeCall(AUTH["ENDPOINT"], primary_session_id, "/conf/dataSets/" + datasetObj["dataset-name"] + "/data", "POST", json.dumps(MX_SYNC_LOG_RECORDS))
	ss.logout(AUTH["ENDPOINT"], primary_session_id)

if __name__ == '__main__':
	run()


