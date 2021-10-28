import json
import requests
import base64
import logging
from time import localtime, strftime
import csv
import distutils
from distutils import util

PREFIX = "/SecureSphere/api/v1"

policyMapping = {
	"Firewall Policy": "firewallPolicies",
	"HTTP Protocol Signatures": "httpProtocolSignaturesPolicies",
	"HTTP/1.x Protocol Validation": "httpProtocolPolicies",
	"HTTP/2 Protocol Validation": "http2ProtocolPolicies",
	"Snippet Injection": "snippetInjectionPolicies",
	"Stream Signature": "streamSignaturesPolicies",   
	"Web Application Custom": "webApplicationCustomPolicies",
	"Web Application Signatures": "webApplicationSignaturesPolicies",
	"Web Profile": "webProfilePolicies",
	"Web Service Correlated Validation": "webCorrelationPolicies",
	"Web Service Custom": "webServiceCustomPolicies"
}

ignoreADCDatasets = {
	"ThreatRadar - Anonymous Proxies": True,
	"ThreatRadar - Comment Spam IPs": True,
	"ThreatRadar - Malicious IPs": True,
	"ThreatRadar - Phishing URLs": True,
	"ThreatRadar - SQL Injection IPs": True,
	"ThreatRadar - Scanner IPs": True,
	"ThreatRadar - TOR IPs": True
}

ignoreADCIpGroups = {
	"AOL IP Addresses": True,
	"All Search Engines": True,
	"Allowed IP Addresses": True,
	"Ask IP Addresses": True,
	"Baidu IP Addresses": True,
	"Bing IP Addresses": True,
	"Cloud WAF (Incapsula) IP Addresses": True,
	"FireEye Trusted Appliances": True,
	"Google IP Addresses": True,
	"Internal IP Addresses": True,
	"PeopleSoft Machines IP Addresses": True,
	"Yahoo IP Addresses": True,
	"Yandex IP Addresses": True
}

def initSettigs():
	# disable insecure requests for typically configured self-signed MX cert
	try:
		from requests.packages.urllib3.exceptions import InsecureRequestWarning
		requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
	except:
		pass
	try:
		from requests.packages.urllib3.exceptions import InsecurePlatformWarning
		requests.packages.urllib3.disable_warnings(InsecurePlatformWarning)
	except:
		pass
	try:
		from requests.packages.urllib3.exceptions import SNIMissingWarning
		requests.packages.urllib3.disable_warnings(SNIMissingWarning)
	except:
		pass
	try:
		import urllib3
		urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
	except:
		pass

def login(mx_host,username, password):
	initSettigs()
	auth_string = '%s:%s' % (username, password)
	headers = {
		'content-type': 'application/json',
		'Authorization': 'Basic ' + base64.b64encode(auth_string.encode('utf-8')).decode('utf-8')
	}
	auth_url = '/auth/session'
	logging.warning("Logging into MX: POST "+mx_host+PREFIX+auth_url)
	try:
		response = requests.post(mx_host+PREFIX+auth_url, {}, headers=headers, verify=False)
		if not response:
			logging.warning("Failed login request, no response from server")
			exit()
		try:
			responseObj = response.json()
			logging.warning("Successful login. auth="+base64.b64encode(auth_string.encode('utf-8')).decode('utf-8')+" Response code: "+str(response.status_code)+", SESSIONID: "+str(responseObj['session-id']))
			return responseObj['session-id']
		except Exception as e:
			logging.warning("Failed login request - "+str(e))
			exit()
	except Exception as e:
		logging.warning("Failed login request - "+str(e))
		exit()

def logout(mx_host, session_id):
	initSettigs()
	auth_url = '/auth/session'
	logging.warning("\nLogging out of MX: DELETE "+mx_host+PREFIX+auth_url)
	headers = {
		'Cookie': session_id,
		'Accept': 'application/json',
		'Content-Type': 'application/json'
	}
	try:
		response = requests.delete(mx_host+PREFIX+auth_url, headers=headers, verify=False)
		if response.status_code != 200:
			logging.warning("Failed to log out of MX ("+mx_host+PREFIX+auth_url+") - RESPONSE CODE: "+str(response.status_code)+"\nRESPONSE: "+str(response.text))
		try:
			logging.warning("\nSuccessfully Logged out of MX ("+mx_host+PREFIX+auth_url+") - RESPONSE CODE: "+str(response.status_code))
		except Exception as e:
			logging.warning("Failed logout request for MX ("+mx_host+") and SESSIONID ("+session_id+") - "+str(e))
	except Exception as e:
		logging.warning("Failed logout request for MX (" + mx_host + ") and SESSIONID (" + session_id + ") - " + str(e))

def makeCall(mx_host, session_id, action, method="GET", data=None):
	initSettigs()
	url = mx_host+PREFIX+action
	headers = {
		'Cookie': session_id,
		'Accept': 'application/json',
		'Content-Type': 'application/json'
	}
	if data == None:
		content = None
	else:
		content = data.encode("utf-8")
	try:
		if method == 'POST':
			logging.warning("curl -ik -X POST -H \"Cookie: "+session_id+"\" -H \"Content-Type: application/json\" -H \"Accept: application/json\" -d '"+data+"' '"+mx_host+PREFIX+requests.utils.quote(action)+"'")
			response = requests.post(url, content, headers=headers, verify=False)
		elif method == 'GET':
			logging.warning("curl -ik -X GET -H \"Cookie: "+session_id+"\" -H \"Content-Type: application/json\" -H \"Accept: application/json\" '"+mx_host+PREFIX+requests.utils.quote(action)+"'")
			response = requests.get(url, headers=headers, verify=False)
		elif method == 'DELETE':
			logging.warning("curl -ik -X DELETE -H \"Cookie: "+session_id+"\" -H \"Content-Type: application/json\" -H \"Accept: application/json\" '"+mx_host+PREFIX+requests.utils.quote(action)+"'")
			response = requests.delete(url, headers=headers, verify=False)
		elif method == 'PUT':
			logging.warning("curl -ik -X PUT -H \"Cookie: "+session_id+"\" -H \"Content-Type: application/json\" -H \"Accept: application/json\" -d '"+data+"' '"+mx_host+PREFIX+requests.utils.quote(action)+"'")
			response = requests.put(url, content, headers=headers, verify=False)
		if response.status_code == 404:
			logging.warning("API ERROR (" + method + " " + url + ") status code: "+str(response.status_code))
		elif response.status_code != 200:
			logging.warning("API ERROR (" + method + " " + url + ") "+str(response.status_code)+" | response: "+json.dumps(response.json()))
		else:
			logging.warning("API RESPONSE (" + method + " " + url + ") status code: "+str(response.status_code))
		return response
	except Exception as e:
		logging.warning("ERROR - "+str(e))

def initMxSyncLog(mx_host, session_id, dataset):
	datasetObj = json.loads(dataset)
	logging.warning("\nChecking for dataset (" + datasetObj["dataset-name"] + ") on MX (" + mx_host + ")")
	colResponse = makeCall(mx_host, session_id, "/conf/dataSets/" + datasetObj["dataset-name"] + "/columns")
	if colResponse.status_code != 200:
		makeCall(mx_host, session_id, "/conf/dataSets/createDataset?caseSensitive=false", "POST", dataset)

def getDataset(mx_host, session_id, dataset_name):
	colResponse = makeCall(mx_host, session_id, "/conf/dataSets/" + dataset_name + "/columns")
	dataResponse = makeCall(mx_host, session_id, "/conf/dataSets/" + dataset_name + "/data")
	dataset = {
		"name": dataset_name,
		"schema": colResponse.json(),
		"data": dataResponse.json()
	}
	return dataset

def upsertDataset(mx_host, session_id, datasetObj):
	logging.warning("\nChecking for dataset (" + datasetObj["name"] + ") on MX (" + mx_host + ")")
	colResponse = makeCall(mx_host, session_id, "/conf/dataSets/" + datasetObj["name"] + "/columns")
	# check to see if dataset exists
	if colResponse.status_code == 406:
		logging.warning("\nNo dataset found for (" + datasetObj["name"] + ") on MX (" + mx_host + "), creating and populating dataset")
		makeCall(mx_host, session_id, "/conf/dataSets/createDataset?caseSensitive=false", "POST", json.dumps(datasetObj["schema"]))
		response = makeCall(mx_host, session_id, "/conf/dataSets/" + datasetObj["name"] + "/data", "POST", json.dumps({"records": datasetObj["data"]["records"]}))
		if response.status_code==200:
			status = "Success ("+str(response.status_code)+")"
		else:
			status = "failed ("+str(response.status_code)+") "
	else:
		colResponseObj = colResponse.json()
		if colResponseObj["columns"] == datasetObj["schema"]["columns"]:
			logging.warning("\nFound dataset (" + datasetObj["name"] + ") on MX ("+mx_host+"), updating data only.")
			response = makeCall(mx_host, session_id, "/conf/dataSets/" + datasetObj["name"] + "/data", "POST", json.dumps({"records":datasetObj["data"]["records"]}))
			if response.status_code==200:
				status = "Success ("+str(response.status_code)+")"
			else:
				status = "Failed ("+str(response.status_code)+") "
		else:
			logging.warning("\nDataset schema does not match, deleting dataset (" + datasetObj["name"] + ") attempting to delete and recreate on MX (" + mx_host + ")")
			deleteResponse = makeCall(mx_host, session_id, "/conf/dataSets/"+datasetObj["name"]+"/deleteDataset", "POST",json.dumps({}))
			if deleteResponse.status_code==200:
				createResponse = makeCall(mx_host, session_id, "/conf/dataSets/createDataset?caseSensitive=false", "POST", json.dumps(datasetObj["schema"]))
				if createResponse.status_code == 200:
					dataResponse = makeCall(mx_host, session_id, "/conf/dataSets/" + datasetObj["name"] + "/data", "POST", json.dumps({"records": datasetObj["data"]["records"]}))
					if dataResponse.status_code == 200:
						status = "Success (" + str(dataResponse.status_code) + ")"
					else:
						status = "Failed (" + str(dataResponse.status_code) + ") "
				else:
					status = "Failed (" + str(createResponse.status_code) + ") "
			else:
				deleteResponseObj = deleteResponse.json()
				status = "Failed ("+str(deleteResponse.status_code)+") "+str(deleteResponseObj["errors"][0]["description"])
	return {
		"key": mx_host + "_|_dataset_|_" + datasetObj["name"],
		"type": "dataset",
		"name": datasetObj["name"],
		"status": status,
		"timestamp": strftime("%Y/%m/%d %H:%M:%S", localtime())
	}

def getIPGroup(mx_host, session_id, ip_group):
	dataResponse = makeCall(mx_host, session_id, "/conf/ipGroups/"+str(ip_group)+"/data")
	return {
		"name": ip_group,
		"data": dataResponse.json()
	}

def upsertIPGroup(mx_host, session_id, ipGroupObj):
	logging.warning("\nChecking for ipGroup (" + ipGroupObj["name"] + ") on MX (" + mx_host + ")")
	dataResponse = makeCall(mx_host, session_id, "/conf/ipGroups/"+str(ipGroupObj["name"])+"/data")
	dataResponseObj = dataResponse.json()
	# check to see if ipGroup exists
	if dataResponse.status_code == 406:
		logging.warning("\nNo ipGroup found for (" + ipGroupObj["name"] + ") on MX (" + mx_host + "), attempting to create and populate ipGroup - "+json.dumps(ipGroupObj["data"]))
		createresponse = makeCall(mx_host, session_id, "/conf/ipGroups/"+ipGroupObj["name"], "POST", json.dumps(ipGroupObj["data"]))
		if createresponse.status_code == 200:
			status = "Success (" + str(createresponse.status_code) + ")"
		else:
			status = "Failed (" + str(createresponse.status_code) + ") "
	else:
		deleteresponse = makeCall(mx_host, session_id, "/conf/ipGroups/" + ipGroupObj["name"] + "/clear", "DELETE")
		if deleteresponse.status_code == 200:
			for entry in ipGroupObj["data"]["entries"]:
				entry["operation"] = "add"
			updateresponse = makeCall(mx_host, session_id, "/conf/ipGroups/" + ipGroupObj["name"],"PUT",json.dumps(ipGroupObj["data"]))
			if updateresponse.status_code == 200:
				status = "Success (" + str(updateresponse.status_code) + ")"
			else:
				status = "Failed (" + str(updateresponse.status_code) + ") "
		else:
			status = "failed (" + str(deleteresponse .status_code) + ") "
	return {
		"key": mx_host + "_|_ipGroup_|_" + ipGroupObj["name"],
		"type": "ipGroup",
		"name": ipGroupObj["name"],
		"status": status,
		"timestamp": strftime("%Y/%m/%d %H:%M:%S", localtime())
	}


def getSignature(mx_host, session_id, signature):
	print("getSignature()")
	# implement signature retrieval
	# dataResponse = makeCall(mx_host, session_id, "/conf/ipGroups/"+str(ip_group)+"/data")
	# return {
	# 	"name": ip_group,
	# 	"data": dataResponse.json()
	# }

def upsertSignature():
	print("upsertSignature()")

def upsertWebPolicy(mx_host, cur_session_id, policy_name, policyAttr):
	logging.warning("Retrieving \"" + policyAttr["policyType"] + "\" policy \"" + policy_name + "\" from primary MX - REQUEST: \nGET /conf/policies/security/" + policyMapping[policyAttr["policyType"]] + "/" + policy_name)
	if policyAttr["isok"] is True:
		# merge source and destination applyTo assets
		tmpApplyTo = {}
		getresponse = makeCall(mx_host, cur_session_id, "/conf/policies/security/" + policyMapping[policyAttr["policyType"]] + "/" + policy_name)
		if (getresponse.status_code == 200):
			logging.warning("Policy \"" + policy_name + "\" does exist, attempting to update - REQUEST: \nPUT /conf/policies/security/" + policyMapping[policyAttr["policyType"]] + "/" + policy_name)
			getresponseObj = getresponse.json()
			for asset in getresponseObj["applyTo"]:
				assetstr = str(json.dumps(asset))
				asset["operation"] = "remove"
				tmpApplyTo[assetstr] = asset
			# overwrite all applyTo sites as add in master MX policy
			for asset in policyAttr["config.json"]["applyTo"]:
				assetstr = str(json.dumps(asset))
				asset["operation"] = "add"
				tmpApplyTo[assetstr] = asset
			policyAttr["config.json"]["applyTo"] = []
			for asset in tmpApplyTo:
				policyAttr["config.json"]["applyTo"].append(tmpApplyTo[asset])

			updateresponse = makeCall(mx_host, cur_session_id, "/conf/policies/security/" + policyMapping[policyAttr["policyType"]] + "/" + policy_name, "PUT", json.dumps(policyAttr["config.json"]))
			if updateresponse.status_code == 200:
				status = "Success (" + str(updateresponse.status_code) + ")"
			else:
				status = "Failed (" + str(updateresponse.status_code) + ") "
		else:
			logging.warning("Policy \"" + policy_name + "\" does not exist, attempting to create - REQUEST: \nPUT /conf/policies/security/" + policyMapping[policyAttr["policyType"]] + "/" + policy_name)
			createresponse = makeCall(mx_host, cur_session_id, "/conf/policies/security/" + policyMapping[policyAttr["policyType"]] + "/" + policy_name, "POST", json.dumps(policyAttr["config.json"]))
			if createresponse.status_code == 200:
				status = "Success (" + str(createresponse.status_code) + ")"
			else:
				try:
					status = "Failed (" + str(createresponse.status_code) + ") " + createresponse["errors"][0]["description"]
				except:
					status = "Failed (" + str(createresponse.status_code) + ") "
	else:
		status = "Policy not migrated, contains unsupported predicates"
	return {
		"key": mx_host + "_|_"+policyMapping[policyAttr["policyType"]]+"_|_" + policy_name,
		"type": "policy - "+policyMapping[policyAttr["policyType"]],
		"name": policy_name,
		"status": status,
		"timestamp": strftime("%Y/%m/%d %H:%M:%S", localtime())
	}

def ParseCsvWafPolicies(CSV_FILE_PATH):
	policies = {}
	rowIndex = {}
	f = open(CSV_FILE_PATH, 'r', encoding='utf-8-sig')
	csvfile = f.read().split("\n")
	rows = list(csv.reader(csvfile, quotechar='"', delimiter=',', quoting=csv.QUOTE_ALL, skipinitialspace=True, dialect=csv.excel))
	
	# Parse csv headers by name/index order into associative lookup to support csv data in different column order
	for i in range(len(rows[0])):
		if (rows[0][i].strip()!=""):
			rowIndex[rows[0][i].strip().lower().replace(" ","_")] = i
	if ("policy_name" not in rowIndex or "policy_type" not in rowIndex ):
		logging.warning('[ERROR] Required fields are missing, csv must contain a minimum of the the following columns:Policy Name, and Policy Type')
		exit()
	
	for row_num in range(len(rows[1:])):
		row_num_str = str(row_num+1)
		row = rows[row_num+1]
		if (len(row)!=0):
			policy_name = row[rowIndex["policy_name"]].strip()
			policy_type = row[rowIndex["policy_type"]].strip()
			policy_level = row[rowIndex["policy_level"]].strip()
			if (policy_name not in policies): 
				policies[policy_name] = {
					"policy_level":policy_level,
					"policy_type":policy_type,
					"rules":{}
				}			
			rule_name = row[rowIndex["rule_name"]].strip()
			rule_action = row[rowIndex["rule_action"]].strip()
			rule_severity = row[rowIndex["rule_severity"]].strip()
			rule_enabled = row[rowIndex["rule_enabled"]].strip()
			policies[policy_name]["rules"][rule_name] = {
				"rule_action":rule_action,
				"rule_severity":rule_severity,
				"rule_enabled":rule_enabled
			}
			# policies.append({"policy_name":policy_name,"policy_type":policy_type})
	return policies	

def ParseCsvWaf(CSV_FILE_PATH):
	sites = {}
	rowIndex = {}
	f = open(CSV_FILE_PATH, 'r')
	csvfile = f.read().split("\n")
	rows = list(csv.reader(csvfile, quotechar='"', delimiter=',', quoting=csv.QUOTE_ALL, skipinitialspace=True))
	
	# Parse csv headers by name/index order into associative lookup to support csv data in different column order
	for i in range(len(rows[0])):
		if (rows[0][i].strip()!=""):
			rowIndex[rows[0][i].lower().replace(" ","_")] = i
	
	# Check for minimum required fields
	if ("site" not in rowIndex or "server_group" not in rowIndex or "operation_mode" not in rowIndex or "service" not in rowIndex or "application" not in rowIndex):
		logging.warning('[ERROR] Required fields are missing, csv must contain a minimum of the the following columns:\nSite, Server Group, Operation, Service, and Application')
		exit()

	# Process each row into normalized site tree object
	for row_num in range(len(rows[1:])):
		row_num_str = str(row_num+1)
		row = rows[row_num+1]
		site_name = row[rowIndex["site"]].strip()
		if (site_name==""):
			logging.warning("[WARNING] CSV Row "+row_num_str+" - Site name empty, ignoring record.")
			logging.warning("CSV Row "+row_num_str+" Data: "+str(row)+"\n")
		else:
			if site_name not in sites:
				sites[site_name] = {}
			server_group_name = row[rowIndex["server_group"]].strip()
			if (server_group_name==""):
				logging.warning("[WARNING] CSV Row "+row_num_str+" - Server Group name empty, ignoring record.")
				logging.warning("CSV Row "+row_num_str+" Data: "+str(row)+"\n")
			else:
				if server_group_name not in sites[site_name]:
					sites[site_name][server_group_name] = {"services":{}}
					operation_mode = row[rowIndex["operation_mode"]].strip().lower()
					if (operation_mode!=""):
						sites[site_name][server_group_name]["operation_mode"] = operation_mode

				# Check for both server_ip and gateway_group columns to be present
				if ("server_ip" in rowIndex or "gateway_group" in rowIndex):
					if ("server_ip" in rowIndex and "gateway_group" in rowIndex):
						server_ip = row[rowIndex["server_ip"]].strip()
						gateway_group = row[rowIndex["gateway_group"]].strip()
						# Check for both server_ip and gateway_group columns to have values
						if (server_ip.strip()!="" or gateway_group.strip()!=""):
							if (server_ip.strip()!="" and gateway_group.strip()!=""):
								if ("server_ips" not in sites[site_name][server_group_name]):
									sites[site_name][server_group_name]["server_ips"] = {}
								sites[site_name][server_group_name]["server_ips"][server_ip] = gateway_group
							else:
								logging.warning("[ERROR] CSV Row "+row_num_str+" - Required fields are missing, if you have column Server IP, you mush also specify column Gateway Group")
								logging.warning("CSV Row "+row_num_str+" Data: "+str(row)+"\n")
					else:
						logging.warning('[ERROR] Required fields are missing, if you have column Server IP, you mush also specify column Gateway Group')

				service_name = row[rowIndex["service"]].strip()				
				if (service_name==""):
					logging.warning("[WARNING] CSV Row "+row_num_str+" - Service name empty, ignoring service and application level configuration portions of this record.")
					logging.warning("CSV Row "+row_num_str+" Data: "+str(row)+"\n")
				else:
					if service_name not in sites[site_name][server_group_name]["services"]:
						sites[site_name][server_group_name]["services"][service_name] = {"ports":{},"sslPorts":{},"sslCerts":{},"krpConfigs":{}, "applications":{}}

					if ("service_ports" in rowIndex):
						service_ports = row[rowIndex["service_ports"]].strip()
						# Check for port, if no port is specified, assign default HTTP port of 80
						if (service_ports==""):
							sites[site_name][server_group_name]["services"][service_name]["ports"]["80"] = True
						else: 
							for port in service_ports.split(","):
								sites[site_name][server_group_name]["services"][service_name]["ports"][port] = True

					if ("service_ssl_ports" in rowIndex):
						service_ssl_ports = row[rowIndex["service_ssl_ports"]].strip()
						# Check for port, if no port is specified, assign default HTTP port of 80
						if (service_ssl_ports==""):
							sites[site_name][server_group_name]["services"][service_name]["sslPorts"]["443"] = True
						else: 
							for port in service_ssl_ports.split(","):
								sites[site_name][server_group_name]["services"][service_name]["sslPorts"][port] = True
							service_name = row[rowIndex["service"]].strip()
					
					certPresent = False
					# Check for both ssl_private_key and ssl_public_key columns to be present
					if ("ssl_private_key" in rowIndex or "ssl_public_key" in rowIndex or "ssl_key_name" in rowIndex or "hsm" in rowIndex):
						if ("ssl_private_key" in rowIndex and "ssl_public_key" in rowIndex and "ssl_key_name" in rowIndex and "hsm" in rowIndex):
							ssl_key_name = row[rowIndex["ssl_key_name"]].strip()
							ssl_private_key = row[rowIndex["ssl_private_key"]].strip()
							ssl_public_key = row[rowIndex["ssl_public_key"]].strip()
							hsm_val = row[rowIndex["hsm"]].strip().lower()
							hsm = bool(distutils.util.strtobool(hsm_val)) if hsm_val!="" else False
							# Check for both ssl_private_key and ssl_public_key columns to have values
							if (ssl_private_key!="" or ssl_public_key!="" or ssl_key_name!=""):
								if (ssl_private_key!="" and ssl_public_key!="" and ssl_key_name!=""):
									certPresent = True
									cert = {
										"format":"pem",
										"private":OpenFile(ssl_private_key),
										"certificate":OpenFile(ssl_public_key),
										"hsm":hsm
									}
									sites[site_name][server_group_name]["services"][service_name]["sslCerts"][ssl_key_name] = cert
								else:
									logging.warning("[ERROR] CSV Row "+row_num_str+" - Required fields are missing, you mush have SSL Key Name, SSL Private Key, and SSL Private Key to upload a SSL pem type certificate")
									logging.warning("CSV Row "+row_num_str+" Data: ",row)
						else:
							logging.warning('[ERROR] Required fields are missing, if you have column Server IP, you mush also specify column Gateway Group')
							exit()
					# ssl_p12
					# ssl_p12_passphrase

					if ("krp_inbound_port" in rowIndex or "krp_internal_host" in rowIndex or "krp_outbound_port" in rowIndex or "gateway_group" in rowIndex or "krp_outbound_priority" in rowIndex or "gateway_krp_alias_name" in rowIndex):
						if ("krp_inbound_port" in rowIndex and "krp_internal_host" in rowIndex and "krp_outbound_port" in rowIndex and "gateway_group" in rowIndex and "krp_outbound_priority" in rowIndex and "gateway_krp_alias_name" in rowIndex):
							krp_inbound_port = row[rowIndex["krp_inbound_port"]].strip()
							krp_internal_host = row[rowIndex["krp_internal_host"]].strip()
							krp_outbound_port = row[rowIndex["krp_outbound_port"]].strip()
							gateway_group = row[rowIndex["gateway_group"]].strip()
							krp_outbound_priority = row[rowIndex["krp_outbound_priority"]].strip()
							gateway_krp_alias_name = row[rowIndex["gateway_krp_alias_name"]].strip()
							
							if (krp_inbound_port!="" or krp_internal_host!="" or krp_outbound_port!="" or gateway_group!="" or krp_outbound_priority!="" or gateway_krp_alias_name!=""):
								if (krp_inbound_port!="" and krp_internal_host!="" and krp_outbound_port!="" and gateway_group!="" and krp_outbound_priority!="" and gateway_krp_alias_name!=""):
									krpConfig = {
										"krp_inbound_port":krp_inbound_port,
										"gateway_group":gateway_group,
										"gateway_krp_alias_name":gateway_krp_alias_name,
										"krpRules":{
											"outboundRules":{}
										}
									}
									krp_config_id = gateway_group+"_"+gateway_krp_alias_name+"_"+krp_inbound_port+"_"+str(ssl_key_name)
									if krp_config_id not in sites[site_name][server_group_name]["services"][service_name]["krpConfigs"]:
										sites[site_name][server_group_name]["services"][service_name]["krpConfigs"][krp_config_id] = krpConfig

									if certPresent:
										sites[site_name][server_group_name]["services"][service_name]["krpConfigs"][krp_config_id]["krpRules"]["serverCertificate"] = ssl_key_name

									encrypt = bool(distutils.util.strtobool(row[rowIndex["krp_encrypt_outbound"]].strip().lower())) if hsm_val!="" else False
									outboundRule = {
										"externalHost": "Any",
										"internalIpHost": row[rowIndex["krp_internal_host"]],
										"serverPort": row[rowIndex["krp_outbound_port"]], 
										"encrypt": encrypt
									}
									sites[site_name][server_group_name]["services"][service_name]["krpConfigs"][krp_config_id]["krpRules"]["outboundRules"][krp_outbound_priority] = outboundRule
						else:
							logging.warning('[ERROR] Required fields are missing, to specify a KRP rule, you must have all of following columns populated: KRP Alias Name, Inbound KRP Port, KRP Internal Host, KRP Outbound Port, Gateway Group and KRP Outbound Priority.')

					application_name = row[rowIndex["application"]].strip()
					if (application_name==""):
						logging.warning("[WARNING] CSV Row "+row_num_str+" - Application name empty, ignoring application configuration portions of this record.")
						logging.warning("CSV Row "+row_num_str+" Data: "+str(row)+"\n")
					else:
						sites[site_name][server_group_name]["services"][service_name]["applications"][application_name] = {"hostToAppMappings":{}}
						if ("application_mapping_priority" in rowIndex or "application_mapping_host" in rowIndex or "host_match_type" in rowIndex):
							if ("application_mapping_priority" in rowIndex and "application_mapping_host" in rowIndex and "host_match_type" in rowIndex):
								priority = row[rowIndex["application_mapping_priority"]].strip()
								host = row[rowIndex["application_mapping_host"]].strip()
								host_match_type = row[rowIndex["host_match_type"]].strip().lower().capitalize()
								
								# Check for all app required values
								if (priority!="" or host!="" or host_match_type!=""):
									if (priority!="" and host!="" and host_match_type!=""):
										appMapping = {"host":host,"hostMatchType":host_match_type}
										sites[site_name][server_group_name]["services"][service_name]["applications"][application_name]["hostToAppMappings"][priority] = appMapping
									else:
										logging.warning("[ERROR] CSV Row "+row_num_str+" - Required fields are missing, you mush have Application, Application Mapping Priority, Application Mapping Host, and Host Match Type to map applications")
										logging.warning("CSV Row "+row_num_str+" Data: ",str(row))

	# print("\n\n"+json.dumps(sites))
	# exit()
	return sites

def ErrorCheck(response):
	isOk=True
	if response.status_code!=200:
		isOk=False
		responseObj = response.json()
		if (responseObj["errors"][0]["error-code"]=="IMP-10005"):
			isOk=True
	return isOk

def WriteFile(fileName, data):
	open(fileName, 'w+').close()
	file=open(fileName,"w+")
	file.write(data)

def OpenFile(fileName, readMode="rt"):
	try:
		with open(fileName, readMode) as f:
			fileTxt = f.read()
		f.closed
		return fileTxt
	except:
		print('[ERROR] File path "'+fileName+'" in csv not found, or script unable to read.')
		exit()

