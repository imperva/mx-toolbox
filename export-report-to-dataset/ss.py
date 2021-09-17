import sys
import json
import requests
import base64
import logging
from time import localtime, strftime

PREFIX = "/SecureSphere/api/v1"
sessionfile = "session.txt"

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

def getSession(mx_host,username, password):	
	try:
		logging.warning("opening session file: "+sessionfile)
		f = open(sessionfile, "r")
		session_id = f.read()
		result = makeCall(mx_host, session_id, "/administration/version")
		if (result.status_code!=200):
			logging.warning("Invalid session, logging in and creating file: "+sessionfile)		
			filehandle = open(sessionfile, 'w')
			session_id = login(mx_host,username, password)
			filehandle.write(session_id)
			filehandle.close()
			return session_id
		else:
			logging.warning("Valid session found in '"+sessionfile+"': "+session_id)
			return session_id
	except:
		logging.warning("Missing session file, logging in and creating file: "+sessionfile)		
		filehandle = open(sessionfile, 'w')
		session_id = login(mx_host,username, password)
		filehandle.write(session_id)
		filehandle.close()
		return session_id

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
			logging.warning("API REQUEST (" + method + " " + url + ") " + str(content))
			response = requests.post(url, content, headers=headers, verify=False)
		elif method == 'GET':
			logging.warning("API REQUEST (" + method + " " + url + ") ")
			response = requests.get(url, headers=headers, verify=False)
		elif method == 'DELETE':
			logging.warning("API REQUEST (" + method + " " + url + ") ")
			response = requests.delete(url, headers=headers, verify=False)
		elif method == 'PUT':
			logging.warning("API REQUEST (" + method + " " + url + ") " + str(content))
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


def getSignature():
	print("getSignature()")

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


