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

def initConfig(configfile):
	CONFIG = {}
	try:
		with open(configfile, 'r') as data:
			CONFIG = json.load(data)
			logging.warning("Loaded "+configfile+" configuration")
			return CONFIG
	except:
		logging.warning("Missing \""+configfile+"\" file, create file named config.json with the following contents:\n{\n\t\"log_level\": \"debug\",\n\t\"environment\": \"dev\",\n\t\"mx_auth\": {\n\t\t\"endpoint\": \"MXENDPOINT\",\n\t\t\"username\": \"MXUSERNAME\",\n\t\t\"password\": \"MXPASSWORD\",\n\t\t\"license_key\": \"LICENSE_KEY\"\n\t},\n\t\"newrelic_auth\": {\n\t\t\"account_id\": \"ACCOUNT_ID\",\n\t\t\"api_key\": \"API_KEY\",\n\t\t\"event_type\": \"WAFAlerts\",\n\t}\n}")
		exit()

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
		if response.status_code != 200: 
			print('Status:', response.status_code, 'Headers:', response.headers, 'Error Response:',response.json())
			logging.warning('Status:', response.status_code, 'Headers:', response.headers, 'Error Response:',response.json())
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

def get_mx_instances_by_tagname(tagkey, tagvalue, AWSREGIONS):
	MXs = []
	for region in AWSREGIONS:
		ec2client = boto.ec2.connect_to_region(region)
		response = ec2client.get_all_instances(filters={"tag-key":"impv","tag-value":"mx-sync"})
		instances = [i for r in response for i in r.instances]
		for i in instances:
			# region = str(i.__dict__["region"])
			# region[11:]
			MXs.append({
				"ENDPOINT":"https://" + i.__dict__["private_ip_address"] + ":8083",
				"NAME":i.__dict__["key_name"] + "_" + i.__dict__["tags"]["Name"],
				"REGION": region
			})
	return MXs

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
    if ("site" not in rowIndex or "server_group" not in rowIndex or "server_group" not in rowIndex):
        print('[ERROR] Required fields are missing, csv must contain a minimum of the the following columns:\nSite, Server Group, Service')
        exit()

    # Process each row into normalized site tree object
    for row_num in range(len(rows[1:])):
        row_num_str = str(row_num+1)
        row = rows[row_num+1]
        site_name = row[rowIndex["site"]].strip()
        if site_name not in sites:
            sites[site_name] = {}
        
        server_group_name = row[rowIndex["server_group"]].strip()
        if server_group_name not in sites[site_name]:
            sites[site_name][server_group_name] = {"services":{}}
        
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
                        print("[ERROR] CSV Row "+row_num_str+" - Required fields are missing, if you have column Server IP, you mush also specify column Gateway Group")
                        print("CSV Row "+row_num_str+" Data: "+row_str)
            else:
                print('[ERROR] Required fields are missing, if you have column Server IP, you mush also specify column Gateway Group')
                exit()
                
        service_name = row[rowIndex["service"]].strip()
        if service_name not in sites[site_name][server_group_name]["services"]:
            sites[site_name][server_group_name]["services"][service_name] = {"ports":{},"sslPorts":{},"sslCerts":{},"krpRules":{}}

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
        
        # Check for both ssl_private_key and ssl_public_key columns to be present
        if ("ssl_private_key" in rowIndex or "ssl_public_key" in rowIndex or "ssl_key_name" in rowIndex):
            if ("ssl_private_key" in rowIndex and "ssl_public_key" in rowIndex and "ssl_key_name" in rowIndex):
                ssl_key_name = row[rowIndex["ssl_key_name"]].strip()
                ssl_private_key = row[rowIndex["ssl_private_key"]].strip()
                ssl_public_key = row[rowIndex["ssl_public_key"]].strip()
                # Check for both ssl_private_key and ssl_public_key columns to have values
                if (ssl_private_key!="" or ssl_public_key!="" or ssl_key_name!=""):
                    if (ssl_private_key!="" and ssl_public_key!="" and ssl_key_name!=""):
                        ssl_private_key_txt = OpenFile(ssl_private_key)
                        ssl_public_key_txt = OpenFile(ssl_public_key)                        
                        sites[site_name][server_group_name]["services"][service_name]["sslCerts"][ssl_private_key+"_"+ssl_public_key] = {"ssl_private_key":ssl_private_key_txt,"ssl_public_key":ssl_public_key_txt}
                    else:
                        print("[ERROR] CSV Row "+row_num_str+" - Required fields are missing, you mush have SSL Key Name, SSL Private Key, and SSL Private Key to upload a SSL pem type certificate")
                        print("CSV Row "+row_num_str+" Data: ",row)
            else:
                print('[ERROR] Required fields are missing, if you have column Server IP, you mush also specify column Gateway Group')
                exit()      
        # ssl_p12
        # ssl_p12_passphrase

        if ("krp_alias_name" in rowIndex or "inbound_krp_port" in rowIndex or "krp_internal_host" in rowIndex or "krp_outbound_port" or "gateway_group" in rowIndex):
            if ("krp_alias_name" in rowIndex and "inbound_krp_port" in rowIndex and "krp_internal_host" in rowIndex and "krp_outbound_port" in rowIndex and "gateway_group" in rowIndex):                
                krp_alias_name = row[rowIndex["krp_alias_name"]]
                krpRule = {
                    "inbound_krp_port":row[rowIndex["inbound_krp_port"]],
                    "krp_internal_host":row[rowIndex["krp_internal_host"]],
                    "krp_outbound_port":row[rowIndex["krp_outbound_port"]],
                    "gateway_group":row[rowIndex["gateway_group"]]
                }
                sites[site_name][server_group_name]["services"][service_name]["krpRules"][krp_alias_name] = krpRule
            else:
                print('[ERROR] Required fields are missing, to specify a KRP rule, you must have all of following columns populated: KRP Alias Name, Inbound KRP Port, KRP Internal Host, KRP Outbound Port, and Gateway Group.')
                exit()

        # application = row[rowIndex["application"]]
        # hostname = row[rowIndex["hostname"]]
    # print("\n\n"+json.dumps(sites))
    return sites

def OpenFile(fileName, readMode="rt"):
    try:
        with open(fileName, readMode) as f:
            fileTxt = f.read()
        f.closed
        return fileTxt
    except:
        print('[ERROR] File path "'+fileName+'" in csv not found, or script unable to read.')
        exit()
