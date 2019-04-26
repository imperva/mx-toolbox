import ss
import json

PRIMARY_MX_HOST = "https://172.31.11.85:8083"
AUTH = {}
with open('config', 'r') as data:
    AUTH = json.load(data)

policyPrefix = "BA_api_test"
TEMP_POLICY = {
	"severity": "medium",
	#"enabled": True,
	"followedAction": "",
	#"oneAlertPerSession": False,
	#"displayResponsePage": False,
	"action": "none",
	"matchCriteria": [],
	"applyTo": []
}
sourcePolicies = {
	"datasetAttributeLookup": '{"type": "datasetAttributeLookup", "operation": "atLeastOne", "attribute": "val", "searchInLookupDataset": ["BA_dataset"], "searchInUserValues": ["test"], "field": "acceptLanguages", "lookupDataset": "BA_attribute_dataset"}',
	# "sourceGeolocation": '{"applyIfUnidentified": false, "values": ["Afghanistan"], "type": "sourceGeolocation", "operation": "atLeastOne"}',
	"applicationUser": '{"matchNoOrUnknownUser": false, "values": ["ba"], "type": "applicationUser", "operation": "atLeastOne"}',
	"authenticatedSession": '{"type": "authenticatedSession", "value": "no"}',
	"authenticationResult": '{"type": "authenticationResult", "value": "successful"}',
	"authenticationUrl": '{"type": "authenticationUrl", "value": "no"}',
	"clientTypeBotProtection": '{"type": "clientTypeBotProtection", "operation": "atLeastOne", "clientTypes": ["badBot"]}',
	"enrichmentData": '{"type": "enrichmentData", "operation": "atLeastOne", "userDefinedFieldName": "my_field_name", "matchUnknownValue": false, "searchInLookupDataset": ["BA_dataset"]}',
	"lookupDatasetSearch": '{"type": "lookupDatasetSearch", "operation": "atLeastOne", "matchUnknownValue": true, "searchInLookupDataset": ["BA_dataset"], "field": "proxyIpAddresses"}',
	#"httpRequest": '{"type": "httpRequest", "operation": "matchAll", "matchValues": [{"part": "parameter", "name": "test", "operation": "includes", "value": "myval"}, {"part": "header", "name": "test", "operation": "includes", "value": "myval"}, {"part": "url", "name": "test", "operation": "includes", "value": "/test/url"}]}',
	"httpRequestAcceptLanguage": '{"values": ["test"], "type": "httpRequestAcceptLanguage", "operation": "atLeastOne"}',
	"httpRequestContentType": '{"values": ["test"], "type": "httpRequestContentType", "operation": "excludeAll"}',
	"httpRequestCookieName": '{"type": "httpRequestCookieName", "operation": "atLeastOne", "cookieNames": [{"cookie": "testcookieexact", "matchType": "Exact"}, {"cookie": "testcookieprefix", "matchType": "Prefix"}]}',
	"httpRequestCookies": '{"values": ["testcookievalue"], "type": "httpRequestCookies", "operation": "atLeastOne", "match": "prefix", "name": "testcookie"}',
	"httpRequestFileExtension": '{"values": ["test"], "type": "httpRequestFileExtension", "operation": "atLeastOne"}',
	"httpRequestHeaderValue": '{"values": ["testheadervalue"], "type": "httpRequestHeaderValue", "operation": "atLeastOne", "name": "testeheadername"}',
	"httpRequestHeaderName": '{"values": ["test"], "type": "httpRequestHeaderName", "operation": "atLeastOne"}',
	"httpRequestHostName": '{"values": ["test"], "type": "httpRequestHostName", "operation": "atLeastOne"}',
	"httpRequestMethod": '{"values": ["test"], "type": "httpRequestMethod", "operation": "atLeastOne"}',
	"httpRequestParameterName": '{"values": ["paramname"], "type": "httpRequestParameterName", "operation": "atLeastOne"}',
	"httpRequestParameterNamePrefix": '{"values": ["paramname"], "type": "httpRequestParameterNamePrefix", "operation": "atLeastOne"}',
	"httpRequestRefererNamePrefix": '{"values": ["RefererName"], "type": "httpRequestRefererNamePrefix", "operation": "atLeastOne"}',
	"httpRequestRefererUrl": '{"values": ["referrerurl"], "type": "httpRequestRefererUrl", "operation": "atLeastOne"}',
	"httpRequestUrl": '{"values": ["url"], "type": "httpRequestUrl", "operation": "atLeastOne", "match": "prefix"}',
	"httpRequestUserAgent": '{"values": ["User_Agent_Value"], "type": "httpRequestUserAgent", "operation": "atLeastOne"}',
	"httpResponseHeaderName": '{"values": ["test"], "type": "httpResponseHeaderName", "operation": "atLeastOne"}',
	"httpResponseCode": '{"values": ["200", "100"], "type": "httpResponseCode", "operation": "atLeastOne"}',
	"httpSession": '{"type": "httpSession", "value": "validated", "operation": "equals"}',
	"numberOfOccurrences": '{"type": "numberOfOccurrences", "context": "originatingSession", "numTimes": 100, "withinSeconds": 300}',
	"profiledRefererHost": '{"type": "profiledRefererHost", "value": "yes"}',
	"protocols": '{"values": ["http", "https"], "type": "protocols", "operation": "atLeastOne"}',
	"proxyIpAddresses": '{"ipGroups": ["BA_IP_group"], "matchNonProxied": true, "type": "proxyIpAddresses", "operation": "atLeastOne"}',
	"sensitiveDictionarySearch": '{"type": "sensitiveDictionarySearch", "searchMode": "Contains", "dictionaries": ["American Express Credit Card Numbers"], "locations": "url"}',
	#"signatures": '{"type": "signatures", "operation": "atLeastOne", "signatures": [{"name": "BA_web_sig_dictionary", "isUserDefined": true}]}',
	"genericDictionarySearch": '{"type": "genericDictionarySearch", "operation": "atLeastOne", "searchMode": "Contains", "dictionaries": ["Admin URLs"], "locations": "url"}',
	"sourceIpAddresses": '{"ipGroups": ["BA_IP_group"], "type": "sourceIpAddresses", "operation": "atLeastOne"}',
	"timeOfDay": '{"type": "timeOfDay", "restrictions": [{"dayOfWeek": "sunday", "from": "00:00", "to": "01:00"}, {"dayOfWeek": "tuesday", "from": "01:00", "to": "02:00"}, {"dayOfWeek": "thursday", "from": "02:00", "to": "03:00"}, {"dayOfWeek": "saturday", "from": "03:00", "to": "04:00"}]}',
	"violations": '{"values": ["Abnormally Long Header Line"], "type": "violations", "operation": "atLeastOne"}',
	"webPageResponseSize": '{"type": "webPageResponseSize", "value": "1000", "operation": "lessOrEquals"}',
	"webPageResponseTime": '{"type": "webPageResponseTime", "value": "1000", "operation": "lessOrEquals"}'
}

session_id = ss.login(PRIMARY_MX_HOST, AUTH["USERNAME"], AUTH["PASSWORD"])
method = "POST"
applyToService = [{"siteName":"Default Site","serverGroupName":"Server us-east-2 Group 2","webServiceName":"HTTP Service"},{"siteName":"Default Site","serverGroupName":"Server us-east-1 Group ","webServiceName":"HTTP Service"}]
applyToApp = [{"siteName":"Default Site","serverGroupName":"Server us-east-2 Group 2","webServiceName":"HTTP Service","webApplicationName":"Default Web Application"},{"siteName":"Default Site","serverGroupName":"Server us-east-1 Group ","webServiceName":"HTTP Service","webApplicationName":"Default Web Application"}]

curPol = TEMP_POLICY.copy()
print("===================  START REQUEST  ====================\r\n")
for policy_name in sourcePolicies:
	matchCriteria = sourcePolicies[policy_name]
	#curPol = json.loads(json.dumps(TEMP_POLICY.copy()))
	curPol["matchCriteria"].append(json.loads(matchCriteria))
print(curPol)
curPol["applyTo"] = applyToService
response = ss.makeCall(PRIMARY_MX_HOST,session_id, "/conf/policies/security/webServiceCustomPolicies/" + policyPrefix + "_service", method, json.dumps(curPol))
curPol["applyTo"] = applyToApp
response = ss.makeCall(PRIMARY_MX_HOST,session_id, "/conf/policies/security/webApplicationCustomPolicies/" + policyPrefix + "_app", method, json.dumps(curPol))
#response = ss.makeCall(session_id, "/conf/policies/security/webServiceCustomPolicies/" + policyPrefix + "_" + policy_name, "POST", json.dumps(curPol))
if response.status_code == 200:
	print(response.status_code)
else:
	print(response.json())
print("===================  END RESPONSE  ====================\r\n")

for policy_name in sourcePolicies:
	curPol2 = {
		"severity": "medium",
		#"enabled": True,
		"followedAction": "",
		# "oneAlertPerSession": False,
		# "displayResponsePage": False,
		"action": "none",
		"matchCriteria": [],
		"applyTo": []
	}
	matchCriteria = sourcePolicies[policy_name]
	curPol2["matchCriteria"].append(json.loads(matchCriteria))
	print("===================  START REQUEST ====================\r\n")
	print(curPol2)
	#response = ss.makeCall(session_id, "/conf/policies/security/webServiceCustomPolicies/" + policyPrefix, "POST", json.dumps(curPol))
	curPol2["applyTo"] = applyToService
	response = ss.makeCall(PRIMARY_MX_HOST,session_id, "/conf/policies/security/webServiceCustomPolicies/" + policyPrefix + "_" + policy_name + "_service", method, json.dumps(curPol2))
	curPol2["applyTo"] = applyToApp
	response = ss.makeCall(PRIMARY_MX_HOST,session_id, "/conf/policies/security/webApplicationCustomPolicies/" + policyPrefix + "_" + policy_name + "_app", method, json.dumps(curPol2))
	print(response)
	if response.status_code == 200:
		print(response.status_code)
	else:
		print(response.json())
	print("===================  END RESPONSE  ====================\r\n")

