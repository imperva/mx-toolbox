#!/usr/bin/env python

import ss
import sys
import json
import csv
import requests
import logging
import urllib

############ ENV Settings ############
logging.basicConfig(filename='export-krp-rules-to-new-relic.log', filemode='w', format='%(name)s - %(levelname)s - %(message)s')

############ GLOBALS ############
configfile = 'config.json'
krprules = []
CONFIG = {}
try:
    with open(configfile, 'r') as data:
        CONFIG = json.load(data)
        logging.warning("Loaded "+configfile+" configuration")

except:
    logging.warning("Missing \""+configfile+"\" file, create file named config.json with the following contents:\n{\n\t\"log_level\": \"debug\",\n\t\"environment\": \"dev\",\n\t\"mx_auth\": {\n\t\t\"endpoint\": \"MXENDPOINT\",\n\t\t\"username\": \"MXUSERNAME\",\n\t\t\"password\": \"MXPASSWORD\",\n\t\t\"license_key\": \"LICENSE_KEY\"\n\t},\n\t\"newrelic_auth\": {\n\t\t\"account_id\": \"ACCOUNT_ID\",\n\t\t\"api_key\": \"API_KEY\",\n\t\t\"event_type\": \"WAFAlerts\",\n\t}\n}")
    exit()

logging.warning("\n\n===========  Start KRP export ===========\n")

def run():
    mx_host = CONFIG["mx_auth"]["endpoint"]
    session_id = ss.login(mx_host, CONFIG["mx_auth"]["username"], CONFIG["mx_auth"]["password"])
    sites_response = ss.makeCall(mx_host, session_id, "/v1/conf/sites/")
    sites = sites_response.json()
    # Load all sites from site tree
    for site in sites["sites"]:
        # Load all server groups from each site
        server_groups_response = ss.makeCall(mx_host, session_id, '/v1/conf/serverGroups/'+site)
        server_groups = server_groups_response.json()
        for server_group in server_groups["server-groups"]:
            # Load all web serivces from from each server group
            web_services_response = ss.makeCall(mx_host, session_id, '/v1/conf/webServices/'+site+"/"+server_group)
            web_services = web_services_response.json()
            for web_service in web_services["web-services"]:
                # Load all inbound krp rules from web service
                krp_inbound_rules_response = ss.makeCall(mx_host, session_id, '/v1/conf/webServices/' + site + "/" + server_group+"/"+web_service+"/krpInboundRules")
                krp_inbound_rules = krp_inbound_rules_response.json()
                for krp_inbound_rule in krp_inbound_rules["inboundKrpRules"]:
                    for inbound_port in krp_inbound_rule["gatewayPorts"]:
                        url = '/v1/conf/webServices/' + site + "/" + server_group + "/" + web_service + "/krpInboundRules/"+krp_inbound_rule["gatewayGroupName"]+"/"+krp_inbound_rule["aliasName"]+"/"+str(inbound_port)+"/krpOutboundRules"
                        krp_outbound_rules_response = ss.makeCall(mx_host, session_id, url)
                        krp_outbound_rules = krp_outbound_rules_response.json()
                        for krp_outbound_rule in krp_outbound_rules["outboundKrpRules"]:
                            krp_rule = {
                                "eventType": CONFIG["newrelic_auth"]["event_type"],
                                "environment": CONFIG["environment"],
                                "site": site,
                                "server_group": server_group,
                                "service": web_service,
                                "gateway_group_name": krp_inbound_rule["gatewayGroupName"],
                                "krp_alias_name": krp_inbound_rule["aliasName"],
                                "inbound_port": inbound_port,
                                "priority": krp_outbound_rule["priority"],
                                "internal_host": krp_outbound_rule["internalIpHost"],
                                "outbound_port": krp_outbound_rule["serverPort"]
                            }
                            new_relic_url = "https://insights-collector.newrelic.com/v1/accounts/" + CONFIG["newrelic_auth"]["account_id"] + "/events"
                            headers = {
                                "Content-Type": "application/json",
                                "X-Insert-Key": CONFIG["newrelic_auth"]["api_key"]
                            }
                            logging.warning("NEW RELIC REQUEST (" + new_relic_url + ")" + json.dumps(krp_rule))
                            #if "proxy_host" in CONFIG["proxies"] and "proxy_port" in CONFIG["proxies"] and "proxy_username" in CONFIG["proxies"] and "proxy_password" in CONFIG["proxies"]:
                            if "proxies" in CONFIG:
                                proxies = {"https": "https://"+CONFIG["proxies"]["proxy_username"]+":"+CONFIG["proxies"]["proxy_password"]+"@"+CONFIG["proxies"]["proxy_host"]+":"+CONFIG["proxies"]["proxy_port"]}
                                response = requests.post(new_relic_url, json.dumps(krp_rule), proxies=proxies, headers=headers, verify=False)
                            else:
                                response = requests.post(new_relic_url, json.dumps(krp_rule), headers=headers, verify=False)
                            logging.warning("NEW RELIC RESPONSE"+json.dumps(response.json()))

if __name__ == '__main__':
    run()


