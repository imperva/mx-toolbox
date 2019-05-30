#!/usr/bin/env python

import os
import re
import sys
from subprocess import PIPE, Popen
from time import localtime, strftime
import json
import requests
import logging

############ ENV Settings ############
logging.basicConfig(filename='send_alert_to_new_relic.log', filemode='w', format='%(name)s - %(levelname)s - %(message)s')

############### Configs ###############
configfile = 'newrelic.config.json'
TIMESTAMP = strftime("%Y/%m/%d %H:%M:%S", localtime())
try:
    with open(configfile, 'r') as data:
        config = json.load(data)
except:
    logging.warning("Missing \""+configfile+"\" file, create file named \""+configfile+"\" with the following contents:\n{\n\t\"license_key\":\"abc123\",\n\t\"log_level\":\"debug\",\n\t\"account_id\":\"2295794\",\n\t\"api_key\":\"abc124\",\n\t\"event_type\":\"WAFAlerts\",\n\t\"environment\":\"dev,\"\n}")
    exit()

def run():
    new_relic_url = "https://insights-collector.newrelic.com/v1/accounts/"+config["account_id"]+"/events"
    headers = {
        "Content-Type": "application/json",
        "X-Insert-Key": config["api_key"]
    }
    del sys.argv[0]
    jsonstr = ' '
    paramsorig = json.loads(jsonstr.join(sys.argv))
    params = {}
    for key in paramsorig:
        if paramsorig[key][:2] != "${":
            params[key] = paramsorig[key]
    params["environment"] = config["environment"]
    logging.warning("NEW RELIC REQUEST ("+new_relic_url+")"+json.dumps(params))
    if "proxy_host" in params and "proxy_port" in params and "proxy_username" in params and "proxy_password" in params:
        proxies = {"https": "https://"+proxy_username+":"+proxy_password+"@"+proxy_host+":"+proxy_port}
        response = requests.post(new_relic_url, json.dumps(params), proxies=proxies, headers=headers, verify=False)
    else:
        response = requests.post(new_relic_url, json.dumps(params), headers=headers, verify=False)
    logging.warning("NEW RELIC RESPONSE"+json.dumps(response.json()))

############### Global Functions ###############
def strim(str):
    return re.sub('\s\s+', ' ', str).strip()

if __name__ == '__main__':
    run()
