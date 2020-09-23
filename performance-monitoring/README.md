# MX and Gateway performance monitoring for Imperva SecureSphere appliances

The performance monitoring package for Imperva SecureSphere appliances provides the ability to output performance and throughput counters into new relic, influxdb/grafana, or into a SIEM via syslog output in JSON format.

## Getting Started

Download the latest files from the performance-monitoring folder.  Within this folder are 3 required files:

1. Download and copy the files into a new directory (/var/user-data) on the Management Server (MX):
    - SSH to the MX, and create the following directory, which is the supported folder for running custom scritps.  
        >`mkdir /var/user-data`  
        `cd /var/user-data`  
    - Download the following files and copy them into the the /var/user-data folder on the MX:  
        >`get_mx_stats.py`  
        `template.config.json`  
    - Download the following files and copy them into the the /var/user-data folder on the Gateway:  
        >`get_gateway_stats.py`  
        `template.config.json`  
    - Rename template.config.json to config.json  
        >`mv template.config.json config.json`  

## Configuration Options ##

The script has one configuration file, which lives in the same directory as the script.

### config.json ###

The `config.json` configuration file is where New Relic specific configuration lives. 

Example:

```
{
  "log_level": "debug",
  "log_file_name": "gateway_statistics.log",
  "environment": "dev",
  "is_userspace": false, 
  "gw_log_search": {
    "enabled": true,
    "files": [{
      "path": "/var/log/messages",
      "search_patterns": [{
          "name":"YOUR_EVENT_NAME",
          "pattern":"some text pattern"
        }, {
          "name":"YOUR_EVENT_NAME_2",
          "pattern":"some other text pattern"
        }
      ]
    }]
  },
  "newrelic": {
    "enabled": false,
    "account_id": "ACCOUNT_ID",
    "api_key": "API_KEY",
    "event_type": "GWStats"
  },
  "influxdb": {
    "enabled": true,
    "host": "http://1.2.3.4:8086/write?db=imperva_performance_stats"
  },
  "syslog": {
    "enabled": true,
    "host": "1.2.3.4",
    "port": 514
  }
}
```

#### Config Options ####

`log_level` - _(optional)_ the log level. Valid values: `CRITICAL`, `ERROR`, `WARNING`, `INFO`, `DEBUG`, `NOTSET`. Defaults to `INFO`.

`log_file_name` - _(optional)_ the log file name. Defaults to `send_alert_to_new_relic.log`.

`environment` - _(optional)_ the logical environment the server operates in.  This value will be reported with every Event.  Ex. `dev`, `stage`, `uat`, `prod`.  Defaults to `dev`

`is_userspace` - _(required)_ set to true if using WAF gateway in NGRP mode (version 14.1 or later)

`gw_log_search` - _(optional)_ feature to search a configurable list of local log files for a configurable list of patterns.  Configuring this can add specific events from a local any local log file (/var/log/messges, or /opt/SecureSphere/etc/logs/GatewayLog/GatewayLog.html for example) to be added to syslog output as soon as the event ocurs.

`gw_log_search.enabled` - _(required)_ set to true to enable gw_log_search feature

`gw_log_search.files` - _(required)_ array of objects with the key->value pairs of path and search_patterns

`gw_log_search.files[].path` - _(required)_ the path to a local log file to execute a set of search_patterns against

`gw_log_search.files[].search_patters` - _(required)_ array of objects with the key->value pairs of name and pattern to search for in a the specified file

`gw_log_search.files[].search_patters[].name` - _(required)_ array of objects with the key->value pairs of name and pattern to search for in a the specified 

`gw_log_search.files[].search_patters[].pattern` - _(required)_ any arbitrary string to search for in a specified local log file, the pattern will match even a partial string and return the whole line to be output in syslog feed 

`newrelic` - (optional) sectional is not required, if not using newrelic, either set newrelic.enabled to false section can be removed from config

`newrelic.enabled` - _(required)_ set to true if using newrelic

`newrelic.account_id` - _(required)_ the Account ID of the New Relic account

`newrelic.event_type` - _(required)_ the name of the Insights Event Type.  The event type as stored by New Relic Insights. New Relic agents and scripts normally report this as eventType. Can be a combination of alphanumeric characters, _ underscores, and :colons.  Defaults to `WAFPerformance`.

`newrelic.api_key` - _(required)_ the API Key for the Insights API

`influxdb` - _(optional) section is not required, if not using influxdb, either set influxdb.enabled to false or section can be removed from config

`influxdb.enabled` - _(required)_ set to true if using influxdb

`influxdb.host` - _(required)_ the influxdb protocol, host, port, and database name. Ex. `[protocol]://[host]:[port]/write?db=[influx_db_name]` or `http://1.2.3.4:8086/write?db=imperva_performance_stats`

`influxdb.username` - _(optional)_ if auth is required for influxdb, specify the username.

`influxdb.password` - _(optional)_ if auth is required for influxdb, specify the password.

`syslog` - _(optional) section is not required, if not using syslog, either set syslog.enabled to false or section can be removed from config

`syslog.enabled` - _(required)_ set to true if using syslog

`syslog.host` - _(optional)_ the syslog host. Ex. `10.10.10.20` or `syslog.servername.local`

`syslog.port` - _(optional)_ the syslog port. Ex. `514`. 

`proxy_host` - _(optional)_ the proxy host. Ex. `webcache.example.com`

`proxy_port` - _(optional)_ the proxy port. Ex. `8080`. Defaults to `80` if a `proxy_host` is set.

`proxy_username` - _(optional)_ the proxy username

`proxy_password` - _(optional)_ the proxy password

## Setting up the scripts to as a cron job:
**MX:** The MX script has 2 modes, one that will capture local OS stats intended to be run every minute, and a second that pulls data from the MX DB about the environment, policies, agents, etc, intended to run at a lessser frequency, like every 5 minutes. Run ```crontab -e``` and add the following entries:
```
* * * * * /usr/bin/python /var/user-data/get_mx_stats.py
*/5 * * * * /usr/bin/python /var/user-data/get_mx_stats.py get_server_stats
```

**Gateway:** The Gateway script is intended to run every minute.  Run ```crontab -e``` and add the following entry:
```
* * * * * /usr/bin/python /var/user-data/get_gateway_stats.py
```

## Installing and dynamic initial configuration in AWS Environments

**Step 1:** Populate the ImpervaLicenseKey parameter upon deploying the cloudformation scring. This allows us to run in an “unlocked” mode to initially set up the script and configure the cron.  

**Step 2:** Create a new S3 bucket, upload the config.json and get_gateway_stats.py files, and give the Gateway instances permissions to access the S3 bucket.  This should be added to the “GwRolePolicies.Properties.PolicyDocument.Statement” resource array:
```
...
[
  {
    "Action": [
      "s3:GetObject"
    ],
    "Resource": "arn:aws:s3::gateway-performance-stats-script",
    "Effect": "Allow"
  }
]
...
```

**Step 3:** Edit the commands section so the GW will download and run the script from the S3 bucket during launch.  Command entries should be added to the “Resources.LaunchConfig.Metadata.commands” resource array:

```
      ...
                    "Fn::FindInMap": [
                "ImpervaVariables",
                "LBHealthCheck",
                "https"
              ]
            }
          ]
        ]
      },
      "mkdir /var/user-data",
      "/usr/bin/aws s3 cp s3://gateway-performance-stats-script/config.json /var/user-data",
      "/usr/bin/aws s3 cp s3://gateway-performance-stats-script/get_gateway_stats.py /var/user-data",
      "echo '* * * * * cd /var/user-data && python /var/user-data/get_gateway_stats.py' | crontab -"          	
    ],
    "MXCredentials": [
      {
      ...
```


## Configure InfluxDB database
1. SSH into the influxDB server, and create the imperva_performance_stats database.
```
$ influx
CREATE DATABASE imperva_performance_stats
SHOW DATABASES
exit
```

## Configure Grafana and import the dashboards
If you have not yet done so, create influxdb datasource in grafana, and import performance monitoring dashboards.

#### Create InfluxDB Datasource ####

1. Navigate to grafana via a browser referencing the IP of your docker host.  In this example, it is run locally on a work station and access with the following: [http://influxdb-host:3000](http://influxdb-host:3000)

1. Log in with your credentials.  If you are using the docker image in [influxdb_grafana][https://github.com/imperva/mx-toolbox/tree/master/performance-monitoring/influxdb_grafana] folder, the default credentials are admin/admin, and you will need to create a new password.

1. Click `Add datasource`, and add a new InfluxDB datasource with the following:

   `Name` - _(required)_ the name of the data source: `Imperva Performance Stats`

   `URL` - _(required)_ the endpoint of influxdb: `http://influxdb-host:8086`.

   `Database` - _(required)_ name of database `imperva_performance_stats`.

   `HTTP Method` - _(required)_ the HTTP method used to push data into influxdb `POST`

1. Click `Save & Test` to validate grafana is able to access the datasource correctly.

#### Import Grafana Dashboards ####
1. Navigate to Home screen by clicking the Grafana logo in the top left corner.

1. Import each of dashboard files in the `mx-tools/performance-monitoring/influxdb_grafana/grafana_dashboards` directory by repeating the following steps:
  -  Click `+ -> Create -> Import` to import a dashboard

1. Click `Upload JSON file` and one dashboard at a time to import repeating this process for each.
 

 