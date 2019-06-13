# Gateway performance monitoring for Imperva SecureSphere gateways

The Gateway performance monitoring for Imperva SecureSphere gateways provides the ability to output performance and throughput counters from gateway appliances into new relic or into a SIEM via syslog output in JSON format.

## Getting Started

Download the latest files from the gateway-performance-monitoring folder.  Within this folder are 2 required files:

```
get_gateway_stats.py
template.config.json
```

The files should be copied to the /var/user-data/ folder on the MX.  The .json config file should live in the same directory, as referenced in the script. 

The template.config.json file must be re-named config.json.  

## Installing and dynamic initial configuration in AWS Environments

TODO

## Configuration Options ##

The script has one configuration file, which lives in the same directory as the script.

### config.json ###

The `config.json` configuration file is where New Relic specific configuration lives. 

Example:

```
{
  "log_level": "debug",
  "environment": "dev",
  "mx": {
    "enabled": false,
    "endpoint": "MXENDPOINT",
    "username": "MXUSERNAME",
    "password": "MXPASSWORD",
    "license_key": "LICENSE_KEY"
  },
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
  "syslog": {
    "enabled": true,
    "host": "1.2.3.4",
    "port": 514
  }
}
```

#### Config Options ####

`log_level` - _(optional)_ the log level. Valid values: `debug`, `info`, `warn`, `error`, `fatal`. Defaults to `info`.

`environment` - _(optional)_ the logical environment the server operates in.  This value will be reported with every Event.  Ex. `dev`, `stage`, `uat`, `prod`.  Defaults to `dev`

`log_file_name` - _(optional)_ the log file name. Defaults to `send_alert_to_new_relic.log`.

`newrelic` - (optional) sectional is not required, if not using newrelic, either set newrelic.enabled to false section can be removed from config

`newrelic.enabled` - _(required)_ set to true if using newrelic

`newrelic.account_id` - _(required)_ the Account ID of the New Relic account

`newrelic.event_type` - _(required)_ the name of the Insights Event Type.  The event type as stored by New Relic Insights. New Relic agents and scripts normally report this as eventType. Can be a combination of alphanumeric characters, _ underscores, and :colons.  Defaults to `WAFPerformance`.

`newrelic.api_key` - _(required)_ the API Key for the Insights API

`syslog` - _(optional) sectional is not required, if not using syslog, either set syslog.enabled to false or section can be removed from config

`syslog.enabled` - _(required)_ set to true if using syslog

`syslog.host` - _(optional)_ the syslog host. Ex. `10.10.10.20` or `syslog.servername.local`

`syslog.port` - _(optional)_ the syslog port. Ex. `514`. 

`proxy_host` - _(optional)_ the proxy host. Ex. `webcache.example.com`

`proxy_port` - _(optional)_ the proxy port. Ex. `8080`. Defaults to `80` if a `proxy_host` is set.

`proxy_username` - _(optional)_ the proxy username

`proxy_password` - _(optional)_ the proxy password
