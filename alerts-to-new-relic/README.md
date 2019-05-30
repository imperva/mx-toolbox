# Alerts to New Relic script for Imperva Management Servers

The Alerts to New Relic script for Imperva Management Servers (MXs) provides a method for outputting alert data in real-time to the New Relic APM solution for aggregation purposes.  Use of this plug-in requires a valid New Relic APM account.

This plugin will enable on-going aggregation to help quantify which sites are protected, which policies are being triggered, and how much of that traffic is being blocked.    

## Getting Started

Download the latest files from the alerts-to-new-relic folder.  Within this folder are 2 required files:

```
send_alert_to_new_relic.py
newrelic.template.config.json
```

The files should be copied to the /var/user-data/ folder on the MX.  The .json config file should live in the same directory, as referenced in the script. 

The newrelic.template.config.json file must be re-named newrelic.config.json and the license key for your New Relic account must be appended. 

Next, the files permissions and ownership needs to be set for the MX service to be able to invoke the script via an action set.  Run the following from a terminal on the MX server:
```
cd /var/user-data
chown mxserver:mxserver /var/user-data/*
chmod 711 /var/user-data/*
chmod +Xx send_alert_to_new_relic.py.sh
```

## Configuring the MX

THe script will be invoked by the MX via an action set by the mxuser os user, and the action set is applied to security policies to run each time a policy is triggered.  

Log into the MX, navigate to Policies->Action Sets and create an action set of type "Security Violations - All".  Add "Run a Shell Command" and populate with the following parameters:

```
Name: send alert to new relic
Command: send_alert_to_new_relic.py
Arguments: {"eventType":"WAFAlerts","alert_id":"${Alert.dn}","event_id":"${Violation.Id}","alert_type":"$!{Event.eventType}","alert_desc":"${Event.violations.alert.description}","violation_desc":"$!{Violation.Description}","action":"$!{Event.violations.alert.immediateAction}","host":"${Event.struct.httpRequest.url.host}","policy-name":"${Violation.PolicyName}"}
Working Dir: /var/user-data/
Run on Every Event: checked

```

## Installing and dynamic initial configuration in AWS Environments

TODO

## Configuration Options ##

The script has one configuration file, which lives in the same directory as the script.

### newrelic.config.json ###

The `newrelic.config.json` configuration file is where New Relic specific configuration lives. 

Example:

```
{
  "license_key": "LICENSE_KEY",
  "log_level": "debug",
  "account_id": "ACCOUNT_ID",
  "api_key": "API_KEY",
  "event_type": "WAFPerformance",
  "environment": "dev,",
  "waf_events": "enabled",
  "dam_events": "enabled",
  "fam_events": "disabled",
  "sharepoint_events": "disabled",
}
```

#### Config Options ####

`license_key` - _(required)_ the New Relic license key used for the Metrics API

`account_id` - _(required)_ the Account ID of the New Relic account

`api_key` - _(required)_ the API Key for the Insights API

`environment` - _(optional)_ the logical environment the server operates in.  This value will be reported with every Event.  Ex. `dev`, `stage`, `uat`, `prod`.  Defaults to `dev`

`event_type` - _(optional)_ the name of the Insights Event Type.  The event type as stored by New Relic Insights. New Relic agents and scripts normally report this as eventType. Can be a combination of alphanumeric characters, _ underscores, and :colons.  Defaults to `WAFPerformance`.

`log_level` - _(optional)_ the log level. Valid values: `debug`, `info`, `warn`, `error`, `fatal`. Defaults to `info`.

`log_file_name` - _(optional)_ the log file name. Defaults to `send_alert_to_new_relic.log`.

`log_file_path` - _(optional)_ the log file path. Defaults to `logs`.

`log_limit_in_kbytes` - _(optional)_ the log file limit in kilobytes. Defaults to `25600` (25 MB). If limit is set to `0`, the log file size would not be limited.

`proxy_host` - _(optional)_ the proxy host. Ex. `webcache.example.com`

`proxy_port` - _(optional)_ the proxy port. Ex. `8080`. Defaults to `80` if a `proxy_host` is set.

`proxy_username` - _(optional)_ the proxy username

`proxy_password` - _(optional)_ the proxy password




### plugin.json ###

The `plugin.json` configuration file is where plugin specific configuration lives. A registered `AgentFactory` will receive a map of key-value pairs from within the `agents` JSON section. 

Example:

```
{
  "agents": [
    {
      "name"       : "Localhost",
      "host"       : "localhost",
      "user"       : "username",
      "password"   : "password",
      "timeout"    : 5,
      "multiplier" : 1.5
    }
  ],
  "categories": {
    "big": [1, 2, 3],
    "enabled": false
  }
}
```

### System Properties ###

The SDK also accepts the following custom JVM parameters:

* `newrelic.platform.config.dir` - Allows you to specify where your configuration files are located. (Does not currently support `~` as a home alias)

## Logging ##

The SDK provides a simple logging framework that will log to both the console and to a configurable logging file. The logging configuration is managed through the `newrelic.json` file and the available options are outlined above in the [Config Options](#config-options) section.

Example configuration:

```
{
  "log_level": "debug",
  "log_file_name": "newrelic_plugin.log",
  "log_file_path": "./path/to/logs/newrelic",
  "log_limit_in_kbytes": 1024
}
```

**Note:** All logging configuration options are optional.
