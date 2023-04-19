# MX Manage Audit Policy Script

This script allows you to apply and un-apply a db service audit policy to a db service in the MX via API. 

## Example useage
  - Apply a policy to a single DB service:
  >`python apply_audit_policy_to_db_service.py "Default Rule - All Events" "Your Site/Server Group Name1/DB Service1" "POST"`
 
  - Apply a policy to multiple DB services:
  >`python apply_audit_policy_to_db_service.py "Default Rule - All Events" "Your Site/Server Group Name1/DB Service1, Server Group Name2/DB Service2" "POST"`

  - Un-apply a policy from a single DB services:
  >`python apply_audit_policy_to_db_service.py "Default Rule - All Events" "Your Site/Server Group Name1/DB Service1" "DELETE"`

  - Un-apply a policy from multiple DB services:
  >`python apply_audit_policy_to_db_service.py "Default Rule - All Events" "Your Site/Server Group Name1/DB Service1, Server Group Name2/DB Service2" "DELETE"`


#### Params ####

`0` - Name of your DB service audit policy 

`1` - String of comma separated list of site tree DB service paths (Site Name/Server Group Name/DB Service Name) to apply the policy to. Example:
  `"Your Site/Server Group Name1/DB Service1, Server Group Name2/DB Service2"`

`2` - METHOD to use in api
      - POST to apply policy 
      - DELETE to un-apply policy 

## Configuration Options ##

The script has one configuration file, which lives in the same directory as the script.

### config.json ###

The `config.json` configuration file is where New Relic specific configuration lives. 

Example:

```
{
  "log_level": "debug",
  "mx": {
    "endpoint": "https://127.0.0.1:8083",
    "username": "youruser",
    "password": "yourpassword"
  }
}
```

#### Config Options ####

`log_level` - _(optional)_ the log level. Valid values: `CRITICAL`, `ERROR`, `WARNING`, `INFO`, `DEBUG`, `NOTSET`. Defaults to `INFO`.

`mx.endpoint` - Endpoint of the MX

`mx.username` - Username of the user to connect to the MX via API

`mx.password` - Password of the user listed above used to connect to the MX via API
