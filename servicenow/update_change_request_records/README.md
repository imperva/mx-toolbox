# SecureSphere ServiceNow Integration - Import Change Request IDs

This project provides the scripts and configuration steps needed to export audit records with valid change request numbers, and dynamically update the change request records in servicenow with the correlating change request numbers. 

#### Step 1: Download and copy script and config to the managemnt server (MX)

1. Download and copy the files into a new directory (/var/user-data) on the Management Server (MX):
    - SSH to the MX, and create the following directory, which is the supported folder for running custom scritps.  
        >`mkdir /var/user-data`
    - Download the following files and copy them into the the /var/user-data folder:  
        >`/servicenow/update_change_request_records/servicenow_update_tickets_with_queries.py`  
        `/template.config.json`  
        `/ss.py`  
    - Rename template.config.json to config.json  
        >`cd /var/user-data`  
        `mv template.config.json config.json`  
1. Update the configuration file with your endpoints and credentials, see **Configuration Options** below:
1. Update file permissions:
    - Make script executable, and change ownership of the file to the mxserver user, so the script can be executed from the action set.  
        > `chmod +x servicenow_update_tickets_with_queries.py`  
        `chmod mxserver:mxserver servicenow_update_tickets_with_queries.py`  
1. Create Action Set in the MX
    - Login to the MX, and navigate to Policies->Action Sets. Click the ![plus.png](images/plus.png) icon to add a new action set.  
    Name: `Push Audit to ServiceNow Change Tickets`  
    ![create-action-set-1.png](images/create-action-set-1.png)  
1. Click the ![up.png](images/up.png) icon to add `OS Command > Run a Shell Command` to add this action to the `Selected Actions` in the action set.
1. Click the ![expand.png](images/expand.png) button to expand the action configuration, add the following configuration parameters values, and click save  
    - Command: `servicenow_update_tickets_with_queries.py`  
    - Arguments: `${Job.attachment}`  
    - Working Dir: `/var/user-data`  
    - Run on Every Event: ![checked.png](images/checked.png)  
    ![create-action-set-2.png](images/create-action-set-2.png)    

1. Import the audit report, or create audit report from scratch. 
   ### Import report instructions ###
    - Navigate to Main->Reports->Manage Reports->Action->Import  
    Select update_change_request_records/assets/change_control_audit_report_export.imf, enter passphrase `auditreport` and click upload.  
    Ensure "Action Set" is correctly mapped to "Export report to S3" and click Import.
   ### Create audit report from scratch instructions ###
    - Navigate to Main->Reports->Manage Reports, and click the ![plus.png](images/plus.png) icon to add a new `DB Audit` report, enter the report name and click create.  
    Name: `Change Control Audit Report`
    - Configure the following parameters on the report and click Save.  
        * General Details->Followed Action: `Push Audit to ServiceNow Change Tickets`  
        * General Details->Format: `CSV`  
        * Data Scope->Selected Policies: Select all applicable policies  
        * Data Scope->Last `1` `Hours` 
        * Data Scope: Add `Ticket Assigned` as an enabled field using ![up.png](images/up.png), and select value of `True`  
        * Tabular: Add the following fields to the report, and click save:  
        ![report_tabular_config.png](images/report_tabular_config.png)
    - Select Action->Run Report to run the report.  
    - Log in to ServiceNow to validate that the audit queries are updated on the change requests with the correlating change request numbers.  
    [Example udpated change request screenshot](https://github.com/imperva/mx-toolbox/blob/master/servicenow/update_change_request_records/screenshots/change_request_example.png)
    

### Configuration Options ###

The script has one configuration file, which lives in the same directory as the script.

### config.json ###

The `config.json` configuration file is where New Relic specific configuration lives. 

Example:

```
{
    "log_level": "debug",
    "environment": "dev",
    "mx": {
        "endpoint": "https://127.0.0.1:8083",
        "username": "your_username",
        "password": "your_password_here"
    },
    "servicenow": {
        "endpoint": "http://your.service-now.com",
        "username": "your_username",
        "password": "your_password_here"
    }
}
```

#### Config Options ####

`log_level` - _(optional)_ the log level. Valid values: `debug`, `info`, `warn`, `error`, `fatal`. Defaults to `info`.

`environment` - _(optional)_ the logical environment the server operates in.  This value will be reported with every Event.  Ex. `dev`, `stage`, `uat`, `prod`.  Defaults to `dev`

`mx.endpoint` - _(required)_ endpoint of the mx, typically run from localhost/127.0.0.1

`mx.username` - _(required)_ the username of the user authenticating to the MX API 

`mx.password` - _(required)_ the password of the user authenticating to the MX API 

`servicenow.endpoint` - _(required)_ endpoint of the servicenow instance

`servicenow.username` - _(required)_ the username of the user authenticating to the servicenow API 

`servicenow.password` - _(required)_ the password of the user authenticating to the servicenow API 