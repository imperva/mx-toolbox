# Imperva SecureSphere MX-Toolbox

The SecureSphere MX-Toolbox is a general purpose repository for custom packages, integrations, and monitoring add-ons for the SecureSphere MX and Gateway appliances.  

1. [Alerts to New Relic](https://github.com/imperva/mx-toolbox/tree/master/servicenow/alert_to_incident) - Send alerts to New Relic via custom action set
1. [Camo CX-Discover Integration](https://github.com/imperva/mx-toolbox/tree/master/cx-discover) - Process CAMO classification .csv report to create table groups, and convert to json to push to S3
1. [ServiceNow Integration](https://github.com/imperva/mx-toolbox/tree/master/servicenow) - Alert to incident, change control reconciliation audit enrichment, close-the-loop updating change requests with queries, and vulnerability assessment export to CMDB and vulnerable items in ServiceNow 
1. [Export KRP Rules to Dataset](https://github.com/imperva/mx-toolbox/tree/master/export-KRP-rules-to-dataset) - Export KRP rules in the siote tree to .csv and upload to data set
1. [Export WAF Profile Learned Hosts to CSV](https://github.com/imperva/mx-toolbox/tree/master/export-learned-hosts) - Export all learned hosts in web profiles to .csv
1. [Export Table Groups to CSV](https://github.com/imperva/mx-toolbox/tree/master/export-table-groups-to-csv) - Export table groups to .csv
1. [MX WAF Security Policy Sync](https://github.com/imperva/mx-toolbox/tree/master/mx-policy-sync) - Replicate and sync security policies across multiple MXs in AWS
1. [MX and Gateway Performance Monitoring](https://github.com/imperva/mx-toolbox/tree/master/performance-monitoring) - Output performance data (CPU, counters, network stats, disk, etc) from both MX and Gateway appliances in near real-time simultaneously to new relic, influxdb/grafana, and/or to SIEM via syslog with uniquely indexed json.
