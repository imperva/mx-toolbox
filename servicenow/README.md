# Imperva SecureSphere ServiceNow Integrations

The SecureSphere ServiceNow Integrations package consists of several scripts used to integrate SecureSphere's WAF and DAM produducts with the ServiceNow platform.  These integrations address the following use cases.

1. [Change Control Reconciliation](https://github.com/imperva/mx-toolbox/tree/master/servicenow/import_change_request_ids) - Import Change Request IDs into dataset to enrich audit data
1. [Update Change Request Records from Audit Data Report](https://github.com/imperva/mx-toolbox/tree/master/servicenow/update_change_request_records) - Update Change Request records with specific audit queries from report 
1. [Security Alert to Incident](https://github.com/imperva/mx-toolbox/tree/master/servicenow/alert_to_incident) - Create Incidents from security alerts
1. [Database Assessment Scan Results to Vulnerability Items](https://github.com/imperva/mx-toolbox/tree/master/servicenow/assessment_report_to_vulnerable_items) - Push all vulnerabilities from database assessment scans results to Vulnerable Items mapping to server SNOW Configuration Items referencing ip/hostname, and SNOW Vulnerabilities referencing CVEs

