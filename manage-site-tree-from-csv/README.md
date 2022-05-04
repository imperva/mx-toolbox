# MX WAF Site Tree and Security Policy Management 

The manage site tree from csv package enables users to manage the site tree in bulk from csv, as well as manage bulk security policies and the policy actions in bulk from csv.  This consists of 3 main Scripts.

## Getting Started

Download the latest files from the performance-monitoring folder.  Within this folder are 3 required files:

1. Bulk site tree import from csv file. Run once per MX to on-board sites; for n # of Sites in site tree, Server Groups, Services, Applications (includes application mapping, and will manage certificates).
    -	Script:  import-waf-site-tree-from-csv.py
    -	CSV Template: siteTree.csv
    -	SS Library:  ss.py
    -	Template Config:  template.config.json:
    
1. Bulk policy update from csv. Create a list of policy names and policy types (web service custom, firewall policy, profiling policy, protocol policy, etc).  Use baselinePolicies.csv template for format example.  The policies in the csv are considered the baseline set, and all policies created are set to the action of block.  However, Server Groups are all set to Simulation mode.
    -	Bulk Update Script:  update-policies-from-csv.py
    -	CSV Template:   baselinePolicies.csv
    -	SS Library:  ss.py
    -	Template Config:  template.config.json

1. Bulk create and apply policies in alert only.  Must run the export at least once from the GOLD MX (the MX with the baseline set of policies) so the json version of the policies are created locally to be referenced later.  Then run the duplicate script once against each MX that needs to be configured. 
    -	Script: export-waf-policies-to-json.py
    -	Duplicate and apply missing policies to assets in the site tree. Script: duplicate-waf-policies-alert-only-from-csv.py
    -	SS Library:  ss.py
    -	Template Config:  template.config.json

## Requirements: ##

1. Machine with network connectivity to the MX.
1.	Command Prompt or Terminal application process has access permission; check firewall allowed processes
1.	Python packages:
```
base64
csv
distutils
distutils util
requests.utils requote_uri
subprocess PIPE,Popen
time localtime, strftime
json
logging
os
pyparsing
requests
ss
sys
urllib
```

### To Run ###

```
$ python <script name> /path/to/my_waf_policies.csv
Example: python export-waf-policies-to-json.py /path/to/my_waf_policies.csv
```
 
### Troubleshoot ###
Test connectivity from Command Prompt application is established; check firewall allowed processes from cmd.exe
    - Run the following command to get a response back from the server.  This command will return a json error of bad credentials that will prove we can get there.
```
curl -ik -X POST -H "Authorization: Basic HGJKGHJKGHJGHJK="  https://1.2.3.4:8083/SecureSphere/api/v1/auth/session
```