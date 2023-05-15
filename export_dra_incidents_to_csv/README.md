# DRA export incident data to csv

Export all Data Risk Analytics (DRA) incidents via API into a csv for reporting purposes. 

## Getting Started

Download the latest files from the export_dra_incidents_to_csv folder.  Within this folder are 2 required files:

1. Download and copy the files into a new directory (/var/user-data) on the Data Risk Analytics (DRA) Server:
    - SSH to the DRA appliance, and create the following directory to run this script from.  
        >`mkdir /var/user-data`  
        `cd /var/user-data`  
    - Download the following files and copy them into the the /var/user-data folder on the MX:  
        >`export_dra_incidents_to_csv.py`  
        `template.config.json`  
    - Rename template.config.json to config.json  
        >`mv template.config.json config.json`  

## Configuration Options ##

The script has one configuration file, which lives in the same directory as the script. Update the `config.json` configuration with the DRA endpoint and credentials.  

#### Script usage ####
1. Run the script using the following: 
   `python export_dra_incidents_to_csv.py`
