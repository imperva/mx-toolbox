#!/bin/bash
SCRIPT_PATH='/var/user-data'

# download mx-toolbox scripts for action-sets
echo $SCRIPT_PATH
mkdir $SCRIPT_PATH
wget -O $SCRIPT_PATH/ss.py https://raw.githubusercontent.com/imperva/mx-toolbox/master/export-io-enrichment-reports/ss.py 
wget -O $SCRIPT_PATH/export_report_to_s3.py https://raw.githubusercontent.com/imperva/mx-toolbox/master/export-io-enrichment-reports/export_report_to_s3.py
wget -O $SCRIPT_PATH/run_export_report_to_s3.sh https://raw.githubusercontent.com/imperva/mx-toolbox/master/export-io-enrichment-reports/run_export_report_to_s3.sh
chmod 776 $SCRIPT_PATH
chmod 776 $SCRIPT_PATH/*
chown mxserver:mxserver $SCRIPT_PATH
chown mxserver:mxserver $SCRIPT_PATH/*
chmod +x $SCRIPT_PATH/*

mkdir /opt/SecureSphere/server/.aws
cp ~/.aws/config /opt/SecureSphere/server/.aws
chown mxserver:mxserver /opt/SecureSphere/server/.aws
cp ~/.aws/config /opt/SecureSphere/server/.aws/config
chown mxserver:mxserver /opt/SecureSphere/server/.aws/config

if [ "$1" ]
then
      wget -O $SCRIPT_PATH/get_mx_stats.py https://raw.githubusercontent.com/imperva/mx-toolbox/master/performance-monitoring/get_mx_stats.py
      wget -O $SCRIPT_PATH/config.json https://raw.githubusercontent.com/imperva/mx-toolbox/master/performance-monitoring/template.config.json
      new_host=$(echo "$1" | sed -e 's/\//\\\//g')
      sed -i -e "s/http:\/\/1.2.3.4:8086\/write?db=imperva_performance_stats/${new_host}/g" $SCRIPT_PATH/config.json
      { crontab -l; echo "* * * * * /usr/bin/python /var/user-data/get_mx_stats.py"; } | crontab -
      { crontab -l; echo "*/5 * * * * /usr/bin/python /var/user-data/get_mx_stats.py get_server_stats"; } | crontab -
fi

exit
