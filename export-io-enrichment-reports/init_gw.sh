#!/bin/bash
SCRIPT_PATH='/var/user-data'

# download mx-toolbox scripts for performance monitoring
echo $SCRIPT_PATH
mkdir $SCRIPT_PATH
wget -O $SCRIPT_PATH/get_gateway_stats.py https://raw.githubusercontent.com/imperva/mx-toolbox/master/performance-monitoring/get_gateway_stats.py
chmod +x $SCRIPT_PATH/*

{ crontab -l; echo "* * * * * /usr/bin/python /var/user-data/get_gateway_stats.py"; } | crontab -

exit
