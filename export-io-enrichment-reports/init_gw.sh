#!/bin/bash
SCRIPT_PATH='/var/user-data'

# download mx-toolbox scripts for performance monitoring
echo $SCRIPT_PATH
mkdir $SCRIPT_PATH

if [ "$1" ]
then
      wget -O $SCRIPT_PATH/get_mx_stats.py https://raw.githubusercontent.com/imperva/mx-toolbox/master/performance-monitoring/get_gateway_stats.py
      wget -O $SCRIPT_PATH/config.json https://raw.githubusercontent.com/imperva/mx-toolbox/master/performance-monitoring/template.config.json
      new_host=$(echo "$1" | sed -e 's/\//\\\//g')
      sed -i -e "s/http:\/\/1.2.3.4:8086\/write?db=imperva_performance_stats/${new_host}/g" config.json
      { crontab -l; echo "* * * * * /usr/bin/python /var/user-data/get_gateway_stats.py"; } | crontab -
fi

exit
