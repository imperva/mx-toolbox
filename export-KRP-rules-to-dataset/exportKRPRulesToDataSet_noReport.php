#!/usr/bin/php
<?php
@define("TIMESTAMP",date("Y/m/d G:i:s"));
define("LOGPATH","exportKRPRulesToDataSet.log");
define("CSVPATH","exportKRPRulesToDataSet".time().".csv");
define("CACHESESSION","false");
define("DEBUG","false");
include('ss.php');
$authAry = array(
	"https://[mxendpoint]:8083/SecureSphere/api"=>array(
		"username"=>"your_username",
		"password"=>"your_password"
	)
);
$emptyJSONObj = (object)array();

$csvdata = array(array("Site","Server_Group","Service","Gateway_Group_Name","KRP_Alias_Name","Inbound_Port","Priority","Internal_Ip_Host","Outbound_Server_Port","Gateway Name","KRP IP Address"));
foreach ($authAry as $curServer=>$auth) {
	$session=ss_login_by_MX($curServer,$auth["username"],$auth["password"]);
	$sites = makeCall('/v1/conf/sites', 'GET', $emptyJSONObj,$session);
	foreach ($sites->{'sites'} as $i=>$site) {
		$serverGroups = makeCall('/v1/conf/serverGroups/'.$site, 'GET', $emptyJSONObj,$session);	
		foreach ($serverGroups->{'server-groups'} as $i=>$serverGroup) {
			$webServices = makeCall('/v1/conf/webServices/'.$site.'/'.$serverGroup, 'GET', $emptyJSONObj,$session);	
			foreach ($webServices->{'web-services'} as $i=>$webService) {
				$krpInboundRulesData = makeCall('/v1/conf/webServices/'.$site.'/'.$serverGroup.'/'.$webService.'/krpInboundRules', 'GET', $emptyJSONObj, $session);
				if (count($krpInboundRulesData->{'inboundKrpRules'})>0) {
					foreach($krpInboundRulesData->{'inboundKrpRules'} as $inboundKrpRule) {
						foreach($inboundKrpRule['gatewayPorts'] as $port){
							$krpOutboundRulesData = makeCall('/v1/conf/webServices/'.$site.'/'.$serverGroup.'/'.$webService.'/krpInboundRules/'.$inboundKrpRule['gatewayGroupName'].'/'.$inboundKrpRule['aliasName'].'/'.$port.'/krpOutboundRules', 'GET', $emptyJSONObj, $session);
							$datasetRecords = makeCall('/v1/conf/dataSets/krp_alias/data', 'GET', $emptyJSONObj, $session);
							foreach($krpOutboundRulesData->{'outboundKrpRules'} as $outboundRule){
								foreach($datasetRecords->{'records'} as $record){
									if ($record['ALIAS']==$inboundKrpRule['aliasName']) {
										$recordAry = array();
										$recordAry[]=$site;
										$recordAry[]=$serverGroup;
										$recordAry[]=$webService;
										$recordAry[]=$inboundKrpRule['gatewayGroupName'];
										$recordAry[]=$inboundKrpRule['aliasName'];
										$recordAry[]=$port;
										$recordAry[]=$outboundRule['priority'];
										$recordAry[]=$outboundRule['internalIpHost'];
										$recordAry[]=$outboundRule['serverPort'];
										$recordAry[]=$record['GATEWAY_NAME'];
										$recordAry[]=$record['IP'];
										$csvdata[]=$recordAry;
									}
								}
							}
						}
					}
				}
			}
		}	
	}
}
#foreach ($csvdata as $records) { error_log(implode(",",$records)."\r\n",3,CSVPATH); }
foreach ($csvdata as $records) { error_log('"'.implode('","',$records).'"\r\n',3,CSVPATH); }

?>