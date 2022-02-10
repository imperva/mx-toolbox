#!/usr/bin/php
<?php
if (!isset($argv[1])) { 
	error_log(TIMESTAMP." | no report name found, please add the ${Job.attachment} placeholder as a command arguemnt to the action set.\n",3,LOGPATH);
	exit();
}
@define("TIMESTAMP",date("Y/m/d G:i:s"));
define("LOGPATH","exportKRPRulesToDataSet.log");
define("PATH2REPORT", '/opt/SecureSphere/server/SecureSphere/jakarta-tomcat-secsph/webapps/SecureSphere/'.$argv[1]);
#define("PATH2REPORT", $argv[1]);
define("CACHESESSION","false");
define("CREATE_DATASETS","false");
define("DATASET","ALL_KRP_Rules");
define("DEBUG","true");
include('ss.php');
define("MX_SERVER","https://[mxendpoint]:8083/SecureSphere/api");
define("MX_USER","your_username");
define("MX_PASS","your_password");
define("SESSION",ss_login());
$emptyJSONObj = (object)array();

$datasetObj = (object)array(/*"action"=>"add",*/"records"=>array());
$datasetCols = (object)array(
	"dataset-name"=>DATASET,
	"columns"=>array(
		(object)array("name"=>"key","key"=>true),
		(object)array("name"=>"Site","key"=>false),
		(object)array("name"=>"Server_Group","key"=>false),
		(object)array("name"=>"Service","key"=>false),
		(object)array("name"=>"Gateway_Group_Name","key"=>false),
		(object)array("name"=>"KRP_Alias_Name","key"=>false),
		(object)array("name"=>"Inbound_Port","key"=>false),
		(object)array("name"=>"Priority","key"=>false),
		(object)array("name"=>"Internal_Ip_Host","key"=>false),
		(object)array("name"=>"Outbound_Server_Port","key"=>false)
	)
);

if (CREATE_DATASETS=='true') {
	// check for datasets, if not exist, create on MX1
	$response = errorCheck(makeCall('/v1/conf/dataSets/'.DATASET.'/data','GET', $emptyObj,null));
	if (isset($response->{'errors'})) {
		ba_error_log('dataset "'.DATASET_WORKSTATION.'" does not exist, creating dataset');
		$response = errorCheck(makeCall('/v1/conf/dataSets/createDataset?caseSensitive=false','POST', $datasetCols));
	}
}

$file = file_get_contents(PATH2REPORT);
if($file) {
	$csvdata = explode("\n",preg_replace('/\r\n?/', "\n", $file));
	for ($rowNum = 1; $rowNum<count($csvdata); $rowNum++) {
		if (trim($csvdata[$rowNum])!='') {
			$row = str_getcsv($csvdata[$rowNum],",",'"');
			$krpInboundRulesData = makeCall('/v1/conf/webServices/'.$row[0].'/'.$row[1].'/'.$row[2].'/krpInboundRules', 'GET', $emptyJSONObj, null);
			if (count($krpInboundRulesData->{'inboundKrpRules'})>0) {
				foreach($krpInboundRulesData->{'inboundKrpRules'} as $inboundKrpRule) {
					foreach($inboundKrpRule['gatewayPorts'] as $port){
						$krpOutboundRulesData = makeCall('/v1/conf/webServices/'.$row[0].'/'.$row[1].'/'.$row[2].'/krpInboundRules/'.$inboundKrpRule['gatewayGroupName'].'/'.$inboundKrpRule['aliasName'].'/'.$port.'/krpOutboundRules', 'GET', $emptyJSONObj, null);
						foreach($krpOutboundRulesData->{'outboundKrpRules'} as $outboundRule){
							$datasetObj->{'records'}[] = array(
								"key"=>$inboundKrpRule['gatewayGroupName'].'_'.$inboundKrpRule['aliasName'].'_'.$outboundRule['internalIpHost'].'_'.$outboundRule['serverPort'],
								"Site"=>(string)$row[0],
								"Server_Group"=>(string)$row[1],
								"Service"=>(string)$row[2],
								"Gateway_Group_Name"=>(string)$inboundKrpRule['gatewayGroupName'],
								"KRP_Alias_Name"=>(string)$inboundKrpRule['aliasName'],
								"Inbound_Port"=>(string)$port,
								"Priority"=>(string)$outboundRule['priority'],
								"Internal_Ip_Host"=>(string)$outboundRule['internalIpHost'],
								"Outbound_Server_Port"=>(string)$outboundRule['serverPort']
							);
						}
					}
				}
			}
		}
	}
}
$response = makeCall('/v1/conf/dataSets/'.DATASET.'/data', 'POST', $datasetObj,null);
?>