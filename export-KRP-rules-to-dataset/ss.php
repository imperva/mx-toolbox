	<?php
/* 
 * Utility API functions file, include this library in any script to use the following functions.
 */
function ss_login() {
	if (CACHESESSION=="true") {
		$cursession = @file_get_contents(SESSIONPATH);
		$response = errorCheck(makeCall('/v1/administration/version','GET',(object)array(),$cursession));
		if (isset($response->{"errors"})) {
			$action = '/v1/auth/session';
			$curlstr='curl -ik -X POST -H "Authorization: Basic '.base64_encode(MX_USER.":".MX_PASS).'" '.MX_SERVER.$action;
			ba_error_log("Login Request for user '".MX_USER."' to MX:".MX_SERVER.$action." - Authorization: Basic ".base64_encode(MX_USER.":".MX_PASS));
			ba_error_log("ss_login | ".$curlstr);
			$post_header = array(
				"Content-Type: application/json",
				"Accept: application/json",
				"Content-Length: 0",
				"Authorization: Basic ".base64_encode(MX_USER.':'.MX_PASS)
			);
			$ch = curl_init(MX_SERVER.$action);
			curl_setopt($ch, CURLOPT_HEADER, 0);
			curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, 0);
			curl_setopt($ch, CURLOPT_CUSTOMREQUEST, 'POST');
			curl_setopt($ch, CURLOPT_HTTPHEADER, $post_header);
			curl_setopt($ch, CURLOPT_RETURNTRANSFER, 1);
			$response = errorCheck((object)json_decode(curl_exec($ch),true));
			ba_error_log("RESPONSE: ".json_encode($response));
			curl_close($ch);
			if (!isset($response->{"errors"})){
				file_put_contents(SESSIONPATH,$response->{'session-id'});
				ba_error_log("Login successful, assigning new session in ".SESSIONPATH);
				return($response->{'session-id'});		
			} else {
				ba_error_log("ERROR: INVALID CREDENTIALS ");
				exit();
			}
		} else {
			ba_error_log("ss_login | Login successful, use existing session in ".SESSIONPATH);
			return($cursession);
		}
	} else { 
		$action = '/v1/auth/session';
		$curlstr='curl -ik -X POST -H "Authorization: Basic '.base64_encode(MX_USER.":".MX_PASS).'" '.MX_SERVER.$action;
		ba_error_log("Login Request for user '".MX_USER."' to MX:".MX_SERVER.$action." - Authorization: Basic ".base64_encode(MX_USER.":".MX_PASS));
		ba_error_log("ss_login | ".$curlstr);
		$post_header = array(
			"Content-Type: application/json",
			"Accept: application/json",
			"Content-Length: 0",
			"Authorization: Basic ".base64_encode(MX_USER.':'.MX_PASS)
		);
		$ch = curl_init(MX_SERVER.$action);
		curl_setopt($ch, CURLOPT_HEADER, 0);
		curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, 0);
		curl_setopt($ch, CURLOPT_CUSTOMREQUEST, 'POST');
		curl_setopt($ch, CURLOPT_HTTPHEADER, $post_header);
		curl_setopt($ch, CURLOPT_RETURNTRANSFER, 1);
		$response = errorCheck((object)json_decode(curl_exec($ch),true));
		ba_error_log("RESPONSE: ".json_encode($response));
		curl_close($ch);
		return($response->{'session-id'});	
	}
}

function ss_login_by_MX($curServer,$curUser,$curPassword) {
	$action = '/v1/auth/session';
	$curlstr='curl -ik -X POST -H "Authorization: Basic '.base64_encode($curUser.":".$curPassword).'" '.$curServer.$action;
	ba_error_log("Login Request for user '".$curUser."' to MX:".$curServer.$action." - Authorization: Basic ".base64_encode($curUser.":".$curPassword));
	ba_error_log("ss_login | ".$curlstr);
	$post_header = array(
		"Content-Type: application/json",
		"Accept: application/json",
		"Content-Length: 0",
		"Authorization: Basic ".base64_encode($curUser.":".$curPassword)
	);
	$ch = curl_init($curServer.$action);
	curl_setopt($ch, CURLOPT_HEADER, 0);
	curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, 0);
	curl_setopt($ch, CURLOPT_CUSTOMREQUEST, 'POST');
	curl_setopt($ch, CURLOPT_HTTPHEADER, $post_header);
	curl_setopt($ch, CURLOPT_RETURNTRANSFER, 1);
	$response = errorCheck((object)json_decode(curl_exec($ch),true));
	ba_error_log("RESPONSE: ".json_encode($response));
	curl_close($ch);
	if (!isset($response->{"errors"})){
		#file_put_contents(SESSIONPATH,$response->{'session-id'});
		#ba_error_log("Login successful, assigning new session in ".SESSIONPATH);
		return(array("cur_mx_server"=>$curServer,"cursession"=>$response->{'session-id'}));
	} else {
		ba_error_log("ERROR: INVALID CREDENTIALS ");
		exit();
	}
}

function makeCall($action, $method, $json_data, $cursessionObj) {
	if (!isset($cursessionObj) || $cursessionObj==null) {
		$cursession=SESSION;
		$curMxServer=MX_SERVER;
	} else {
		$cursession=$cursessionObj["cursession"];
		$curMxServer=$cursessionObj["cur_mx_server"];		
	}
	$contentLength = '0';
	if ($method=='POST' || $method=='PUT') $contentLength = strlen(json_encode($json_data));
	$curlstr='curl -ik -X '.$method.' -H "Cookie: '.$cursession.'" -H "Content-Type: application/json" -H "Accept: application/json" ';	
	if ($method=='POST' || $method=='PUT') $curlstr.=" -d '".json_encode($json_data)."' ";
	$curlstr.=$curMxServer.str_replace(" ","%20",$action);
	ba_error_log("makeCall | ".$curlstr);
	$post_header = array(
		"Content-Type: application/json",
		"Content-Length: ".$contentLength,
		"Cookie: ".$cursession
	);
	$ch = curl_init($curMxServer.str_replace(" ","%20",$action));
	curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, false);
	curl_setopt($ch, CURLOPT_CUSTOMREQUEST, $method);
	curl_setopt($ch, CURLOPT_HTTPHEADER, $post_header);
	curl_setopt($ch, CURLOPT_RETURNTRANSFER, 1);
	if ($method=='POST' || $method=='PUT') {
		curl_setopt($ch, CURLOPT_POSTFIELDS, json_encode($json_data)); 
	}
	$response = errorCheck((object)json_decode(curl_exec($ch),true));
	ba_error_log("RESPONSE: ".json_encode($response));
	return($response);
}
// MX2 server API functions
function ss_login2() {
	if (CACHESESSION=="true") {
		$cursession = @file_get_contents(SESSIONPATH2);
		$response = errorCheck(makeCall2('/v1/administration/version','GET',(object)array(),$cursession));
		if (isset($response->{"errors"})) {
			$action = '/v1/auth/session';
			$curlstr='curl -ik -X POST -H "Authorization: Basic '.base64_encode(MX_USER2.":".MX_PASS2).'" '.MX_SERVER2.$action;
			ba_error_log("Login Request for user '".MX_USER2."' to MX:".MX_SERVER2.$action." - Authorization: Basic ".base64_encode(MX_USER2.":".MX_PASS2));
			ba_error_log("ss_login | ".$curlstr);
			$post_header = array(
				"Content-Type: application/json",
				"Accept: application/json",
				"Content-Length: 0",
				"Authorization: Basic ".base64_encode(MX_USER2.':'.MX_PASS2)
			);
			$ch = curl_init(MX_SERVER2.$action);
			curl_setopt($ch, CURLOPT_HEADER, 0);
			curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, 0);
			curl_setopt($ch, CURLOPT_CUSTOMREQUEST, 'POST');
			curl_setopt($ch, CURLOPT_HTTPHEADER, $post_header);
			curl_setopt($ch, CURLOPT_RETURNTRANSFER, 1);
			$response = errorCheck((object)json_decode(curl_exec($ch),true));
			ba_error_log("RESPONSE: ".json_encode($response));
			curl_close($ch);
			if (!isset($response->{"errors"})){
				file_put_contents(SESSIONPATH2,$response->{'session-id'});
				ba_error_log("ss_login2 | Login successful, assigning new session in ".SESSIONPATH2);
				return($response->{'session-id'});		
			} else {
				ba_error_log("ERROR: INVALID CREDENTIALS ");
				exit();
			}
		} else {
			ba_error_log("Login successful, use existing session in ".SESSIONPATH2);
			return($cursession);
		}
	} else { 
		$action = '/v1/auth/session';
		$curlstr='curl -ik -X POST -H "Authorization: Basic '.base64_encode(MX_USER2.":".MX_PASS2).'" '.MX_SERVER2.$action;
		ba_error_log("Login Request for user '".MX_USER2."' to MX:".MX_SERVER2.$action." - Authorization: Basic ".base64_encode(MX_USER2.":".MX_PASS2));
		ba_error_log("ss_login | ".$curlstr);
		$post_header = array(
			"Content-Type: application/json",
			"Accept: application/json",
			"Content-Length: 0",
			"Authorization: Basic ".base64_encode(MX_USER2.':'.MX_PASS2)
		);
		$ch = curl_init(MX_SERVER2.$action);
		curl_setopt($ch, CURLOPT_HEADER, 0);
		curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, 0);
		curl_setopt($ch, CURLOPT_CUSTOMREQUEST, 'POST');
		curl_setopt($ch, CURLOPT_HTTPHEADER, $post_header);
		curl_setopt($ch, CURLOPT_RETURNTRANSFER, 1);
		$response = errorCheck((object)json_decode(curl_exec($ch),true));
		ba_error_log("RESPONSE: ".json_encode($response));
		curl_close($ch);
		return($response->{'session-id'});	
	}
}
function makeCall2($action, $method, $json_data, $cursession) {
	if (!isset($cursession) || $cursession==null) $cursession=SESSION2;
	$contentLength = '0';
	if ($method=='POST' || $method=='PUT') $contentLength = strlen(json_encode($json_data));
	$curlstr='curl -ik -X '.$method.' -H "Cookie: '.$cursession.'" -H "Content-Type: application/json" -H "Accept: application/json" ';	
	if ($method=='POST' || $method=='PUT') $curlstr.=" -d '".json_encode($json_data)."' ";
	$curlstr.=MX_SERVER2.str_replace(" ","%20",$action);
	ba_error_log("makeCall2 | ".$curlstr);
	$post_header = array(
		"Content-Type: application/json",
		"Content-Length: ".$contentLength,
		"Cookie: ".$cursession
	);
	$ch = curl_init(MX_SERVER2.str_replace(" ","%20",$action));
	curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, false);
	curl_setopt($ch, CURLOPT_CUSTOMREQUEST, $method);
	curl_setopt($ch, CURLOPT_HTTPHEADER, $post_header);
	curl_setopt($ch, CURLOPT_RETURNTRANSFER, 1);
	if ($method=='POST' || $method=='PUT') {
		curl_setopt($ch, CURLOPT_POSTFIELDS, json_encode($json_data)); 
	}
	$response = errorCheck((object)json_decode(curl_exec($ch),true));
	ba_error_log("RESPONSE: ".json_encode($response));
	return($response);
}

function makeCallSOAP($body) {
	@$logDate = date("F j, Y, g:i a");
	$session = curl_init(REMEDY_SERVER);
	$post_header = array(
			"POST /services/v1.2/mir3 HTTP/1.0",
			"Content-Type: text/xml; charset=utf-8",
			"Accept: application/soap+xml",
			"Cache-Control: no-cache",
			"Pragma: no-cache",
			"SOAPAction: \"\""
	);
	curl_setopt($session, CURLOPT_POST, true);
	curl_setopt($session, CURLOPT_HTTPHEADER, $post_header);
	curl_setopt($session, CURLOPT_RETURNTRANSFER, 1);
	curl_setopt($session, CURLOPT_POSTFIELDS, $body);
	$response = curl_exec($session);
	
	if (curl_errno($session)) {
		throw new Exception("CURL Error: ".curl_error($session));
	} else {
		curl_close($session);
	}
	
	if (DEBUG) {
		error_log("=================START OnDemand Web Services =================\n\r");
		error_log($logDate." REQUEST:".$body."\n\r");
		error_log($logDate." RESPONSE:".$response."\n\r");
		error_log("=================END OnDemand Web Services =================\n\r");
	}
	
	error_log("=================START OnDemand Web Services =================\n\r");
	error_log($logDate." REQUEST:".$body."\n\r");
	error_log($logDate." RESPONSE:".$response."\n\r");
	error_log("=================END OnDemand Web Services =================\n\r");
	
	$response = str_replace("soapenv:","",$response);
	$response = str_replace("sf:","",$response);
	$response = str_replace("ns1:","",$response);
	$response = str_replace("ns0:","",$response);
	$response = str_replace(' xsi:type="QueryResult"',"",$response);
	$response = str_replace(' xsi:type="sObject"',"",$response);
	$response = str_replace(' xsi:nil="true"',"",$response);
	$responseDOM = simplexml_load_string($response);
	return($responseDOM->Body);
}


function errorCheck($response) {
	if (isset($response->{'errors'})) {
		ob_start();
		print_r($response);
		$str = ob_get_contents();
		ob_end_clean();
		if (DEBUG=='true') error_log($str." \n",3,LOGPATH);
	}
	return $response;
}

function ba_error_log($errstr){
	if (DEBUG=='true') {
		error_log(PHP_EOL.TIMESTAMP.' | '.$errstr.PHP_EOL,3,LOGPATH);
		print(PHP_EOL.TIMESTAMP.' | '.$errstr.PHP_EOL);
	}
}

function getMXIP(){
	return str_replace('server-address',"",str_replace(' ',"",exec('impctl gateway show --server-address')));
}

?>