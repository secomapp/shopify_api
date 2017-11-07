<?php
  namespace secomapp\shopify_api;

  use GuzzleHttp\json_encode;
  use GuzzleHttp\json_decode;

  class WcurlException extends \Exception { }
  class CurlException extends \Exception {  }
  class ApiException extends \Exception {
    protected $info;
    function __construct($info) {
      $this->info = $info;
      $errordetail = "ERROR DETAIL:".PHP_EOL
      ."response_headers".print_r($info ['response_headers'],true).PHP_EOL
      ."response".print_r($info ['response'],true).PHP_EOL;
//       parent::__construct ( $info ['response_headers'] ['http_status_message'], $info ['response_headers'] ['http_status_code'] );
      parent::__construct ( $errordetail, $info ['response_headers'] ['http_status_code'] );
    }
    function getInfo() {
      return $this->info;
    }
  }
  
  function wcurl($method, $url, $query='', $payload='', $request_headers=array(), &$response_headers=array(), $curl_opts=array())
  {
    $ch = curl_init(wcurl_request_uri($url, $query));
    wcurl_setopts($ch, $method, $payload, $request_headers, $curl_opts);
    $response = curl_exec($ch);
    $curl_info = curl_getinfo($ch);
    $error = curl_error($ch);
    $errorno = curl_errno($ch);
    curl_close($ch);
    if ($error) throw new WcurlException($error.PHP_EOL."Response:".PHP_EOL.json_encode($response,true), $errorno);
    $header_size = $curl_info["header_size"];
    $msg_header = substr($response, 0, $header_size);
    $msg_body = substr($response, $header_size);
    $response_headers = wcurl_response_headers($msg_header);
    return $msg_body;
  }
  function wcurl_request_uri($url, $query)
  {
    if (empty($query)) return $url;
    if (is_array($query)) return "$url?".http_build_query($query);
    else return "$url?$query";
  }
  function wcurl_setopts($ch, $method, $payload, $request_headers, $curl_opts)
  {
    $default_curl_opts = array
    (
      CURLOPT_HEADER => true,
      CURLOPT_RETURNTRANSFER => true,
      CURLOPT_FOLLOWLOCATION => true,
      CURLOPT_MAXREDIRS => 3,
      CURLOPT_SSL_VERIFYPEER => true,
      CURLOPT_SSL_VERIFYHOST => 2,
      CURLOPT_USERAGENT => 'wcurl',
      CURLOPT_CONNECTTIMEOUT => 120,
      CURLOPT_TIMEOUT => 120,
    );
    if ('GET' == $method)
    {
      $default_curl_opts[CURLOPT_HTTPGET] = true;
    }
    else
    {
      $default_curl_opts[CURLOPT_CUSTOMREQUEST] = $method;
      // Disable cURL's default 100-continue expectation
      if ('POST' == $method) array_push($request_headers, 'Expect:');
      if (!empty($payload))
      {
        if (is_array($payload))
        {
          $payload = http_build_query($payload);
          array_push($request_headers, 'Content-Type: application/x-www-form-urlencoded; charset=utf-8');
        }
        $default_curl_opts[CURLOPT_POSTFIELDS] = $payload;
      }
    }
    if (!empty($request_headers)) $default_curl_opts[CURLOPT_HTTPHEADER] = $request_headers;
    $overriden_opts = $curl_opts + $default_curl_opts;
    foreach ($overriden_opts as $curl_opt=>$value) curl_setopt($ch, $curl_opt, $value);
  }
  function wcurl_response_headers($msg_header)
  {
    $multiple_headers = preg_split("/\r\n\r\n|\n\n|\r\r/", trim($msg_header));
    $last_response_header_lines = array_pop($multiple_headers);
    $response_headers = array();
    $header_lines = preg_split("/\r\n|\n|\r/", $last_response_header_lines);
    list(, $response_headers['http_status_code'], $response_headers['http_status_message']) = explode(' ', trim(array_shift($header_lines)), 3);
    foreach ($header_lines as $header_line)
    {
      list($name, $value) = explode(':', $header_line, 2);
      $response_headers[strtolower($name)] = trim($value);
    }
    return $response_headers;
  }
  
  function install_url($shop, $api_key) {
    return "http://$shop/admin/api/auth?api_key=$api_key";
  }
  
  function is_valid_request($query_params, $shared_secret) {
    if (!isset($query_params['timestamp'])) return false;
    $seconds_in_a_day = 24 * 60 * 60;
    $older_than_a_day = $query_params ['timestamp'] < (time () - $seconds_in_a_day);
    if ($older_than_a_day)
      return false;
    
    $hmac = $query_params['hmac'];
    unset($query_params['hmac']);
    foreach ($query_params as $key=>$val) $params[] = "$key=$val";
    sort($params);
    return (hash_hmac('sha256', ''.implode('&', $params), $shared_secret, false) === $hmac);
  }
  
  function permission_url($shop, $api_key, $scope = array(), $redirect_uri = '') {
    $scope = empty ( $scope ) ? '' : '&scope=' . implode ( ',', $scope );
    $redirect_uri = empty ( $redirect_uri ) ? '' : '&redirect_uri=' . urlencode ( $redirect_uri );
    return "https://$shop/admin/oauth/authorize?client_id=$api_key$scope$redirect_uri";
  }
  
  function oauth_access_token($shop, $api_key, $shared_secret, $code) {
    return _api ( 'POST', "https://$shop/admin/oauth/access_token", NULL, array (
        'client_id' => $api_key,
        'client_secret' => $shared_secret,
        'code' => $code 
    ) );
  }
  
  function client($shop, $shops_token, $api_key, $shared_secret, $private_app = false) {
    $password = $shops_token;
    $baseurl = "https://$shop/";
    
    return function ($method, $path, $params = array(), &$response_headers = array()) use($baseurl, $shops_token) {
      setlocale(LC_ALL, "en_US.UTF8");
      $url = $baseurl . ltrim ( $path, '/' );
      $query = in_array ( $method, array (
          'GET',
          'DELETE' 
      ) ) ? $params : array ();
      $payload = in_array ( $method, array (
          'POST',
          'PUT' 
      ) ) ? json_encode ( $params ) : array ();
      
      $request_headers = array ();
      array_push ( $request_headers, "X-Shopify-Access-Token: $shops_token" );
      if (in_array ( $method, array (
          'POST',
          'PUT' 
      ) ))
        array_push ( $request_headers, "Content-Type: application/json; charset=utf-8" );
      
      return _api ( $method, $url, $query, $payload, $request_headers, $response_headers );
    };
  }
  
  function _api($method, $url, $query = '', $payload = '', $request_headers = array(), &$response_headers = array(), $loop = 0) {
    try {
      $response = wcurl ( $method, $url, $query, $payload, $request_headers, $response_headers );
    } catch ( WcurlException $e ) {
      throw new CurlException ( $e->getMessage (), $e->getCode () );
    }
    
    $response = json_decode ( $response, true );
    
    if (isset ( $response ['errors'] ) or ($response_headers ['http_status_code'] >= 400)) {
      if ($loop < 3 && ($response_headers ['http_status_code'] == 429 || calls_left ( $response_headers ) == 0)) {
        usleep ( 500000 ); // sleep 0.5 second and try again (max 3 times)
        $loop ++;
        return _api ( $method, $url, $query, $payload, $request_headers, $response_headers, $loop );
      }
      throw new ApiException ( compact ( 'method', 'path', 'params', 'response_headers', 'response', 'shops_myshopify_domain', 'shops_token' ) );
    }
    
    if (calls_left ( $response_headers ) > 0 && calls_left ( $response_headers ) <= 3) {
      usleep ( 100000 );
    }
    return (is_array ( $response ) and ! empty ( $response )) ? array_shift ( $response ) : $response;
  }
  
  function calls_made($response_headers) {
    return _shop_api_call_limit_param ( 0, $response_headers );
  }
  
  function call_limit($response_headers) {
    return _shop_api_call_limit_param ( 1, $response_headers );
  }
  
  function calls_left($response_headers) {
    if (calls_made ( $response_headers ) >= 0 && call_limit ( $response_headers ) > 0) {
      return call_limit ( $response_headers ) - calls_made ( $response_headers );
    } else {
      return -1;
    }
  }
  
  function _shop_api_call_limit_param($index, $response_headers) {
    try {
      if(isset($response_headers ['http_x_shopify_shop_api_call_limit'] )){
        $params = explode ( '/', $response_headers ['http_x_shopify_shop_api_call_limit'] );
        return ( int ) $params [$index];
      }
    } catch ( Exception $e ) {
    }
    return -1;
  }
  
  function legacy_token_to_oauth_token($shops_token, $shared_secret, $private_app = false) {
    return $private_app ? $secret : md5 ( $shared_secret . $shops_token );
  }
  
  function legacy_baseurl($shop, $api_key, $password) {
    return "https://$api_key:$password@$shop/";
  }

?>
