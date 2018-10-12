<?php

namespace fyflzjz\oauth;

class QqConect
{
    const VERSION = "2.0";
    const GET_AUTH_CODE_URL = "https://graph.qq.com/oauth2.0/authorize";
    const GET_ACCESS_TOKEN_URL = "https://graph.qq.com/oauth2.0/token";
    const GET_OPENID_URL = "https://graph.qq.com/oauth2.0/me";

    protected $recorder;
    private $kesArr;
    private $APIMap;
    private $debug = true;
    private $config = [];

    /**
     * 构造方法
     *
     * @param string $access_token access_token value
     * @param string $openid       openid value
     */
    public function __construct($config = [], $access_token = "", $openid = "")
    {
        $this->config = $config;
        $this->recorder = new Recorder();

        //如果access_token和openid为空，则从session里去取，适用于demo展示情形
        if ($access_token === "" || $openid === "") {
            $this->keysArr = [
                "oauth_consumer_key" => (int)$this->config["app_id"],
                "access_token"       => $this->recorder->read("access_token"),
                "openid"             => $this->recorder->read("openid"),
            ];
        } else {
            $this->keysArr = [
                "oauth_consumer_key" => (int)$this->config["app_id"],
                "access_token"       => $access_token,
                "openid"             => $openid,
            ];
        }

        //初始化APIMap
        /*
         * 加#表示非必须，无则不传入url(url中不会出现该参数)， "key" => "val" 表示key如果没有定义则使用默认值val
         * 规则 array( baseUrl, argListArr, method)
         */
        $this->APIMap = [
            //qzone
            "addBlog"        => [
                "https://graph.qq.com/blog/add_one_blog",
                ["title", "format" => "json", "content" => null],
                "POST",
            ],
            "addTopic"       => [
                "https://graph.qq.com/shuoshuo/add_topic",
                ["richtype", "richval", "con", "#lbs_nm", "#lbs_x", "#lbs_y", "format" => "json", "#third_source"],
                "POST",
            ],
            "getUserInfo"    => [
                "https://graph.qq.com/user/get_user_info",
                ["format" => "json"],
                "GET",
            ],
            "addOneBlog"     => [
                "https://graph.qq.com/blog/add_one_blog",
                ["title", "content", "format" => "json"],
                "GET",
            ],
            "addAlbum"       => [
                "https://graph.qq.com/photo/add_album",
                ["albumname", "#albumdesc", "#priv", "format" => "json"],
                "POST",
            ],
            "uploadPic"      => [
                "https://graph.qq.com/photo/upload_pic",
                ["picture", "#photodesc", "#title", "#albumid", "#mobile", "#x", "#y", "#needfeed", "#successnum", "#picnum", "format" => "json"],
                "POST",
            ],
            "listAlbum"      => [
                "https://graph.qq.com/photo/list_album",
                ["format" => "json"],
            ],
            "addShare"       => [
                "https://graph.qq.com/share/add_share",
                ["title", "url", "#comment", "#summary", "#images", "format" => "json", "#type", "#playurl", "#nswb", "site", "fromurl"],
                "POST",
            ],
            "checkPage_fans" => [
                "https://graph.qq.com/user/check_page_fans",
                ["page_id" => "314416946", "format" => "json"],
            ],

            //wblog
            "addT"           => [
                "https://graph.qq.com/t/add_t",
                ["format" => "json", "content", "#clientip", "#longitude", "#compatibleflag"],
                "POST",
            ],
            "addPicT"        => [
                "https://graph.qq.com/t/add_pic_t",
                ["content", "pic", "format" => "json", "#clientip", "#longitude", "#latitude", "#syncflag", "#compatiblefalg"],
                "POST",
            ],
            "delT"           => [
                "https://graph.qq.com/t/del_t",
                ["id", "format" => "json"],
                "POST",
            ],
            "getRepostList"  => [
                "https://graph.qq.com/t/get_repost_list",
                ["flag", "rootid", "pageflag", "pagetime", "reqnum", "twitterid", "format" => "json"],
            ],
            "getInfo"        => [
                "https://graph.qq.com/user/get_info",
                ["format" => "json"],
            ],
            "getOtherInfo"   => [
                "https://graph.qq.com/user/get_other_info",
                ["format" => "json", "#name", "fopenid"],
            ],
            "getFanslist"    => [
                "https://graph.qq.com/relation/get_fanslist",
                ["format" => "json", "reqnum", "startindex", "#mode", "#install", "#sex"],
            ],
            "getIdollist"    => [
                "https://graph.qq.com/relation/get_idollist",
                ["format" => "json", "reqnum", "startindex", "#mode", "#install"],
            ],
            "addIdol"        => [
                "https://graph.qq.com/relation/add_idol",
                ["format" => "json", "#name-1", "#fopenids-1"],
                "POST",
            ],
            "delIdol"        => [
                "https://graph.qq.com/relation/del_idol",
                ["format" => "json", "#name-1", "#fopenid-1"],
                "POST",
            ],
            //pay
            "getTenpayAddr"  => [
                "https://graph.qq.com/cft_info/get_tenpay_addr",
                ["ver" => 1, "limit" => 5, "offset" => 0, "format" => "json"],
            ],
        ];
    }

    /**
     * 魔术方法，做api调用转发
     *
     * @param string $name 调用的方法名称
     * @param array  $arg  参数列表数组
     *
     * @return array 返加调用结果数组
     */
    public function __call($name, $arg)
    {
        //如果APIMap不存在相应的api
        if (empty($this->APIMap[ $name ])) {
            $this->showError("api调用名称错误", "不存在的API: $name");
        }

        //从APIMap获取api相应参数
        $baseUrl = $this->APIMap[ $name ][0];
        $argsList = $this->APIMap[ $name ][1];
        $method = isset($this->APIMap[ $name ][2]) ? $this->APIMap[ $name ][2] : "GET";

        if (empty($arg)) {
            $arg[0] = null;
        }

        //对于get_tenpay_addr，特殊处理，php json_decode对\xA312此类字符支持不好
        if ($name != "get_tenpay_addr") {
            $response = json_decode($this->_applyAPI($arg[0], $argsList, $baseUrl, $method));
            $responseArr = $this->objToArr($response);
        } else {
            $responseArr = $this->simple_json_parser($this->_applyAPI($arg[0], $argsList, $baseUrl, $method));
        }

        //检查返回ret判断api是否成功调用
        if ($responseArr['ret'] == 0) {
            return $responseArr;
        } else {
            $this->showError($response->ret, $response->msg);
        }

    }

    /**
     * 显示错误信息
     *
     * @param int    $code        错误代码
     * @param string $description 描述信息（可选）
     */
    private function showError($code, $description = '$')
    {
        $errorMsg = [
            "20001" => "配置文件损坏或无法读取，请重新执行intall",
            "30001" => "The state does not match. You may be a victim of CSRF.",
            "50001" => "可能是服务器无法请求https协议,可能未开启curl支持,请尝试开启curl支持，重启web服务器，如果问题仍未解决，请联系我们",
        ];

        if (!$this->debug) {
            return false;
        }
        if ($description == '$') {
            $description = isset($errorMsg[ $code ]) ? $errorMsg[ $code ] : '';
        }

        echo json_encode(['code' => $code, 'msg' => $description, 'data' => '']);
        exit();
    }

    private function _applyAPI($arr, $argsList, $baseUrl, $method)
    {
        $pre = "#";
        $keysArr = $this->keysArr;

        $optionArgList = [];//一些多项选填参数必选一的情形
        foreach ($argsList as $key => $val) {
            $tmpKey = $key;
            $tmpVal = $val;

            if (!is_string($key)) {
                $tmpKey = $val;

                if (strpos($val, $pre) === 0) {
                    $tmpVal = $pre;
                    $tmpKey = substr($tmpKey, 1);
                    if (preg_match("/-(\d$)/", $tmpKey, $res)) {
                        $tmpKey = str_replace($res[0], "", $tmpKey);
                        $optionArgList[ $res[1] ][] = $tmpKey;
                    }
                } else {
                    $tmpVal = null;
                }
            }

            //-----如果没有设置相应的参数
            if (!isset($arr[ $tmpKey ]) || $arr[ $tmpKey ] === "") {

                if ($tmpVal == $pre) {//则使用默认的值
                    continue;
                } else if ($tmpVal) {
                    $arr[ $tmpKey ] = $tmpVal;
                } else {
                    if ($v = $_FILES[ $tmpKey ]) {

                        $filename = dirname($v['tmp_name']) . "/" . $v['name'];
                        move_uploaded_file($v['tmp_name'], $filename);
                        $arr[ $tmpKey ] = "@$filename";

                    } else {
                        $this->showError("api调用参数错误", "未传入参数$tmpKey");
                    }
                }
            }

            $keysArr[ $tmpKey ] = $arr[ $tmpKey ];
        }
        //检查选填参数必填一的情形
        foreach ($optionArgList as $val) {
            $n = 0;
            foreach ($val as $v) {
                if (in_array($v, array_keys($keysArr))) {
                    $n++;
                }
            }

            if (!$n) {
                $str = implode(",", $val);
                $this->showError("api调用参数错误", $str . "必填一个");
            }
        }

        if ($method == "POST") {
            if ($baseUrl == "https://graph.qq.com/blog/add_one_blog") $response = $this->post($baseUrl, $keysArr, 1);
            else $response = $this->post($baseUrl, $keysArr, 0);
        } else if ($method == "GET") {
            $response = $this->get($baseUrl, $keysArr);
        }

        return $response;

    }

    /**
     * post方式请求资源
     *
     * @param string $url     基于的baseUrl
     * @param array  $keysArr 请求的参数列表
     * @param int    $flag    标志位
     *
     * @return string           返回的资源内容
     */
    private function post($url, $keysArr, $flag = 0)
    {

        $ch = curl_init();
        if (!$flag) curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, false);
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
        curl_setopt($ch, CURLOPT_POST, true);
        curl_setopt($ch, CURLOPT_POSTFIELDS, $keysArr);
        curl_setopt($ch, CURLOPT_URL, $url);
        $ret = curl_exec($ch);

        curl_close($ch);

        return $ret;
    }

    /**
     * get方式请求资源
     *
     * @param string $url     基于的baseUrl
     * @param array  $keysArr 参数列表数组
     *
     * @return string         返回的资源内容
     */
    private function get($url, $keysArr)
    {
        $combined = $this->combineURL($url, $keysArr);

        return $this->getContents($combined);
    }

    /**
     * 拼接url
     *
     * @param string $baseURL 基于的url
     * @param array  $keysArr 参数列表数组
     *
     * @return string           返回拼接的url
     */
    private function combineURL($baseURL, $keysArr)
    {
        $combined = $baseURL . "?";
        $valueArr = [];

        foreach ($keysArr as $key => $val) {
            $valueArr[] = "$key=$val";
        }

        $keyStr = implode("&", $valueArr);
        $combined .= ($keyStr);

        return $combined;
    }

    /**
     * 服务器通过get请求获得内容
     *
     * @param string $url 请求的url,拼接后的
     *
     * @return string           请求返回的内容
     */
    private function getContents($url)
    {
        if (ini_get("allow_url_fopen") == "1") {
            $response = file_get_contents($url);
        } else {
            $ch = curl_init();
            curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, false);
            curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
            curl_setopt($ch, CURLOPT_URL, $url);
            $response = curl_exec($ch);
            curl_close($ch);
        }

        //请求为空
        if (empty($response)) {
            $this->showError("50001");
        }

        return $response;
    }

    /**
     * 对象到数组转换
     *
     * @param $obj
     *
     * @return array
     */
    private function objToArr($obj)
    {
        if (!is_object($obj) && !is_array($obj)) {
            return $obj;
        }
        $arr = [];
        foreach ($obj as $k => $v) {
            $arr[ $k ] = $this->objToArr($v);
        }

        return $arr;
    }

    /**
     * 简单实现json到php数组转换功能
     *
     * @param $json
     *
     * @return array
     */
    private function simple_json_parser($json)
    {
        $json = str_replace("{", "", str_replace("}", "", $json));
        $jsonValue = explode(",", $json);
        $arr = [];
        foreach ($jsonValue as $v) {
            $jValue = explode(":", $v);
            $arr[ str_replace('"', "", $jValue[0]) ] = (str_replace('"', "", $jValue[1]));
        }

        return $arr;
    }

    /**
     * QQ登录
     */
    public function qqLogin()
    {
        $appid = $this->config["app_id"];
        $callback = $this->config["callback"];

        //生成唯一随机串防CSRF攻击
        $state = md5(uniqid(rand(), true));
        $this->recorder->write('state', $state);

        //构造请求参数列表
        $keysArr = [
            "response_type" => "code",
            "client_id"     => $appid,
            "redirect_uri"  => $callback,
            "state"         => $state,
            "scope"         => 'get_user_info',
        ];
        $login_url = $this->combineURL(self::GET_AUTH_CODE_URL, $keysArr);

        header("Location:$login_url");
    }

    public function qqCallback()
    {
        $state = $this->recorder->read("state");

        //验证state防止CSRF攻击
        if (!$state || $_GET['state'] != $state) {
            $this->showError("30001");
        }

        //请求参数列表
        $keysArr = [
            "grant_type"    => "authorization_code",
            "client_id"     => $this->config["app_id"],
            "client_secret" => $this->config["appkey"],
            "redirect_uri"  => urlencode($this->config["callback"]),
            "code"          => $_GET['code'],
        ];

        //构造请求access_token的url
        $token_url = $this->combineURL(self::GET_ACCESS_TOKEN_URL, $keysArr);
        $response = $this->getContents($token_url);

        if (strpos($response, "callback") !== false) {

            $lpos = strpos($response, "(");
            $rpos = strrpos($response, ")");
            $response = substr($response, $lpos + 1, $rpos - $lpos - 1);
            $msg = json_decode($response);

            if (isset($msg->error)) {
                $this->showError($msg->error, $msg->error_description);
            }
        }

        $params = [];
        parse_str($response, $params);

        $this->recorder->write("access_token", $params["access_token"]);

        //该access token的有效期，单位为秒
        $this->recorder->write("expires_in", $params["expires_in"]);

        //在授权自动续期步骤中，获取新的Access_Token时需要提供的参数
        $this->recorder->write("refresh_token", $params["refresh_token"]);

        return $params;
    }

    /**
     * 刷新access_token
     */
    public function refreshAccessToken()
    {

        $refresh_token = $this->recorder->read("refresh_token");
        if(!$refresh_token){
            return [];
        }

        //请求参数列表
        $keysArr = [
            "grant_type"    => "refresh_token",
            "client_id"     => $this->config["app_id"],
            "client_secret" => $this->config["appkey"],
            "refresh_token" => $refresh_token,
        ];

        //构造请求access_token的url
        $token_url = $this->combineURL(self::GET_ACCESS_TOKEN_URL, $keysArr);
        $response = $this->getContents($token_url);

        if (strpos($response, "callback") !== false) {

            $lpos = strpos($response, "(");
            $rpos = strrpos($response, ")");
            $response = substr($response, $lpos + 1, $rpos - $lpos - 1);
            $msg = json_decode($response);

            if (isset($msg->error)) {
                $this->showError($msg->error, $msg->error_description);
            }
        }

        $params = [];
        parse_str($response, $params);

        $this->recorder->write("access_token", $params["access_token"]);

        //该access token的有效期，单位为秒
        $this->recorder->write("expires_in", $params["expires_in"]);

        //在授权自动续期步骤中，获取新的Access_Token时需要提供的参数
        $this->recorder->write("refresh_token", $params["refresh_token"]);

        return $params;
    }

    /**
     * 获取openid
     *
     * @return mixed
     */
    public function getOpenid()
    {
        //请求参数列表
        $keysArr = [
            "access_token" => $this->recorder->read("access_token"),
        ];

        $graph_url = $this->combineURL(self::GET_OPENID_URL, $keysArr);
        $response = $this->getContents($graph_url);

        //检测错误是否发生
        if (strpos($response, "callback") !== false) {

            $lpos = strpos($response, "(");
            $rpos = strrpos($response, ")");
            $response = substr($response, $lpos + 1, $rpos - $lpos - 1);
        }

        $user = json_decode($response);
        if (isset($user->error)) {
            $this->showError($user->error, $user->error_description);
        }

        //记录openid
        $this->recorder->write("openid", $user->openid);

        return $user->openid;
    }

    /**
     * 获得access_token
     *
     * @param void
     *
     * @since 5.0
     * @return string 返加access_token
     */
    public function getAccessToken()
    {
        return $this->recorder->read("access_token");
    }

}

class Recorder
{
    private static $data;
    private $inc;

    public function init()
    {
        if (empty($_SESSION['QC_userData'])) {
            self::$data = [];
        } else {
            self::$data = $_SESSION['QC_userData'];
        }
    }

    public function write($name, $value)
    {
        self::$data[ $name ] = $value;
    }

    public function read($name)
    {
        if (empty(self::$data[ $name ])) {
            return null;
        } else {
            return self::$data[ $name ];
        }
    }

    public function readInc($name)
    {
        if (empty($this->inc->$name)) {
            return null;
        } else {
            return $this->inc->$name;
        }
    }

    public function delete($name)
    {
        unset(self::$data[ $name ]);
    }

    function __destruct()
    {
        $_SESSION['QC_userData'] = self::$data;
    }
}
