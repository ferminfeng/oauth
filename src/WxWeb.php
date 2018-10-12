<?php

namespace fyflzjz\oauth;

class WxWeb
{
    private $_get_auth_url = 'https://open.weixin.qq.com/connect/oauth2/authorize';
    private $_get_access_token_url = 'https://api.weixin.qq.com/sns/oauth2/access_token';
    private $_get_refresh_token = 'https://api.weixin.qq.com/sns/oauth2/refresh_token';
    private $_get_user_info_url = 'https://api.weixin.qq.com/sns/userinfo';
    private $_get_session_key = 'https://api.weixin.qq.com/sns/jscode2session?grant_type=authorization_code';
    private $_code;
    private $_access_token;
    private $_refresh_token;
    private $_openid;
    private $_session_key;
    private $_wx_appid;
    private $_wx_secret;
    private $_redirect_uri;

    /**
     * 构造方法
     *
     * @param array  $config
     * @param string $code
     * @param string source  h5 :h5第三方登录  wxa:微信小程序第三方登录
     */
    public function __construct($config, $code = '', $source = 'h5')
    {
        $this->_code = $code;
        if ($source == 'h5') {
            $this->_wx_appid = $config['app_id'];
            $this->_wx_secret = $config['app_secret'];
            $this->_redirect_uri = isset($config['callback']) ? $config['callback'] : '';
        } else {
            $this->_wx_appid = $config['appid'];
            $this->_wx_secret = $config['secret'];
            $this->_redirect_uri = isset($config['callback']) ? $config['callback'] : '';
        }
    }

    /**
     * H5获取access_token
     * access_token 有效期两小时
     * refresh_token 有效期30天
     */
    public function InitToken()
    {
        $token_url = $this->_get_access_token_url . '?appid=' . $this->_wx_appid . '&secret=' . $this->_wx_secret . '&code=' . $this->_code . '&grant_type=authorization_code';
        $res = $this->getUrlRes($token_url);

        //解析json
        $token_info = json_decode($res, true);

        /*
         * 请求成功
         * {"access_token":"ACCESS_TOKEN","expires_in":7200,"refresh_token":"REFRESH_TOKEN","openid":"OPENID","scope":"SCOPE"}
         * 请求失败
         * {"errcode":40029,"errmsg":"invalid code"}
         */
        return $token_info;
    }

    /**
     * 刷新access_token
     *
     * @param $refresh_token
     *
     * @return mixed
     */
    public function refreshAccessToken($refresh_token){
        $token_url = $this->_get_access_token_url . '?appid=' . $this->_wx_appid . '&refresh_token=' . $refresh_token . '&grant_type=refresh_token';
        $res = $this->getUrlRes($token_url);

        //解析json
        $token_info = json_decode($res, true);
        return $token_info;
    }

    /**
     * 小程序微信登录获取session_key+openid
     */
    public function InitSessionKey()
    {

        $token_url = $this->_get_session_key . '&appid=' . $this->_wx_appid . '&secret=' . $this->_wx_secret . '&js_code=' . $this->_code;
        $res = $this->getUrlRes($token_url);

        //解析json
        $token_info = json_decode($res, true);

        /**
         * 正常返回的JSON数据包
         * {"openid": "OPENID","session_key": "SESSIONKEY"}
         * 错误时返回JSON数据包(示例为Code无效)
         * {"errcode": 40029,"errmsg": "invalid code"}
         */
        if ($token_info && isset($token_info['openid']) && isset($token_info['session_key'])) {
            $this->setSessionKey($token_info['session_key']);   //设置session_key
            $this->setOpenId($token_info['openid']); //设置openid
        }
        return $token_info;
    }


    /**
     * 通过url获取内容
     *
     * @param $url
     *
     * @return bool|mixed
     */
    public function getUrlRes($url)
    {
        //初始化curl
        $ch = curl_init();
        //设置超时
        curl_setopt($ch, CURLOPT_TIMEOUT, 30);
        curl_setopt($ch, CURLOPT_URL, $url);
        curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, false);
        curl_setopt($ch, CURLOPT_SSL_VERIFYHOST, false);
        curl_setopt($ch, CURLOPT_HEADER, false);
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
        //运行curl，结果以jason形式返回
        $res = curl_exec($ch);
        curl_close($ch);

        if (!$res) {
            return false;
        }

        return $res;
    }

    /**
     * 微信登录
     */
    public function wxLogin()
    {
        $login_url = $this->_get_auth_url . '?appid=' . $this->_wx_appid . '&redirect_uri=' . urlencode($this->_redirect_uri) . '&response_type=code&scope=snsapi_userinfo&state=1#wechat_redirect';

        header("Location:" . $login_url);
    }

    /**
     * 获取用户信息
     * https://open.weixin.qq.com/cgi-bin/showdocument?action=dir_list&t=resource/res_list&verify=1&id=open1419316518&token=&lang=zh_CN
     *
     * @param $access_token
     * @param $openid
     *
     * @return mixed
     * {"openid":"OPENID","nickname":"NICKNAME","sex":1,"province":"PROVINCE",
    * "city":"CITY","country":"COUNTRY","headimgurl": "http://wx.qlogo.cn/mmopen/g3MonUZtNHkdmzicIlibx6iaFqAc56vxLSUfpb6n5WKSYVY0ChQKkiaJSgQ1dZuTOgvLLrhJbERQQ4eMsv84eavHiaiceqxibJxCfHe/0",
    * "privilege":["PRIVILEGE1","PRIVILEGE2"],"unionid": " o6_bmasdasdsad6_2sgVt7hMZOPfL"}
     * {"errcode":40003,"errmsg":"invalid openid"}
     */
    public function getUserInfo($access_token, $openid)
    {

        $user_info_url = $this->_get_user_info_url . '?access_token=' . $access_token . '&openid=' . $openid . '&lang=zh_CN';
        $res = $this->getUrlRes($user_info_url);

        //解析json
        $user_info = json_decode($res, true);

        return $user_info;
    }

    /**
     * 设置openid
     *
     * @param $openid
     */
    private function setOpenId($openid)
    {
        $this->_openid = $openid;
    }

    public function getOpenId()
    {
        if (empty($this->_openid)) {
            return false;
        } else {
            return $this->_openid;
        }
    }

    /**
     * access_token
     *
     * @param $access_token
     */
    private function setAccessToken($access_token)
    {
        $this->_access_token = $access_token;
    }

    public function getAccessToken()
    {
        if (empty($this->_access_token)) {
            return false;
        } else {
            return $this->_access_token;
        }
    }

    /**
     * 设置token
     *
     * @param $refresh_token
     */
    private function setRefreshToken($refresh_token)
    {
        $this->_refresh_token = $refresh_token;
    }

    public function getRefreshToken()
    {
        if (empty($this->_refresh_token)) {
            return false;
        } else {
            return $this->_refresh_token;
        }
    }

    /**
     * 设置session_key
     *
     * @param $session_key
     */
    private function setSessionKey($session_key)
    {
        $this->_session_key = $session_key;
    }

    public function getSessionKey()
    {
        if (empty($this->_session_key)) {
            return false;
        } else {
            return $this->_session_key;
        }
    }

    /**
     * 对微信小程序用户加密数据的解密
     */
    public function wxBizDataCrypt($sessionKey, $encryptedData, $iv)
    {
        require_once dirname(__FILE__) . '/wxa/wxBizDataCrypt.php';

        $appid = $this->_wx_appid;
        $pc = new WXBizDataCrypt($appid, $sessionKey);
        $errCode = $pc->decryptData($encryptedData, $iv, $data);

        if ($errCode == 0) {
            return json_decode($data, true);
        } else {
            return false;
        }
    }

    /**
     * 生成小程序码
     *
     * @param $scene
     *
     * @return mixed
     */
    public function getwxacode($scene)
    {
        $token_url = 'https://api.weixin.qq.com/cgi-bin/token?grant_type=client_credential' . '&appid=' . $this->_wx_appid . '&secret=' . $this->_wx_secret;
        $res = $this->getUrlRes($token_url);

        //解析json
        $token_info = json_decode($res, true);

        $access_token = $token_info['access_token'];

        $data = [
            "path"  => $scene,
            "width" => "430",
        ];

        $get_url = 'https://api.weixin.qq.com/cgi-bin/wxaapp/createwxaqrcode?access_token=' . $access_token;

        $post_str = json_encode($data);

        $post_datas = self::curlpost($get_url, $post_str);

        return $post_datas;

    }

    public function curlpost($url, $data_string)
    {
        $ch = curl_init();
        curl_setopt($ch, CURLOPT_URL, $url);
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, 1);

        curl_setopt(
            $ch, CURLOPT_HTTPHEADER, [
            'X-AjaxPro-Method:ShowList',
            'User-Agent:Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/33.0.1750.154 Safari/537.36',
        ]);
        curl_setopt($ch, CURLOPT_POST, 1);
        curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, false);
        curl_setopt($ch, CURLOPT_POSTFIELDS, $data_string);
        $data = curl_exec($ch);
        curl_close($ch);

        return $data;
    }

}

/**
 * 对微信小程序用户加密数据的解密示例代码.
 *
 * @copyright Copyright (c) 1998-2014 Tencent Inc.
 */
class WXBizDataCrypt
{

    private $appid;
    private $sessionKey;

    /**
     * 构造函数
     *
     * @param $sessionKey string 用户在小程序登录后获取的会话密钥
     * @param $appid      string 小程序的appid
     */
    public function WXBizDataCrypt($appid, $sessionKey)
    {
        $this->sessionKey = $sessionKey;
        $this->appid = $appid;
    }

    /**
     * 检验数据的真实性，并且获取解密后的明文.
     *
     * @param $encryptedData string 加密的用户数据
     * @param $iv            string 与用户数据一同返回的初始向量
     * @param $data          string 解密后的原文
     *
     * @return int 成功0，失败返回对应的错误码
     */
    public function decryptData($encryptedData, $iv, &$data)
    {
        if (strlen($this->sessionKey) != 24) {
            return ErrorCode::$IllegalAesKey;
        }
        $aesKey = base64_decode($this->sessionKey);


        if (strlen($iv) != 24) {
            return ErrorCode::$IllegalIv;
        }
        $aesIV = base64_decode($iv);

        $aesCipher = base64_decode($encryptedData);

        $pc = new Prpcrypt($aesKey);
        $result = $pc->decrypt($aesCipher, $aesIV);

        if ($result[0] != 0) {
            return $result[0];
        }

        $dataObj = json_decode($result[1]);
        if ($dataObj == null) {
            return ErrorCode::$IllegalBuffer;
        }
        if ($dataObj->watermark->appid != $this->appid) {
            return ErrorCode::$IllegalBuffer;
        }
        $data = $result[1];

        return ErrorCode::$OK;
    }

}

/**
 * PKCS7Encoder class
 *
 * 提供基于PKCS7算法的加解密接口.
 */
class PKCS7Encoder
{

    public static $block_size = 16;

    /**
     * 对需要加密的明文进行填充补位
     *
     * @param $text 需要进行填充补位操作的明文
     *
     * @return 补齐明文字符串
     */
    function encode($text)
    {
        $block_size = PKCS7Encoder::$block_size;
        $text_length = strlen($text);
        //计算需要填充的位数
        $amount_to_pad = PKCS7Encoder::$block_size - ($text_length % PKCS7Encoder::$block_size);
        if ($amount_to_pad == 0) {
            $amount_to_pad = PKCS7Encoder::block_size;
        }
        //获得补位所用的字符
        $pad_chr = chr($amount_to_pad);
        $tmp = "";
        for ($index = 0; $index < $amount_to_pad; $index++) {
            $tmp .= $pad_chr;
        }

        return $text . $tmp;
    }

    /**
     * 对解密后的明文进行补位删除
     *
     * @param decrypted 解密后的明文
     *
     * @return 删除填充补位后的明文
     */
    function decode($text)
    {

        $pad = ord(substr($text, -1));
        if ($pad < 1 || $pad > 32) {
            $pad = 0;
        }

        return substr($text, 0, (strlen($text) - $pad));
    }

}

/**
 * Prpcrypt class
 */
class Prpcrypt
{

    public $key;

    function Prpcrypt($k)
    {
        $this->key = $k;
    }

    /**
     * 对密文进行解密
     *
     * @param string $aesCipher 需要解密的密文
     * @param string $aesIV     解密的初始向量
     *
     * @return string 解密得到的明文
     */
    public function decrypt($aesCipher, $aesIV)
    {

        try {

            $module = mcrypt_module_open(MCRYPT_RIJNDAEL_128, '', MCRYPT_MODE_CBC, '');

            mcrypt_generic_init($module, $this->key, $aesIV);

            //解密
            $decrypted = mdecrypt_generic($module, $aesCipher);
            mcrypt_generic_deinit($module);
            mcrypt_module_close($module);
        } catch (Exception $e) {
            return [ErrorCode::$IllegalBuffer, null];
        }


        try {
            //去除补位字符
            $pkc_encoder = new PKCS7Encoder;
            $result = $pkc_encoder->decode($decrypted);
        } catch (Exception $e) {
            //print $e;
            return [ErrorCode::$IllegalBuffer, null];
        }

        return [0, $result];
    }

}

/**
 * error code 说明.
 * <ul>
 *    <li>-41001: encodingAesKey 非法</li>
 *    <li>-41003: aes 解密失败</li>
 *    <li>-41004: 解密后得到的buffer非法</li>
 *    <li>-41005: base64加密失败</li>
 *    <li>-41016: base64解密失败</li>
 * </ul>
 */
class ErrorCode
{
    public static $OK = 0;
    public static $IllegalAesKey = -41001;
    public static $IllegalIv = -41002;
    public static $IllegalBuffer = -41003;
    public static $DecodeBase64Error = -41004;
}

