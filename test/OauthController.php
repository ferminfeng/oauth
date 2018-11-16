<?php

namespace app\controllers;

use yii\web\Controller;

class OauthController extends Controller
{
    /**
     * QQ第三方登录
     */
    public function actionOauthQq()
    {
        $config = [
            'app_id'   => '123456',
            'app_key'  => '132456',
            'callback' => 'http://expmple.com/oauth/callback.php',
        ];

        $qcConect = new \fyflzjz\oauth\QqConect($config);

        //调用qqLogin方法会自动跳转到QQ授权登录页面
        $url = $qcConect->qqLogin();
        $this->redirect($url);
    }

    /**
     * 微信第三方登录
     */
    public function actionOauthWx()
    {
        $config = [
            'app_id'     => '1234',
            'app_secret' => '1',
            'callback' => 'http://expmple.com/oauth/callback.php',
        ];

        $wxWeb = new \fyflzjz\oauth\WxWeb($config);
        //调用wxLogin方法会自动跳转到QQ授权登录页面
        $url = $wxWeb->wxLogin();
        $this->redirect($url);
    }

    /**
     * 微信第三方登录回调
     */
    public function actionWxLoginCallback()
    {
        $code = empty($_GET['code']) ? '' : $_GET['code'];
        if (empty($code)) {
            echo 'code为空';die;
        }

        $config = [
            'app_id'     => '1234',
            'app_secret' => '1',
            'callback'   => 'http://exmple.com/example/oauth/callback.php',
        ];

        $wxWeb = new \fyflzjz\oauth\WxWeb($config, $code, 'h5');

        /*
         * 存储 token_info 数据
         * 在 access_token 有效期内(expires_in)可直接使用存储的 token_info 数据
         * 在 access_token 失效前可通过 $wxWeb->refreshAccessToken() 方法刷新 access_token
         */
        $wxWeb->InitToken();
		
        //获取token和openid
        $access_token = $wx_class->getAccessToken();
        $open_id = $wx_class->getOpenId();

        if (!$access_token || !i$open_id) {
            echo 'access_token|openid为空';die;
        }

        //获取用户信息
        $user_info = $wxWeb->getUserInfo($access_token, $open_id);
        if (!$user_info || !is_array($user_info)) {
            echo '用户信息为空';die;
        }

        print_r($user_info);
    }

    /**
     * QQ第三方登录回调
     */
    public function actionQqLoginCallback()
    {
        $config = [
            'app_id'   => '123456',
            'app_key'  => '132456',
            'callback'   => 'http://exmple.com/example/oauth/callback.php',
        ];

        $qcConect = new \fyflzjz\oauth\QqConect($config);

        /*
         * 存储 callback 数据
         * 在 access_token 有效期内(expires_in)可直接使用存储的callback数据
         * 在 access_token 失效前可通过 $qcConect->refreshAccessToken() 方法刷新 access_token
         */
        $callback = $qcConect->qqCallback();
        $access_token = $callback['access_token'];
        $openid = $qcConect->getOpenid();

        //获取用户信息
        $user_info = $qcConect->getUserInfo($access_token, $openid);

        if (!$user_info || !is_array($user_info)) {
            echo '用户信息为空';die;
        }

        print_r($user_info);
    }
}
