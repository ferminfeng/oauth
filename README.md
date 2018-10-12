
> ##微信、QQ网页端第三方登录

```
还在调试中哦
```



> ### 安装

```
composer require fyflzjz/oauth
```

> ### 使用示例

- QQ第三方登录

```
$config = [
    'app_id'   => '123456',
    'app_key'  => '132456',
    'callback' => 'http://expmple.com/oauth/callback.php',
];

$qcConect = new \app\common\oauth\QqConect($config);
//调用qqLogin方法会自动跳转到QQ授权登录页面
$qcConect->qqLogin();
```

- 微信第三方登录

```
$config = [
    'app_id'     => '1234',
    'app_secret' => '1',
    'callback' => 'http://expmple.com/oauth/callback.php',
];

$wxWeb = new \app\common\oauth\WxWeb($config);
//调用wxLogin方法会自动跳转到QQ授权登录页面
$wxWeb->wxLogin();
```

- qq第三方登录回调

```
$config = [
    'app_id'   => '123456',
    'app_key'  => '132456',
    'callback' => 'http://example.com/oauth/callback.php',
];

$qcConect = new \app\common\oauth\QqConect($config);

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

```

- 微信第三方登录回调

```
$code = empty($_GET['code']) ? '' : $_GET['code'];

$config = [
    'app_id'     => '1234',
    'app_secret' => '1',
    'callback'   => 'http://exmple.com/example/oauth/callback.php',
];

$wxWeb = new \app\common\oauth\WxWeb($config, $code, 'h5');

/*
* 存储 token_info 数据
* 在 access_token 有效期内(expires_in)可直接使用存储的callback数据
* 在 access_token 失效前可通过 $wxWeb->refreshAccessToken() 方法刷新 access_token
*/
$token_info = $wxWeb->InitToken();

$access_token = $token_info['access_token'];
$open_id = $token_info['openid'];

//获取用户信息
$user_info = $wxWeb->getUserInfo($access_token, $open_id);
```

