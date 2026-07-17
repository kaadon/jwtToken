<?php
require_once __DIR__ . '/../vendor/autoload.php';

// jwt.php 配置文件用到了 env()，无完整 App 环境时提供兜底实现
if (!function_exists('env')) {
    function env($name, $default = null)
    {
        $val = getenv(str_replace('.', '_', strtoupper($name)));
        return $val === false ? $default : $val;
    }
}

use Kaadon\Jwt\Jwt;
use Kaadon\Jwt\JwtException;
use think\App;
use think\Config;

// 轻量引导：只创建容器并绑定 config 实例，不做完整 initialize（避免启动 Cache 等服务报错）
$app = new App();
App::setInstance($app);
$app->bind('app', $app);

// 手动构建 Config 实例并注入 jwt 配置
$config = new Config();
$app->instance('config', $config);

$jwt = require __DIR__ . '/../src/config/jwt.php';
// 关闭 elsewhere/ip/user_agent，以便无 Redis、无 HTTP 环境下测试
$jwt['ip'] = false;
$jwt['user_agent'] = false;
$jwt['elsewhere'] = false;
$config->set($jwt, 'jwt');

// 生成 token
$token = Jwt::create('555', ['name' => 'test']);
echo "生成的 Token:\n{$token}\n\n";

// 验证 token（verify 默认从 Authorization 头取值，这里手动加 Bearer 前缀）
try {
    $decoded = Jwt::verify('Bearer ' . $token);
} catch (JwtException $e) {

}
echo "验证结果:\n";
print_r($decoded);
