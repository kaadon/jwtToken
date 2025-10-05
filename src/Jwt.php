<?php


namespace Kaadon\Jwt;


use Firebase\JWT\JWT as BaseJwt;
use Redis;
use RedisException;
use think\facade\Config;
use think\facade\Request;


class Jwt
{

    private static array $configuration = [
        // JWT加密算法
        'alg' => 'ES256',
        //签发者
        'issuer' => 'kaadon',
        // 非对称需要配置
        'private_key' => <<<EOD
-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgYJaXP8KapeFy4Lto
85tNQ+wRzNYGAGZXoZjMb2/GHoihRANCAAQLFJ+Lgjt5A/Vnc8OG6m2TBK5xxGLg
ZRdae5ojDObyiXsxzX267LJ1KMUAad3FFYSyQWd7BtiPWrJIWPcsQsIK
-----END PRIVATE KEY-----
EOD,
        'public_key' => <<<EOD
-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAECxSfi4I7eQP1Z3PDhuptkwSuccRi
4GUXWnuaIwzm8ol7Mc19uuyydSjFAGndxRWEskFnewbYj1qySFj3LELCCg==
-----END PUBLIC KEY-----
EOD,
        // JWT有效时间
        'exp' => 3600 * 24 * 7,
    ];

    /**
     * token生成
     *
     * @param string $identify
     * @param array $data
     * @return string
     * @throws RedisException|\Kaadon\Jwt\JwtException
     */
    public static function create(string $identify, array $data = []): string
    {
        $config = Config::get('jwt.token');
        $config = array_merge(self::$configuration, $config);
        $time = time();
        $exp = $config['exp'] ?: 60 * 60 * 24 * 7;
        $key = $config['private_key'];
        $iss = $config['issuer'];
        $exp = $time + $exp;
        $data['identify'] = $identify;
        $data['ip'] = self::getIp();
        if (isset($config['user_agent']) && !empty($config['user_agent'] && isset($_SERVER['HTTP_USER_AGENT']))) {
            $data['user_agent'] = sha1($_SERVER['HTTP_USER_AGENT'] . $_SERVER['HTTP_X_FORWARDED_FOR']);
        }
        $payload = [
            'iss' => $iss,
            'iat' => $time,
            'exp' => $exp,
            'data' => $data,
        ];
        $token = BaseJwt::encode($payload, $key, $config['alg']);
        if (!empty($config['elsewhere'])) {
            $configCache = Config::get('jwt.cache');
            self::redis(is_array($configCache) ? $configCache : [])->set(($configCache['prefix'] ?? "cache:JWT:") . $data['identify'], sha1($token), $config['exp'] ?: 60 * 60 * 24 * 7);
        }
        return $token;
    }

    /**
     * token验证
     *
     * @param string|null $token token
     *
     * @return object
     * @throws \RedisException|\Kaadon\Jwt\JwtException
     */
    public static function verify(string $token = null): object
    {
        //逻辑代码
        if (empty($token)) {
            $token = Request::header('Authorization');
        }
        if (!$token || !is_string($token) || strlen($token) <= 7) {
            throw new JwtException('The token does not exist or is illegal');
        }
        $token = substr($token, 7);
        $config = Config::get('jwt.token');
        $config = array_merge(self::$configuration, $config);
        $key = $config['public_key'];
        if (!$key) {
            throw new JwtException('Public key not configured');
        }
        $headers =  new \stdClass();
        $headers->alg = $config['alg'];
        try {
            $decoded = BaseJwt::decode($token, $key, $headers);
        } catch (\Exception $exception) {
            throw new JwtException("error:{$exception->getMessage()}");
        }
        if (!empty($config['elsewhere'])) {
            $configCache = Config::get('jwt.cache');
            $OldToken = self::redis(is_array($configCache) ? $configCache : [])->get(($configCache['prefix'] ?? "cache:JWT:") . $decoded->data->identification);
            if (empty($OldToken)) throw new JwtException('You are not logged in or your login has expired');
            if ($OldToken != sha1($token)) throw new JwtException('Your account is logged in elsewhere');
        }
        if (isset($config['ip']) && !empty($config['ip'] && $decoded->data->ip !== self::getIp())) {
            throw new JwtException('Your login environment has been switched');
        }
        if (!empty($config['user_agent']) && isset($decoded->data->user_agent) && $decoded->data->user_agent !== sha1($_SERVER['HTTP_USER_AGENT'])) {
            throw new JwtException('Your login device has been switched');
        }
        return $decoded;
    }

    /**
     * token删除
     *
     * @param $identification
     * @return false|int|Redis
     * @throws RedisException|\Kaadon\Jwt\JwtException
     */
    public static function delete($identification): bool|int|Redis
    {
        $config = Config::get('jwt.cache');
        return self::redis(is_array($config) ? $config : [])->del(($config['prefix'] ?? "cache:JWT:") . $identification);
    }

    /**
     * @throws \Kaadon\Jwt\JwtException
     */
    public static function redis(array $param): Redis
    {
        try {
            //逻辑代码
            $redis = new Redis();
            $redis->connect($param['host'] ?: '127.0.0.1', $param['port'] ?: 6379);
            if ($param['password']) {
                $redis->auth($param['password']);
            }
            if ($param['select']) {
                $redis->select($param['select']);
            }
            return $redis;
        } catch (\Exception $exception) {
            throw new JwtException("系统错误:联系管理员[REDIS]");
        }
    }

    public static function getIp($type = 0, $adv = true)
    {
        $type = $type ? 1 : 0;
        static $ip = NULL;
        if ($ip !== NULL) return $ip[$type];
        if ($adv) {
            if (isset($_SERVER['HTTP_X_FORWARDED_FOR'])) {
                $arr = explode(',', $_SERVER['HTTP_X_FORWARDED_FOR']);
                $pos = array_search('unknown', $arr);
                if (false !== $pos) unset($arr[$pos]);
                $ip = trim($arr[0]);
            } elseif (isset($_SERVER['HTTP_CLIENT_IP'])) {
                $ip = $_SERVER['HTTP_CLIENT_IP'];
            } elseif (isset($_SERVER['REMOTE_ADDR'])) {
                $ip = $_SERVER['REMOTE_ADDR'];
            }
        } elseif (isset($_SERVER['REMOTE_ADDR'])) {
            $ip = $_SERVER['REMOTE_ADDR'];
        }
        // IP地址合法验证
        $long = sprintf("%u", ip2long((string)$ip));
        $ip = $long ? array($ip, $long) : array('0.0.0.0', 0);
        return $ip[$type];
    }


}
