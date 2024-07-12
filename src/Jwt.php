<?php


namespace Kaadon\Jwt;


use Firebase\JWT\JWT as BaseJwt;
use Redis;
use RedisException;
use think\Exception;
use think\facade\Config;
use think\facade\Request;
use think\response\Json;


class Jwt
{

    private static $config = [
        // JWT加密算法
        'alg' => 'HS256',
        //签发者
        'issuer' => 'kaadon',
        // 非对称需要配置
        'private_key' => <<<EOD
-----BEGIN RSA PRIVATE KEY-----
MIIBVAIBADANBgkqhkiG9w0BAQEFAASCAT4wggE6AgEAAkEAlp50BaGP0MyE0/45FRKpxh0sDGECrm6cpp6DkOBFTTdvlxSNZCsO47NWjxjpIrmXV7H0XjmU+3hpWceQpW65wQIDAQABAkEAiriVkzoiAuTa0YUrfcUaqGTl1ODkX1Nw4+TKt/xW163zjeCHAy2YEe6HxGyJITYu156UhC7cOtdsBvM+a275oQIhANj5B2S651fbKh5qJCkROlqmsnaJx5m1oSTB89VK+CWDAiEAsbYFvcz5FvRr7kRJ9VBNzRsSx67nlI9rRjqF+duLBGsCID+eRRyz8MFB8ceZN6ES/Bk4Z3t6Spw3NVihxez0Xm4hAiAe/bRQnj9OPn/YBHa1XjTDMRZ8VkcyhDRcAfa9VQkQUwIge9SR0zj/8kj2/x+4e7zC5QnYA7Qn3mTpmJ7uVtOP9m4=
-----END RSA PRIVATE KEY-----
EOD,
        'public_key' => <<<EOD
-----BEGIN PUBLIC KEY-----
MFwwDQYJKoZIhvcNAQEBBQADSwAwSAJBAJaedAWhj9DMhNP+ORUSqcYdLAxhAq5unKaeg5DgRU03b5cUjWQrDuOzVo8Y6SK5l1ex9F45lPt4aVnHkKVuucECAwEAAQ==
-----END PUBLIC KEY-----
EOD,
        // JWT有效时间
        'exp' => 3600 * 24 * 7,
    ];

    /**
     * token生成
     *
     * @param string $identification
     * @param array $data
     * @return string
     * @throws RedisException
     */
    public static function create(string $identification, array $data = []): string
    {
        $config = Config::get('jwt.token');
        $config = array_merge(self::$config, $config);
        $time = time();
        $exp = $config['exp'] ?: 60 * 60 * 24 * 7;
        $key = $config['private_key'];
        $iss = $config['issuer'];
        $exp = $time + $exp;
        $data['identification'] = $identification;
        $data['ip'] = self::getIp();
        if (isset($config['user_agent']) && !empty($config['user_agent'] && isset($_SERVER['HTTP_USER_AGENT']))) {
            $data['user_agent'] = sha1($_SERVER['HTTP_USER_AGENT']);
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
            self::redis(is_array($configCache) ? $configCache : [])->set(($configCache['prefix'] ?? "cache:JWT:") . $data['identification'], sha1($token), $config['exp'] ?: 60 * 60 * 24 * 7);
        }
        return $token;
    }

    /**
     * token验证
     *
     * @param string|null $token token
     *
     * @return object
     */
    public static function verify(string $token = null)
    {
        try {
            //逻辑代码
            if (empty($token)) {
                $tokenBearer = Request::header('Authorization');
                if (!$tokenBearer || !is_string($tokenBearer) || strlen($tokenBearer) < 7) {
                    throw new Exception('The token does not exist or is illegal');
                }
                $token = substr($tokenBearer, 7);
                if (!$token) {
                    throw new Exception('Token is required');
                }
            }
            $config = Config::get('jwt.token');
            $config = array_merge(self::$config, $config);
            $key = $config['public_key'];
            if (!$key) {
                throw new Exception('Public key not configured');
            }
            $decoded = BaseJwt::decode($token, $key, array($config['alg']));

            if (!$decoded || !is_object($decoded)) {
                throw new Exception('Token validation failed');
            }

            if (!empty($config['elsewhere'])) {
                $configCache = Config::get('jwt.cache');
                $Oldtoken = self::redis(is_array($configCache) ? $configCache : [])->get(($configCache['prefix'] ?? "cache:JWT:") . $decoded->data->identification);
                if (empty($Oldtoken)) throw new Exception('You are not logged in or your login has expired');
                if ($Oldtoken != sha1($token)) throw new Exception('Your account is logged in elsewhere');
            }

            if (isset($config['ip']) && !empty($config['ip'] && $decoded->data->ip !== self::getIp())) {
                throw new Exception('Your login environment has been switched');
            }

            if (!empty($config['user_agent']) && isset($decoded->data->user_agent) && $decoded->data->user_agent !== sha1($_SERVER['HTTP_USER_AGENT'])) {
                throw new Exception('Your login device has been switched');
            }
            return $decoded;
        } catch (\Exception $exception) {
            throw new JwtException($exception->getMessage()) ;
        }
    }

    /**
     * token删除
     *
     * @param $identification
     * @return false|int|Redis
     * @throws RedisException
     */
    public static function delete($identification)
    {
        $config = Config::get('jwt.cache');
        return self::redis(is_array($config) ? $config : [])->del(($config['prefix'] ?? "cache:JWT:") . $identification);
    }

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
            throw new JwtException("系统错误:联系管理员[REDIS]") ;
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
