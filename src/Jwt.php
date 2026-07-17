<?php


namespace Kaadon\Jwt;


use Firebase\JWT\JWT as BaseJwt;
use Firebase\JWT\Key;
use think\facade\Config;
use think\facade\Request;


class Jwt
{

    private static array $configuration = [
        // JWT加密算法（pem 兜底密钥为 RSA，对应 RS256）
        'alg' => 'RS256',
        //签发者
        'issuer' => 'kaadon',
        // 非对称密钥：留空时运行时兜底读取 src/config/pem/*.pem
        'private_key' => '',
        'public_key' => '',
        // JWT有效时间
        'exp' => 3600 * 24 * 7,
    ];

    /**
     * 合并 token 配置：非对称密钥缺省时惰性兜底读取 src/config/pem/*.pem
     *
     * @return array
     */
    private static function tokenConfig(): array
    {
        $config = array_merge(self::$configuration, (array)Config::get('jwt'));
        foreach (['private_key' => 'private.pem', 'public_key' => 'public.pem'] as $field => $file) {
            if (empty($config[$field])) {
                $config[$field] = (string)@file_get_contents(__DIR__ . '/config/pem/' . $file);
            }
        }
        return $config;
    }

    /**
     * token生成
     *
     * @param string $identify
     * @param array $data
     * @return string
     */
    public static function create(string $identify, array $data = []): string
    {
        $config = self::tokenConfig();
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
            JwtCache::set($data['identify'], sha1($token), null, $config['exp'] ?: 60 * 60 * 24 * 7);
        }
        return $token;
    }

    /**
     * token验证
     *
     * @param string|null $token token
     *
     * @return object
     * @throws \Kaadon\Jwt\JwtException
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
        $config = self::tokenConfig();
        $key = $config['public_key'];
        if (!$key) {
            throw new JwtException('Public key not configured');
        }
        try {
            $decoded = BaseJwt::decode($token, new Key($key, $config['alg']));
        } catch (\Exception $exception) {
            throw new JwtException("error:{$exception->getMessage()}");
        }
        if (!empty($config['elsewhere'])) {
            $OldToken = JwtCache::get($decoded->data->identify);
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
     * @return bool
     */
    public static function delete($identification): bool
    {
        return JwtCache::del($identification);
    }

    public static function getIp($type = 0, $adv = true)
    {
        $type = $type ? 1 : 0;
        static $ip = NULL;
        if ($ip !== NULL) return $ip[$type];
        if ($adv) {
            if (isset($_SERVER['HTTP_X_REAL_IP'])) {
                // 优先使用 nginx proxy_set_header X-Real-IP $XRealIP;
                $ip = trim($_SERVER['HTTP_X_REAL_IP']);
            } elseif (isset($_SERVER['HTTP_X_FORWARDED_FOR'])) {
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
