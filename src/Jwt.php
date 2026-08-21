<?php


namespace Kaadon\Jwt;


use Exception;
use Firebase\JWT\JWT as BaseJwt;
use Firebase\JWT\Key;
use think\facade\Config;
use think\facade\Request;


class Jwt
{

    /**
     * 库自带兜底 pem 文件内容缓存：文件内容在进程生命周期内不变，避免每次调用重复读盘。
     *
     * @var array<string, string>
     */
    private static array $pemCache = [];

    /**
     * 合并 token 配置：默认值单一来源于 config/jwt.php，非对称密钥缺省时兜底读取库自带的 config/pem/*.pem。
     *
     * @return array
     */
    private static function tokenConfig(): array
    {
        $default = require __DIR__ . '/../config/jwt.php';
        $config = array_merge($default, (array)Config::get('jwt'));
        if ($config['alg'] === 'EdDSA') {
            foreach (['private_key' => 'private.pem', 'public_key' => 'public.pem'] as $field => $file) {
                if (empty($config[$field])) {
                    $config[$field] = self::$pemCache[$file] ??= (string)@file_get_contents(__DIR__ . '/../config/pem/' . $file);
                }
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
     * @throws JwtException
     */
    public static function create(string $identify, array $data = []): string
    {
        $config = self::tokenConfig();
        $time = time();
        $ttl = $config['exp'] ?: 60 * 60 * 24 * 7;
        $key = $config['private_key'];
        if (!$key) {
            throw new JwtException('Private key not configured');
        }
        $iss = $config['issuer'];
        $exp = $time + $ttl;
        $data['identify'] = $identify;
        $data['ip'] = self::getIp();
        if (!empty($config['user_agent']) && ($userAgent = self::userAgentHash()) !== null) {
            $data['user_agent'] = $userAgent;
        }
        $payload = [
            'iss' => $iss,
            'iat' => $time,
            'exp' => $exp,
            'data' => $data,
        ];
        $token = BaseJwt::encode($payload, $key, $config['alg']);
        if (!empty($config['elsewhere'])) {
            JwtCache::set($data['identify'], sha1($token), null, $ttl);
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
    public static function verify(?string $token = null): object
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
        } catch (Exception $exception) {
            throw new JwtException("error:{$exception->getMessage()}");
        }
        if (!empty($config['elsewhere'])) {
            $OldToken = JwtCache::get($decoded->data->identify);
            if (empty($OldToken)) throw new JwtException('You are not logged in or your login has expired');
            if ($OldToken != sha1($token)) throw new JwtException('Your account is logged in elsewhere');
        }
        if (!empty($config['ip']) && $decoded->data->ip !== self::getIp()) {
            throw new JwtException('Your login environment has been switched');
        }
        if (!empty($config['user_agent']) && isset($decoded->data->user_agent) && $decoded->data->user_agent !== self::userAgentHash()) {
            throw new JwtException('Your login device has been switched');
        }
        return $decoded;
    }

    /**
     * 计算 user_agent 指纹：create() 和 verify() 共用同一份公式，避免两处各自实现导致算出的哈希不一致。
     *
     * @return string|null 当前请求没有 User-Agent 头时返回 null
     */
    private static function userAgentHash(): ?string
    {
        if (!isset($_SERVER['HTTP_USER_AGENT'])) {
            return null;
        }
        return sha1($_SERVER['HTTP_USER_AGENT'] . ($_SERVER['HTTP_X_FORWARDED_FOR'] ?? ''));
    }

    /**
     * token删除
     *
     * @param $identification
     * @return bool
     * @throws JwtException
     */
    public static function delete($identification): bool
    {
        return JwtCache::del($identification);
    }

    public static function getIp($type = 0, $adv = true)
    {
        return Request::ip($type, $adv);
    }


}
