<?php


namespace Kaadon\Jwt;

use think\facade\Config;
use Firebase\JWT\JWT as BaseJwt;
use Request;

class Jwt
{

    private static $config = [
        // JWT加密算法
        'alg'        => 'HS256',
        //签发者
        'secret'      => 'Kaadon',
        'issuer'           =>'kaadon',
        // 非对称需要配置
        'private_key'  => <<<EOD
-----BEGIN RSA PRIVATE KEY-----
MIICXAIBAAKBgQC8kGa1pSjbSYZVebtTRBLxBz5H4i2p/llLCrEeQhta5kaQu/Rn
vuER4W8oDH3+3iuIYW4VQAzyqFpwuzjkDI+17t5t0tyazyZ8JXw+KgXTxldMPEL9
5+qVhgXvwtihXC1c5oGbRlEDvDF6Sa53rcFVsYJ4ehde/zUxo6UvS7UrBQIDAQAB
AoGAb/MXV46XxCFRxNuB8LyAtmLDgi/xRnTAlMHjSACddwkyKem8//8eZtw9fzxz
bWZ/1/doQOuHBGYZU8aDzzj59FZ78dyzNFoF91hbvZKkg+6wGyd/LrGVEB+Xre0J
Nil0GReM2AHDNZUYRv+HYJPIOrB0CRczLQsgFJ8K6aAD6F0CQQDzbpjYdx10qgK1
cP59UHiHjPZYC0loEsk7s+hUmT3QHerAQJMZWC11Qrn2N+ybwwNblDKv+s5qgMQ5
5tNoQ9IfAkEAxkyffU6ythpg/H0Ixe1I2rd0GbF05biIzO/i77Det3n4YsJVlDck
ZkcvY3SK2iRIL4c9yY6hlIhs+K9wXTtGWwJBAO9Dskl48mO7woPR9uD22jDpNSwe
k90OMepTjzSvlhjbfuPN1IdhqvSJTDychRwn1kIJ7LQZgQ8fVz9OCFZ/6qMCQGOb
qaGwHmUK6xzpUbbacnYrIM6nLSkXgOAwv7XXCojvY614ILTK3iXiLBOxPu5Eu13k
eUz9sHyD6vkgZzjtxXECQAkp4Xerf5TGfQXGXhxIX52yH+N2LtujCdkQZjXAsGdm
B2zNzvrlgRmgBrklMTrMYgm1NPcW+bRLGcwgW2PTvNM=
-----END RSA PRIVATE KEY-----
EOD,
        'public_key' => <<<EOD
-----BEGIN PUBLIC KEY-----
MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQC8kGa1pSjbSYZVebtTRBLxBz5H
4i2p/llLCrEeQhta5kaQu/RnvuER4W8oDH3+3iuIYW4VQAzyqFpwuzjkDI+17t5t
0tyazyZ8JXw+KgXTxldMPEL95+qVhgXvwtihXC1c5oGbRlEDvDF6Sa53rcFVsYJ4
ehde/zUxo6UvS7UrBQIDAQAB
-----END PUBLIC KEY-----
EOD,
        // JWT有效时间
        'exp'         => 3600 * 24 * 7,
    ];

    /**
     * token生成
     *
     * @param array $admin_user 用户信息
     *
     * @return string
     */
    public static function create(string $identification,$data = [])
    {
        $config = Config::get('jwt.token');
        $config = array_merge(self::$config,$config);
        $time = time();
        $exp = $config['exp']?: 60*60*24*7;
        $key = $config['private_key']?:self::$privateKey;
        $iss = $config['issuer'];
        $exp = $time + $exp;
        $data['identification'] = $identification;
        $payload = [
            'iss'  => $iss,
            'iat'  => $time,
            'exp'  => $exp,
            'data' => $data,
        ];

        $token = BaseJwt::encode($payload, $key, 'RS256');

        JwtCache::set($data['identification'], $token);

        return $token;
    }

    /**
     * token验证
     *
     * @param string  $token         token
     *
     * @return json
     */
    public static function verify($token = null)
    {

        if (empty($token)){
            $tokenBearer = Request::header('Authorization');
            if (!$tokenBearer) {
                throw new JwtException('token is must.');
            }
            $token = substr($tokenBearer, 7);
            if (!$token) {
                throw new JwtException('token is required.');
            }
        }
        $config = Config::get('jwt.token');
        $config = array_merge(self::$config,$config);
        $key     = $config['public_key'];
        if (!$key){
            throw new JwtException('token is required.');
        }
        $decoded = BaseJwt::decode($token, $key, array('RS256'));

        if (!$decoded || !is_object($decoded)){
            throw new JwtException('Token validation failed.');
        }

        $Oldtoken = JwtCache::get($decoded->data->identification);
        if ($Oldtoken != $token){
            throw new JwtException('Your account is logged in elsewhere!');
        }
        if (time() > $decoded->data->exp){
            throw new JwtException('Login expired, please login again');
        }

        return  $decoded;
    }
}
