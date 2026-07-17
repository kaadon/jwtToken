<?php


return [
    //验证ip
    'ip' => true,
    //验证user_agent
    'user_agent' => true,
    // JWT加密算法（pem 兜底密钥为 RSA，对应 RS256）
    'alg' => 'RS256',
    // 签发者
    'issuer' => 'kaadon',
    // 非对称密钥：留空时由 Jwt 兜底读取 src/config/pem/*.pem
    'private_key' => env('JWT_PRIVATE_KEY', ''),
    'public_key' => env('JWT_PUBLIC_KEY', ''),
    // JWT有效时间
    'exp' => 3600 * 24 * 7,
];
