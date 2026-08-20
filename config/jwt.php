<?php


return [
    //验证ip
    'ip' => true,
    //验证user_agent
    'user_agent' => true,
    // 单点登录：同一 identify 只保留最后一次签发的 token，需要可用的缓存驱动
    'elsewhere' => false,
    // JWT加密算法（pem 兜底密钥为 Ed25519，base64url 编码，依赖 ext-sodium）
    'alg' => 'EdDSA',
    // 签发者
    'issuer' => 'kaadon',
    // 非对称密钥：留空时兜底使用库自带的 config/pem/*.pem（仅供快速上手，生产环境请生成
    // 自己的密钥后通过 JWT_PRIVATE_KEY/JWT_PUBLIC_KEY 覆盖）
    'private_key' => env('JWT_PRIVATE_KEY', ''),
    'public_key' => env('JWT_PUBLIC_KEY', ''),
    // JWT有效时间
    'exp' => 3600 * 24 * 7,
    // 免鉴权路由白名单（JwtMiddleware 读取，pathinfo 小写后精确匹配）
    'white' => [],
];
