<?php


return [
    'token' => [
        //验证ip
        'ip' => true,
        //验证user_agent
        'user_agent' => true,
        // JWT加密算法
        'alg' => 'ES256',
        // 签发者
        'issuer' => 'kaadon',
        // 非对称需要配置
        'private_key' => env('JWT_PRIVATE_KEY', <<<EOD
-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgYJaXP8KapeFy4Lto
85tNQ+wRzNYGAGZXoZjMb2/GHoihRANCAAQLFJ+Lgjt5A/Vnc8OG6m2TBK5xxGLg
ZRdae5ojDObyiXsxzX267LJ1KMUAad3FFYSyQWd7BtiPWrJIWPcsQsIK
-----END PRIVATE KEY-----
EOD
        ),
        'public_key' => env('JWT_PUBLIC_KEY', <<<EOD
-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAECxSfi4I7eQP1Z3PDhuptkwSuccRi
4GUXWnuaIwzm8ol7Mc19uuyydSjFAGndxRWEskFnewbYj1qySFj3LELCCg==
-----END PUBLIC KEY-----
EOD
        ),
        // JWT有效时间
        'exp' => 3600 * 24 * 7,
    ],
    'cache' => [
        'host' => env('redis.hostname', '127.0.0.1'),
        'password' => env('redis.password', '123456'),
        'select' => env('redis.select', 1),
        'port' => env('redis.port', 6379),
        'prefix' => env('redis.prefix', 'cache:') . 'jwt:',
    ]
];
