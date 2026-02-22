<?php


return [
    'token' => [
        //验证ip
        'ip'          => false,
        //验证user_agent
        'user_agent'  => false,
        // JWT加密算法
        'alg'         => 'RS512',
        //签发者
        'secret'      => 'jwtToken',
        'issuer'      => 'jwtToken',
        // 非对称需要配置
        'private_key' => <<<EOD
-----BEGIN PRIVATE KEY-----
MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQCnwmxTu3tzdzNa
YTtc35z1UogPS11lDL901E735DYSalIYGaTsfzS8xxuzs/qoK7yjxrcpnNDxqU3M
4oQSpdYpAc5SskkOOXfK/eSTvEAtyGcDdJVbeNDq9p64oMekq/EoWXiw2MpgoedF
2LnQcxYI3JAhQOdZGAnFVw/KEUL3hF2PpcWRj0Y3qwXted9r6nN1JcgR1b3DuYXF
+pi5hyKI7QPISsIZCMgCnqkEEpfek8egR9Se5fmEx+2e60j52oQXjHhLxCW7ngTP
LEgFr+bQYgsOwS0g5YvK5W3LpMrk7DJjVn9aQiqBjTnjdPkGlWJ5N+woOnO6W8T+
scXCckeZAgMBAAECggEAAqjbbMxpHaCDKOint0Y4R89iJtPsDCESm/iNs/JjRRF4
cbdeXP17SY7iiovM6oOe/v20g61fxqUHfbsNmvoUFhxYOAlpjRcuJgK2b/0pC1DF
CVH82DFnJoJ4a7bo01yCe0BH4I3fT37hmsLf10Ur0UIl6tELmeb+qKlDr9FsPV5O
Pt8JQhs1qRB09D+9vT4nbBkVTwTuujjSyCWc4fNaE88Ee4N6KmdApzwNdHptrE+Q
UzLMugvM+ATtUwvHu8nAHtxAvoGclNoLp+ccpp0dL9tiQ228JN2w4SB0Q3DD9Pis
XxZRG341HMlk07sAV/OPYAz4mR7lBk269mN/HwSEDQKBgQDk+4/VXsENlSsm7i5Z
gnp9EYxFldRt/rJWdpPv4zeQvWb1462VVUijPYQRvtkr8pNhss3RaJbHr4IIJyiu
tkO8UQdZrr6V5tO5ECNHaRnAtHIYfniZAhoR2zHvTWoPeVLVUTOkbsP2Y/0LhPl8
4XMz/zhQ/+lVvfsibCevc99R/wKBgQC7jZwweKpOP+oPm9QGxzcg89wucJyZphfw
Pc9eSc9wfiIxvDc/hRBz/NxUnTbrndZa5g3djWbYMPS/xtNpVrAuXrKNjG0GOyJg
8tWd4GbkFWP3yLUYh8xHOYlD4MdSxOI19Cc+BA3yVKFG+j5cnmGrfhoOchzYs4GV
+igk9rO2ZwKBgCl8sqi0DEJLvo/FI7yv+UVjwohxBxYOyX0E6vTRtCWTS25NnAus
cgaxhJY6f9qIjs9quAOy8W6oi+SyQ5q0Bz29aJmFIZ7DPaUQGXQ8xJ+3kdyCPZNr
YBHQJxH2crru/mUL21F1iCfCIfzOUO2hY2AOY8O5OiuAylmIQwB0/Ac9AoGAIemH
FlSbJq7z2YKpodgfpbuyUktWZYncxjnG5xudgI+uCyQnMTsUMITGKh6LMatGeQUj
+K16rRidCJgg3ekozhmdW27Kv9etba465eMPd6pOex01cYwMacyDf1yDbfnflTXi
apo9E1YuGzFgWUriCiow9++2O5Cpm76xx408DX0CgYEA20pL20hgXmwVDhxNW9r2
XUvnd6RwygqpV++t1s6zSVI5cf5DuQYIPam2GGVgjRp5BUpGv3Sg+nrpN0xdpa9t
fE9qBGYCjfI0qTWI06qJ4U+0DoVXaHi3LRclT/OWLSRqLXCPmbLqI9I3KIQgXqdp
ckty2mlJPqnyp5RX8/2N0hI=
-----END PRIVATE KEY-----
EOD,
        'public_key'  => <<<EOD
-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAp8JsU7t7c3czWmE7XN+c
9VKID0tdZQy/dNRO9+Q2EmpSGBmk7H80vMcbs7P6qCu8o8a3KZzQ8alNzOKEEqXW
KQHOUrJJDjl3yv3kk7xALchnA3SVW3jQ6vaeuKDHpKvxKFl4sNjKYKHnRdi50HMW
CNyQIUDnWRgJxVcPyhFC94Rdj6XFkY9GN6sF7Xnfa+pzdSXIEdW9w7mFxfqYuYci
iO0DyErCGQjIAp6pBBKX3pPHoEfUnuX5hMftnutI+dqEF4x4S8Qlu54EzyxIBa/m
0GILDsEtIOWLyuVty6TK5OwyY1Z/WkIqgY0543T5BpVieTfsKDpzulvE/rHFwnJH
mQIDAQAB
-----END PUBLIC KEY-----
EOD,
        // JWT有效时间
        'exp'         => 3600 * 24 * 7,
    ],
    'cache' => [
        'host'     => env('redis.hostname', '127.0.0.1'),
        'password' => env('redis.password', '123456'),
        'select'   => env('redis.select', 1),
        'port'     => env('redis.port', 6379),
        'prefix'   => env('redis.prefix', 'cache:') . 'jwt:',
    ]
];
