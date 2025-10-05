<?php


use Kaadon\Jwt\Jwt;

if (!function_exists('jwt_create')) {
    /**
     * @throws \RedisException|\Kaadon\Jwt\JwtException
     */
    function jwt_create($identification, $data = []): string
    {
        return Jwt::create($identification,$data);
    }
}

if (!function_exists('jwt_verify')) {
    function jwt_verify($token = null): object
    {
        return Jwt::verify($token);
    }
}

if (!function_exists('jwt_delete')) {
    function jwt_delete($identification = null): bool|int|Redis
    {
        if ($identification){
            return Jwt::delete($identification);
        }
        return false;
    }
}

if (!function_exists('jwt_realIp')) {
    function jwt_realIp()
    {
        return Jwt::getIp();
    }
}