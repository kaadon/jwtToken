<?php


use Kaadon\Jwt\Jwt;

if (!function_exists('jwt_create')) {
    function jwt_create(string $identification,$data = []): string
    {
        return Jwt::create($identification,$data);
    }
}
if (!function_exists('jwt_verify')) {
    function jwt_verify($token = null)
    {
        return Jwt::verify($token);
    }
}
if (!function_exists('jwt_delete')) {
    function jwt_delete($identification = null)
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