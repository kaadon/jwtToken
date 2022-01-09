<?php


if (!function_exists('jwt_create')) {
    function jwt_create(string $identification,$data = [])
    {
        return \Kaadon\Jwt\Jwt::create($identification,$data);
    }
}
if (!function_exists('jwt_verify')) {
    function jwt_verify($token = null)
    {
        return \Kaadon\Jwt\Jwt::verify($token);
    }
}