<?php


namespace Kaadon\Jwt;


use think\facade\Cache;

class JwtCache
{
    /**
     * 缓存key
     *
     * @param string $identification 用户名
     * @param string|null $Module
     * @return string
     */
    public static function key(string $identification, string $Module = null): string
    {
        if (is_null($Module)){
            $Module = 'Api';
        }
        return 'Jwt:' . $Module . ':'.$identification;
    }

    /**
     * 缓存有效时间
     *
     * @param int $expire 有效时间
     *
     * @return float|int
     */
    public static function exp(int $expire = 0): float|int
    {
        if (empty($expire)) {
            $expire = 24 * 60 * 60;
        }
        return $expire;
    }

    /**
     * 缓存设置
     *
     * @param string $identification 用户id
     * @param $value
     * @param null $Module
     * @param int $expire 有效时间
     *
     * @return array 用户信息
     */
    public static function set(string $identification, $value, $Module = null, int $expire = 0): array
    {
        $key = self::key($identification , $Module);
        $val = $value;
        $exp = $expire ?: self::exp();
        Cache::set($key, $val, $exp);
        return $val;
    }

    /**
     * 缓存获取
     *
     * @param string $identification
     *
     * @param null $Module
     * @return array 用户信息
     */
    public static function get(string $identification, $Module = null): array
    {
        $key = self::key($identification , $Module);
        return Cache::get($key);
    }

    /**
     * 缓存删除
     *
     * @param string $identification
     * @param null $Module
     * @return bool
     */
    public static function del(string $identification, $Module = null): bool
    {
        $key = self::key($identification , $Module);
        return Cache::delete($key);
    }
}