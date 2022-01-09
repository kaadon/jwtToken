<?php


namespace Kaadon\Jwt;


use think\facade\Cache;

class JwtCache
{
    /**
     * 缓存key
     *
     * @param int $username 用户名
     *
     * @return string
     */
    public static function key(int $username, string $Module = null)
    {
        if (is_null($Module)){
            $Module = 'Api';
        }
        $key = 'Jwt:' . $Module . ':'.$username;

        return $key;
    }

    /**
     * 缓存有效时间
     *
     * @param int $expire 有效时间
     *
     * @return int
     */
    public static function exp($expire = 0)
    {
        if (empty($expire)) {
            $expire = 1 * 24 * 60 * 60;
        }

        return $expire;
    }

    /**
     * 缓存设置
     *
     * @param int $username 用户id
     * @param array   $admin_user    用户信息
     * @param int $expire        有效时间
     *
     * @return array 用户信息
     */
    public static function set(int $username, $value, $Module = null, $expire = 0)
    {
        $key = self::key($username , $Module);
        $val = $value;
        $exp = $expire ?: self::exp();
        Cache::set($key, $val, $exp);

        return $val;
    }

    /**
     * 缓存获取
     *
     * @param int $username 用户id
     *
     * @param null $Module
     * @return array 用户信息
     */
    public static function get(int $username, $Module = null)
    {
        $key = self::key($username , $Module);
        $res = Cache::get($key);

        return $res;
    }

    /**
     * 缓存删除
     *
     * @param int $username 用户id
     *
     * @return bool
     */
    public static function del(int $username, $Module = null)
    {
        $key = self::key($username , $Module);
        $res = Cache::delete($key);

        return $res;
    }
}