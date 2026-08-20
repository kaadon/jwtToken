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
    public static function key(string $identification, ?string $Module = null): string
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
    public static function exp(int $expire = 0)
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
     * @return mixed 缓存值
     * @throws JwtException
     */
    public static function set(string $identification, $value, $Module = null, int $expire = 0)
    {
        $key = self::key($identification , $Module);
        $val = $value;
        $exp = $expire ?: self::exp();
        try {
            Cache::set($key, $val, $exp);
        } catch (\Throwable $exception) {
            throw new JwtException('Cache write failed: ' . $exception->getMessage(), 0, $exception);
        }
        return $val;
    }

    /**
     * 缓存获取
     *
     * @param string $identification
     *
     * @param null $Module
     * @return mixed 缓存值，未命中为 null
     * @throws JwtException
     */
    public static function get(string $identification, $Module = null)
    {
        $key = self::key($identification , $Module);
        try {
            return Cache::get($key);
        } catch (\Throwable $exception) {
            throw new JwtException('Cache read failed: ' . $exception->getMessage(), 0, $exception);
        }
    }

    /**
     * 缓存删除
     *
     * @param string $identification
     * @param null $Module
     * @return bool
     * @throws JwtException
     */
    public static function del(string $identification, $Module = null): bool
    {
        $key = self::key($identification , $Module);
        try {
            return Cache::delete($key);
        } catch (\Throwable $exception) {
            throw new JwtException('Cache delete failed: ' . $exception->getMessage(), 0, $exception);
        }
    }
}