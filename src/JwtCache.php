<?php


namespace Kaadon\Jwt;


use Kaadon\Jwt\Contract\JwtCacheHandler;
use think\facade\Cache;
use think\facade\Config;

/**
 * JWT 会话缓存：默认直接复用应用的 think\facade\Cache 存储，不做连接/命名空间隔离。
 *
 * 多机部署且需要会话隔离（例如独立的 Redis host/port/select/prefix）时，实现
 * {@see JwtCacheHandler} 接口，并在 config/jwt.php 的 cache_handler 配置项中填入实现类的
 * 完整类名，即可整体替换下面的默认读写逻辑。
 */
class JwtCache
{
    private static ?JwtCacheHandler $handler = null;
    private static bool $resolved = false;

    /**
     * 缓存key
     *
     * @param string $identification 用户名
     * @param string|null $Module
     * @return string
     */
    public static function key(string $identification, ?string $Module = null): string
    {
        return 'Jwt:' . ($Module ?? 'Api') . ':' . $identification;
    }

    /**
     * 解析 config/jwt.php 里配置的自定义缓存处理器；未配置或非法时返回 null，走下面的默认实现。
     */
    private static function customHandler(): ?JwtCacheHandler
    {
        if (self::$resolved) {
            return self::$handler;
        }
        self::$resolved = true;
        $default = require __DIR__ . '/../config/jwt.php';
        $config = array_merge($default, (array)Config::get('jwt'));
        $class = (string)($config['cache_handler'] ?? '');
        if ($class !== '' && is_a($class, JwtCacheHandler::class, true)) {
            self::$handler = new $class();
        }
        return self::$handler;
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
        if ($handler = self::customHandler()) {
            return $handler->set($identification, $value, $Module, $expire);
        }
        $key = self::key($identification, $Module);
        $exp = $expire ?: self::exp();
        try {
            Cache::set($key, $value, $exp);
        } catch (\Throwable $exception) {
            throw new JwtException('Cache write failed: ' . $exception->getMessage(), 0, $exception);
        }
        return $value;
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
        if ($handler = self::customHandler()) {
            return $handler->get($identification, $Module);
        }
        $key = self::key($identification, $Module);
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
        if ($handler = self::customHandler()) {
            return $handler->del($identification, $Module);
        }
        $key = self::key($identification, $Module);
        try {
            return Cache::delete($key);
        } catch (\Throwable $exception) {
            throw new JwtException('Cache delete failed: ' . $exception->getMessage(), 0, $exception);
        }
    }

    /**
     * 缓存有效时间
     *
     * @param int $expire 有效时间
     *
     * @return int
     */
    private static function exp(int $expire = 0): int
    {
        return $expire ?: 24 * 60 * 60;
    }
}
