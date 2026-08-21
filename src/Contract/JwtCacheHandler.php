<?php


namespace Kaadon\Jwt\Contract;


use Kaadon\Jwt\JwtException;

/**
 * JWT 会话缓存后端契约。
 *
 * 默认实现（{@see \Kaadon\Jwt\JwtCache}）直接复用应用的 think\facade\Cache 存储。
 * 多机部署且需要 JWT 会话独立隔离（例如专用的 Redis host/port/select/prefix）时，
 * 实现该接口并在 config/jwt.php 的 cache_handler 配置项中填入实现类的完整类名即可替换。
 */
interface JwtCacheHandler
{
    /**
     * 写入缓存
     *
     * @param string $identification 用户标识
     * @param mixed $value 缓存值
     * @param string|null $module 命名空间/模块，为 null 时由实现自行决定默认值
     * @param int $expire 有效时间（秒），为 0 时由实现自行决定默认值
     * @return mixed 缓存值
     * @throws JwtException
     */
    public function set(string $identification, $value, ?string $module = null, int $expire = 0);

    /**
     * 读取缓存
     *
     * @param string $identification 用户标识
     * @param string|null $module 命名空间/模块，为 null 时由实现自行决定默认值
     * @return mixed 缓存值，未命中为 null
     * @throws JwtException
     */
    public function get(string $identification, ?string $module = null);

    /**
     * 删除缓存
     *
     * @param string $identification 用户标识
     * @param string|null $module 命名空间/模块，为 null 时由实现自行决定默认值
     * @return bool
     * @throws JwtException
     */
    public function del(string $identification, ?string $module = null): bool;
}
