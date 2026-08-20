# 已知问题清单

来自 `/code-review` 对当前 `v3` 分支的评审结果，按优先级排列。`user_agent` 哈希不一致（create/verify 两边算法不统一）已在 `src/Jwt.php` 中修复（抽出共用的 `userAgentHash()` 方法），本文档只记录尚未处理的项。

## 1. EdDSA 之外的算法没有兜底/校验（安全，优先级最高）

- **位置**：`src/Jwt.php` `tokenConfig()`
- **问题**：密钥兜底逻辑用 `if ($config['alg'] === 'EdDSA')` 做门槛，切到其他算法（如 `HS256`）且没配 `private_key`/`public_key` 时，两个字段会静默留空。
- **风险**：`firebase/php-jwt` 的 HMAC 签名路径（`HS256`/`HS384`/`HS512`）对空字符串密钥不会报错，`create()` 会用空密钥正常签发 token，`verify()` 也会正常接受——任何人都能用空密钥伪造合法 token。
- **建议方向**：要么把兜底机制泛化成按算法映射的表，要么在 `tokenConfig()` 里对任何算法都做"密钥非空"的兜底断言，缺密钥时直接抛 `JwtException`，而不是静默放行。

## 2. `create()` 缺少空密钥校验

- **位置**：`src/Jwt.php` `create()`
- **问题**：`verify()` 会显式检查 `if (!$key) throw new JwtException(...)`，`create()` 没有对称的检查就直接调用 `BaseJwt::encode()`。
- **风险**：密钥文件缺失/不可读时，`create()` 会让 `firebase/php-jwt` 抛出的原始 `\DomainException` 直接冒泡，而不是本库统一的 `JwtException`，破坏"调用方只需要 catch JwtException"的异常契约。
- **建议方向**：在 `create()` 里加一个和 `verify()` 对称的 `if (!$key) throw new JwtException(...)` 检查（或者把这个检查提到 `tokenConfig()` 里做成两边共用的一次性断言）。

## 3. `config/pem/*.pem` 尚未提交到 git

- **位置**：`config/pem/private.pem`、`config/pem/public.pem`
- **问题**：`git status` 显示 `config/pem/` 是未跟踪状态（`??`）。
- **风险**：如果这次改动提交时漏了 `git add config/pem/`，任何全新的 clone / CI / `composer install`（发布 tag 后）都会拿不到这两个密钥文件，`tokenConfig()` 静默读到空字符串，`create()`/`verify()` 直接失败。
- **待决策**：是否现在 `git add config/pem/` 并提交，把它作为随库分发的默认兜底密钥（已经在此前讨论中明确是"仅供快速上手"的定位，非生产密钥）。

## 4. `JwtCache` 没有任何异常处理

- **位置**：`src/JwtCache.php`（`set`/`get`/`del`）
- **问题**：旧版 `Jwt::redis()` 会把 Redis 连接/认证失败统一包装成友好的 `JwtException("系统错误:联系管理员[REDIS]")`；现在 `JwtCache` 直接调用 `think\facade\Cache`，没有任何 try/catch。
- **风险**：缓存驱动（Redis 挂了、文件缓存目录不可写等）抛异常时，会从 `Jwt::create()`/`verify()`/`delete()`/`JwtMiddleware` 一路穿透成未捕获的 500，而不是统一的 `JwtException`。
- **建议方向**：在 `JwtCache` 的三个方法里包一层 try/catch，转换成 `JwtException`，恢复旧版的异常契约。

## 5. `getIp()` 手写解析，安全性弱于框架自带方法

- **位置**：`src/Jwt.php` `getIp()`
- **问题**：无条件信任客户端可控的 `X-Real-IP`/`X-Forwarded-For`/`Client-IP` 请求头，没有像 `think\Request::ip()` 那样做"仅在 `REMOTE_ADDR` 命中可信代理 CIDR 时才采信代理头"的校验；且 `ip2long()` 只支持 IPv4，IPv6 地址会被归一化成 `0.0.0.0`，导致 IPv6 客户端的 IP 校验形同虚设。
- **风险**：新默认配置 `ip => true` 下，攻击者只需要在创建 token 和验证 token 两次请求里伪造同一个 `X-Real-IP`，就能绕过"登录环境切换"检测；IPv6 客户端则完全绕过这个检查。
- **建议方向**：改用 `\think\facade\Request::ip()`（旧版中间件本来就是这么用的，这次重构时被换掉了），把可信代理配置交给框架统一管理。

## 6. `getIp()` 的静态缓存在长驻进程下跨请求复用

- **位置**：`src/Jwt.php` `getIp()`：`static $ip = NULL;`
- **问题**：这个缓存是进程级别的，不是请求级别的。
- **风险**：ThinkPHP 8 常见部署在 Swoole/Workerman 等长驻 worker 模式下，同一个 worker 处理的第一个请求算出的 IP 会被静默复用到该 worker 之后处理的所有请求上，导致 `create()` 写入错误的 IP、`verify()` 拿错误的 IP 去比对。
- **建议方向**：去掉 `static` 缓存，或者在请求生命周期开始时重置。

## 7. JWT 会话缓存不再隔离

- **位置**：`config/jwt.php`（`elsewhere` 相关），`src/JwtCache.php`
- **问题**：旧版配置有独立的 Redis host/port/select/prefix，专门给 JWT 单点登录状态用；现在直接复用应用的默认 `think\facade\Cache` 存储。
- **风险**：多机负载均衡且使用默认文件缓存驱动时，A 机上登录写入的会话状态 B 机看不到，导致合法 token 在 B 机上被误判成"未登录或登录已过期"。清空应用通用缓存（比如发布时执行 `Cache::clear()`）也会连带把所有 JWT 会话强制登出。
- **建议方向**：视产品需求决定是否需要恢复独立的缓存命名空间/连接，或者在文档里明确告知使用者这个前提条件。

## 8. 两处默认配置重复且已经分叉

- **位置**：`src/Jwt.php` 的 `self::$configuration`（类内默认值） vs `config/jwt.php`（发布的配置文件）
- **问题**：`alg`/`issuer`/`private_key`/`public_key`/`exp` 在两处重复维护；`self::$configuration` 完全没有 `ip`/`user_agent`/`elsewhere`/`white` 这几个键，而 `config/jwt.php` 分别把它们默认成 `true`/`true`/`false`/`[]`。
- **风险**：一旦 `Config::get('jwt')` 没能正确加载（安装路径错误、配置未发布等），`tokenConfig()` 会静默退回到类内默认值，`ip`/`user_agent` 检查会静默变成关闭状态——和 `config/jwt.php` 对外宣称的默认开启正好相反，安全姿态在悄悄降级。
- **建议方向**：把默认值收敛成单一来源（比如 `tokenConfig()` 直接 `require` `config/jwt.php` 作为默认值，而不是再手写一份）。
