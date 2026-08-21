# 已知问题清单

来自 `/code-review` 对当前 `v3` 分支的评审结果,按优先级排列。

## 已解决

- **`user_agent` 哈希不一致**(create/verify 两边算法不统一)已在 `src/Jwt.php` 中修复(抽出共用的 `userAgentHash()` 方法)。
- **EdDSA 之外的算法没有兜底/校验**:`create()`/`verify()` 现在都会在密钥为空时显式抛出 `JwtException`(`create()` 补齐了和 `verify()` 对称的校验),不再对任意算法静默用空密钥签发/校验 token。
- **`create()` 缺少空密钥校验**:已在 `create()` 中加入 `if (!$key) throw new JwtException(...)`,和 `verify()` 保持对称的异常契约。
- **`config/pem/*.pem` 未提交到 git**:`config/pem/private.pem`、`config/pem/public.pem` 已提交,`git ls-files` 可见,不再是未跟踪状态。
- **`JwtCache` 没有任何异常处理**:`set`/`get`/`del` 三个方法均已包一层 try/catch,统一转换成 `JwtException`。
- **`getIp()` 手写解析,安全性弱于框架自带方法**:已改为直接委托 `\think\facade\Request::ip($type, $adv)`,交由框架统一处理可信代理校验与 IPv6。
- **`getIp()` 的静态缓存在长驻进程下跨请求复用**:随上一条一并解决——不再自行做进程级 `static` 缓存,IP 解析完全交给请求级别的 `Request` 实例。
- **两处默认配置重复且已经分叉**:`tokenConfig()` 不再维护单独的类内默认值,改为直接 `require config/jwt.php` 作为默认值,和发布的配置文件保持单一来源。
- **JWT 会话缓存不再隔离**:新增 `\Kaadon\Jwt\Contract\JwtCacheHandler` 接口,`JwtCache` 按 `config/jwt.php` 的 `cache_handler` 配置项解析——留空时沿用原来 `think\facade\Cache` 的默认读写逻辑(行为不变);需要多机部署下的会话隔离时,业务方自行实现该接口(例如指向独立的 Redis host/port/select/prefix)并把类名填进 `cache_handler` 即可,库本身不替使用者预设隔离策略。

## 待处理

暂无。
