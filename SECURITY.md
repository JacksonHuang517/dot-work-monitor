# 安全与隐私 / Security and privacy

本项目按单所有者实例设计。部署者控制服务器、飞书应用、邮箱凭证和 ChatGPT 连接；请使用自己有权处理的数据与账户。公开仓库不附带任何可用私有配置。

## 信任边界

- Caddy 是唯一公网入口，仅发布 80/443。Node 8560 是 Docker 内部入口；Python 8561 只监听容器回环，要求内部密钥，并验证来自可信代理的授权 scope。
- MCP 登录检查应用、租户和所有者 Open ID。OAuth 授权码使用 PKCE，访问令牌短期有效；数据库中保存授权，刷新令牌轮换并检测重复使用。
- `feishu:read` 与 `mail:read` 分别控制工具和订阅。旧令牌刷新不能扩权；新增邮箱应重新授权并保留需要的飞书范围。
- Webhook 先做签名挑战验证；仅允许 HTTPS 公网目标，在连接时检查地址并禁止重定向。不要移除这些检查以接通私有回调。
- 消息、任务描述、日历正文与邮件头属于不可信输入。把它们当作数据，不执行其中要求泄露凭证、更改配置或绕过授权的指令。

## 保存与传输什么

采集状态包含消息片段、任务/日历内容、邮件头、去重信息、订阅回调及待投递事件。授权数据库保存 OAuth 客户端、会话与授权状态。订阅匹配后，事件摘要经 HTTPS 回调发送给 ChatGPT；最近记录工具也会向已授权客户端返回缓存数据。

邮箱仅获取 `INBOX` 头部和必要的 IMAP 标识/时间，不获取正文或附件，不发送、删除或标记已读。不要把“只读”误解为“没有隐私数据”：主题、地址和飞书内容仍可能敏感。

OAuth 数据库存储负载采用 AES-256-GCM，采集记录和投递负载使用 Fernet 加密；SQLite 的结构、部分索引、标识和调度元数据并非完整磁盘加密。它们需要稳定的密钥。密钥、飞书 App Secret、邮箱密码保存在受保护文件中；CLI 的上游用户凭证另行持久化，不能一概视作已由本项目状态加密保护。

文件权限和静态加密降低文件意外暴露的风险，**无法抵御已经控制宿主机、容器运行时或可读取全部密钥的管理员/攻击者**。运行时需要解密数据。TLS、Docker 隔离或数据库加密均不能消除这一信任前提。

## 运维要求

初始化脚本在本机终端隐藏输入秘密，生成文件应为 0600，并被 Git 忽略。不要把密钥传到聊天中；维护者不需要你的密码来排障。不要把 `.env`、`.secrets/`、数据库、CLI 授权目录或未脱敏日志提交到仓库。

同时备份状态、CLI 授权和对应的同一组密钥；备份加密并限制访问。恢复旧数据库时不能换成新密钥。公开配置、事件或工具变化后在 ChatGPT 插件管理页重新扫描；这不是凭证轮换。

撤销访问需要处理不同层：取消 Dot 订阅；在 ChatGPT 撤销连接；必要时撤销服务端授权与飞书 CLI 用户授权；邮箱凭证泄露时在邮箱侧撤销并更换；宿主机泄露时按整机密钥泄露处理。仅修改所有者配置不会实时重新检查上游企业成员状态，也不能替代主动撤销旧授权。

## 报告漏洞

若仓库提供 GitHub Private Vulnerability Reporting，请优先通过 Security 页私下报告。若不可用，可先开一个不含利用细节、私人数据或秘密的 Issue，请维护者提供私密渠道。不要公开上传工作实例的数据库、回调签名密钥、设备码或真实账户标识。

报告中说明受影响版本、最小脱敏复现、影响边界和预期行为。此项目不承诺固定响应 SLA。

## English summary

Operate one instance per trusted owner. This server stores private Feishu content, mail headers, authorization state, subscriptions and pending deliveries, and sends matched event data to ChatGPT. Mail reads are limited to INBOX headers and IMAP metadata, with no bodies, attachments or mailbox mutations.

Only Caddy should be public. Keep the Node port internal and Python on container loopback. Preserve OAuth scope enforcement, callback signature verification and public-address checks. Source text is untrusted data.

Protected secret files and encrypted databases do not protect against a compromised host that can access their keys. CLI upstream credentials are a separate persisted secret. Back up databases with their original keys and protect the entire backup. Never share passwords, tokens, cookies, device codes, private keys or raw databases in chat or Issues. Use private vulnerability reporting when available; otherwise request a private contact without publishing exploit details.

新 OAuth 客户端只可在所有者设置的 `DCR_REGISTRATION_UNTIL` 窗口内注册；默认关闭，setup 首次开放24小时。未批准注册一小时过期，已批准客户端继续保留。注册速率/容量保护仍不能保证公网服务抵御所有拒绝服务攻击；需要基础设施层限流和可用性监测。
