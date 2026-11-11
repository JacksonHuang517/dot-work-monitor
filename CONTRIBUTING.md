# 贡献指南 / Contributing

欢迎修复兼容性、测试、文档和部署问题。先用脱敏的最小复现明确现象、版本、预期结果；安全漏洞按 [SECURITY.md](SECURITY.md) 报告。

## 本地检查

在仓库根目录使用 Python 3.11+ 和 Node.js 22。建议建立本地虚拟环境后安装 Python 依赖；该目录必须忽略，不要提交运行状态。

```bash
python3 -m venv .venv
.venv/bin/python -m pip install -r requirements-dev.txt
.venv/bin/python -m unittest discover -s tests -v
npm --prefix auth ci
npm --prefix auth run typecheck
npm --prefix auth run build
npm --prefix auth test
```

修改容器或初始化流程时，还需使用自己的空白配置执行初始化预检、`docker compose config --quiet` 和构建验证。不要将输出中的私有字段上传；无法访问 Docker 或真实账户时，明确写出未验证部分。

本地 mock 测试不等于真实飞书登录、邮箱兼容或 Dot 通知验收。只有在自己的部署完成真实订阅、回调成功并观察到 Dot 行为后，才能对该环境作端到端成功声明。

## 修改边界

- 保持默认单所有者、只读采集和两个独立 MCP scope；新增权限或数据读取应在 PR 中明确说明。
- 保持邮箱头部限制、只读选择与 `BODY.PEEK`；不要为了排障加入正文读取或已读/删除操作。
- 保持输入限制、分页检查、UTC 时间处理、重叠窗口、持久化去重、回调验证和加密存储。
- 可复现缺陷应附最小回归测试，尤其是缺失时区、分页异常、权限遗漏、错误重试与刷新扩权。
- 工具/事件字段变化同时更新文档；事件发现或 schema 修改后需要用户在插件详情页重新扫描。
- 不加入真实 app/tenant/user 标识、邮箱、IP、私有域名或本机绝对路径。公开示例域名统一使用 `monitor.example.com`。

提交前查看 diff，确认没有 `.env`、`.secrets/`、数据库、密钥、日志、CLI 凭证或临时输出。PR 描述应简述问题、最终行为、已运行检查和未验证项，保留最小必要 diff。

## English

Use Python 3.11+ and Node.js 22; run the checks above. Add focused regression tests for reproducible bugs. Keep single-owner authorization, read-only sources, independent scopes, UTC handling, bounded collection and verified webhook delivery intact. Never commit real identities, credentials or runtime data.

Describe the problem, resulting behavior, checks actually run and remaining validation limits. Mock tests do not establish a real Dot notification; deployment verification requires real subscriptions, successful callbacks and visible host behavior.

Python formatting: `ruff format dot_feishu scripts tests`; CI checks the same paths with `--check`.
