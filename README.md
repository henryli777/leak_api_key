# leak_api_key

公开来源 AI 密钥、base_url、模型配置泄露线索监测器。项目结构参考 `liebesu/google_ssr_actions` 的定时抓取、去重、历史回写、钉钉通知思路，但这里默认只保存脱敏结果。

## 目标

- 从 GitHub Code / Issues 和 Google SerpAPI 结果里发现疑似泄露线索。
- 识别 AI 相关 `API_KEY`、`base_url`、`OPENAI_BASE_URL`、`model` 等配置。
- 专项识别 `/api/providers` 暴露的 provider 配置对象，按同一 JSON/JS/config block 绑定 `baseUrl/base_url` 和 `apiKey/api_key/key`。
- 输出脱敏后的 `data/history/` 分片历史、`dist/health.json`、`dist/findings.json` 和 HTML 报告。
- 可选生成 `dist/private.html` 独立明文页，输入账号和密码后在浏览器本地解密查看完整值。
- 生成 `dist/validation.html` 后台真实模型验证结果页；配置授权目标后会对你显式授权的 base_url/key 发起真实后台请求，拉取 `/models` 并测试模型可用性，同时保留验证时间。
- 时间统一按东八区 `Asia/Shanghai` 输出。
- 密钥识别和导出默认只保留 `sk-` 前缀的 OpenAI-compatible key；公开导出自检会拒绝非 `sk-` 的 literal key 行。
- 历史数据仍按 `key + base_url` 细粒度配对保存；报告页、公开 CSV 和私有明文 CSV 会按 `key_sha256` 去重导出，同一 key 的多个 base_url 合并到同一行。
- 公开泄露 findings 不做未授权 live test；报告会给出公开证据强度，只有你主动配置授权凭据的目标才会进入后台真实验证。
- 总览页提供 `findings.csv` 下载，内容为按密钥去重后的脱敏证据、哈希、配对来源和公开证据强度。
- 额外生成 `provider_pairs.csv`，按 `key_sha256 + base_url_sha256 + source_url + provider_name` 导出 provider 配置级证据。
- `private.html` 登录解密后提供“下载明文CSV”，CSV 在浏览器本地生成，不作为公开文件发布；同一明文 key 只导出一行，多个 base_url 用单元格内换行保留。
- 对新增中高风险线索发送钉钉通知。
- 支持后续通过 `config/targets.yml` 或 GitHub Secret `TARGETS_YAML` 设定品牌、域名、仓库、项目名等目标。

## 安全边界

本项目只做公开页面检索、特征识别、脱敏、去重和通知：

- 不验证泄露密钥是否可用。
- 不调用泄露的 base_url 或模型接口。
- 默认不在仓库里保存完整密钥。
- `dist/private.html` 不写入明文，只写入加密密文；需要 `PRIVATE_REPORT_PASSWORD` 才会生成。
- 明文 CSV 只在 `private.html` 解密成功后由浏览器本地生成，不会写入 `dist/` 或 GitHub Pages 的静态文件列表。
- 默认不抓取普通 Google 结果页面正文，只分析 SerpAPI 返回的标题和摘要；如果 Google 命中 GitHub blob/raw 源码链接，会自动拉取 raw 内容分析。普通网页正文抓取请仅在授权监测范围内把 `sources.google.fetch_pages` 设为 `true`。
- 模型可用性测试是真实后台验证，只读取 `AUTHORIZED_VALIDATION_TARGETS_JSON` 中你主动配置的凭据，不会用泄露 findings 里的 key 发请求。
- 历史 base_url 备选配对只用于生成候选组合；公开 JSON 仍只保存脱敏 base_url 和哈希，明文值只会进入加密的 `private.html`。
- 公开导出会清理来源 URL query 参数，并在 Actions 中执行 `verify-exports`，防止 raw key 或 token 参数进入公开文件。

建议仓库保持 private，因为脱敏结果仍会包含来源 URL 和排查线索。

## 本地运行

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
cp config/targets.example.yml config/targets.yml
python main.py self-test
python main.py scan --config config/targets.yml --sources github --max-queries 4
```

GitHub 搜索需要 `GITHUB_TOKEN`：

```bash
export GITHUB_TOKEN=ghp_xxx
python main.py scan --sources github --max-queries 4
```

Google 搜索需要 SerpAPI，支持单个、多行或逗号分隔：

```bash
export SERPAPI_KEY='key1
key2
key3'
python main.py scan --sources google --max-queries 4
```

## 来源退避与采集状态

保留现有每 6 小时调度、查询范围、`max_queries` 和 `per_query`。仅对超时、连接中断、HTTP 5xx、429 或带 `Retry-After` 的 403 做有限重试；同一请求最多 3 次，普通瞬时失败默认等待 2 秒、4 秒。会检查 `Retry-After` 秒数 / HTTP 日期，不缩短服务端冷却时间。GitHub 次级限流没有可用 `Retry-After` 时至少按 60 秒处理，因此超过本轮 30 秒单次退避上限后直接延后；GitHub 的 `X-RateLimit-Reset` 仅在剩余配额为 0 时具有主配额含义，此时本轮直接停止。正剩余配额或未报告剩余配额的 GitHub 次级限流不会被日常重置时间覆盖。其他来源的限流响应在未报告正剩余配额时可参考显式重置时间。普通 5xx 不会因日常配额重置头而延后，但仍遵守 `Retry-After`。

单次退避超过 30 秒、来源累计退避将超过 60 秒，或 3 次仍失败时，停止本来源并延后剩余查询。明确配额耗尽时也立即停止，不切换凭据绕过限制；重试始终使用同一凭据。401 和普通权限 403 不重试，422 不重试且保留后续请求间隔。Google 的可选结果页与 SerpAPI 主查询分开处理：结果页 401、403、429、配额耗尽或瞬时失败最终未恢复时，仅延后该主机在本轮的后续正文抓取，保留标题和摘要，继续健康的主查询与其他主机；结果页 429 不重试。SerpAPI 自身的权限和限流错误仍按来源级规则停止。正文抓取与主查询共用全部请求、退避等待和 600 秒预算，实际正文请求后也保留正常间隔。

每个来源在发出请求和等待前检查 600 秒预算，包含网络耗时、正常间隔及退避，并把单次网络超时收紧到剩余预算。最多请求次数按原查询数及结果数计算：GitHub 为 `3 × 查询数 × (2 + per_query)`，Google 为 `3 × 查询数 × (1 + per_query)`，不新增查询或扩大正文抓取范围。这个预算可能使响应很慢的正常来源部分完成；正在进行的请求仍遵循 Requests 的连接 / 读取超时语义，预算不是后台请求的硬中断器。

`health.json` 保留旧字段并增加来源状态（`complete` / `partial` / `failed` / `no_queries` / `skipped`）、计划、已尝试、完成、失败及延后查询数。`queries` 仍是已尝试的逻辑查询数，不把重试重复计入；GitHub 同一逻辑查询的 Code 和 Issues 均完整返回才算完成，`incomplete_results` 不算完整。`deferred_queries` 只计从未开始的查询；失败或只完成一部分的当前查询计入 `failed_queries`，因此计划数等于完成 + 失败 + 延后。`errors` 计失败请求尝试及不完整响应，`failed_requests` 计最终未成功的请求；重试成功可以同时保留错误次数并显示采集完成。`deferred_content_requests` 另计因主机停止或共享预算而未发出的可选正文请求，不计入失败请求或逻辑查询。正文补充请求失败或延后会使来源为部分完成，即使主查询已完成。

页面和现有钉钉通知显示结构化完成情况；错误信息只记录固定原因及 HTTP 状态，不保存响应正文、查询 URL 或异常文本。旧快照未记录的新计数显示为未知，不从旧 `errors=0` 推断采集完整。页面“本轮检查时间”沿用原 `build_time`，不代表每个来源都成功采集；线索仍使用原发现 / 最后出现时间。只更新展示时必须保留原健康 JSON 和快照时间，新的重试统计要等下一次原定运行实际执行后才产生。

## Google 搜索定位策略

Google 不能直接按“任意一级/二级域名”做正则搜索，所以搜索阶段用上下文锚点，检测阶段再做正则提取：

- key 锚点：`"OPENAI_API_KEY=" "sk-"`、`"OPENAI_API_KEY:" "sk-"`、`"Authorization: Bearer sk-"`、`"OPENROUTER_API_KEY" "sk-or-v1"`。
- base_url 锚点：`"OPENAI_BASE_URL=" "https://"`、`"base_url" "https://" "sk-"`、`"api_base" "https://" "sk-"`、`"baseURL" "https://" "apiKey"`。
- SDK 写法锚点：`"client = OpenAI" "base_url" "api_key"`、`"OpenAI(" "base_url=" "api_key="`。
- 接口路径锚点：`"chat/completions" "sk-"`、`"v1/models" "sk-"`。
- Provider API 锚点：`inurl:/api/providers "baseUrl" "apiKey"`、`inurl:/api/providers "sk-"`、`"api/providers" "baseUrl" "apiKey"`、`"api/providers" "models" "baseUrl"`。

检测器会识别 JSON、env、Python/JS 配置里的 key 和 base_url；`base_url: api.example.com/v1` 这种没有协议的域名会按 `https://api.example.com/v1` 归一化后再脱敏、哈希和配对。

`/api/providers` 是特殊高价值入口：即使普通 Google 正文抓取关闭，只要 SerpAPI 结果链接路径包含 `/api/providers`，程序也会抓取该 JSON/API 响应正文再分析，因为这类响应里常见 `baseUrl/baseURL/base_url` 和 `apiKey/api_key/key` 同时出现。

查询配置支持 `queries.source_groups` 分源分组：

- `path_signal`：优先发现 URL 或源码里出现 `/api/providers` 的入口。
- `provider_config`：优先发现同一 provider 配置对象里同时出现 `baseUrl/base_url` 和 `apiKey/api_key/key`。
- `llm_openai_compatible`：保留传统 OpenAI 兼容 key/base_url 搜索。

`provider_config` 结果会记录 `endpoint_path`、`provider_name`、`value_kind`。`value_kind=literal` 表示看起来是明文 key，会写入 key hash；`env_ref` 和 `placeholder` 只作为配置引用证据，不会写入 key hash。

本地生成明文登录页：

```bash
export PRIVATE_REPORT_USER=admin
export PRIVATE_REPORT_PASSWORD='your-strong-password'
python main.py scan --sources github --max-queries 4
open dist/private.html
```

授权模型可用性测试：

```bash
export AUTHORIZED_VALIDATION_TARGETS_JSON='[
  {
    "name": "my-openai-compatible",
    "base_url": "https://api.example.com/v1",
    "api_key": "YOUR_AUTHORIZED_API_KEY",
    "models": ["gpt-4o-mini"],
    "max_models": 8
  }
]'
python main.py scan --sources github --max-queries 1
open dist/validation.html
```

`models` 可省略。省略时会先拉 `{base_url}/models`，如果拉不到模型列表，就使用内置默认模型库测试。

本地授权 CSV 验证：

```bash
cat > secrets.csv <<'CSV'
name,api_key,key_sha256,base_url,base_url_sha256,models,max_models,timeout_seconds
my-key,YOUR_AUTHORIZED_API_KEY,,https://api.example.com/v1,,gpt-4o-mini,8,20
CSV

./scripts/validate_authorized_models.py findings.csv \
  --secrets-csv secrets.csv \
  --base-url-library base-url-library.csv \
  --history-json validation-history.json \
  --i-am-authorized
```

如果你从 `private.html` 登录后下载的是明文 `private-findings-*.csv`，它已经包含 `api_key` 和 `base_url`，可以直接作为输入，不需要额外的 `--secrets-csv`：

```bash
./scripts/validate_authorized_models.py private-findings-2026-07-09.csv \
  --base-url-library base-url-library.csv \
  --history-json validation-history.json \
  --i-am-authorized
```

输出：

- `validation-results.json`：完整后台真实验证结果，不包含明文 key。
- `validation-results.csv`：目标级摘要，不包含 key。
- `validation-available.csv`：只包含可用组合，包含验证时间、脱敏密钥、key 哈希、可用 base_url、可用模型。
- `validation-history.json`：本地历史记录，重复候选默认跳过。
- `base-url-library.csv`：本地明文 base_url 基础库，会合并保存 `secrets.csv` 中出现过的 base_url。

`findings.csv` 负责提供哈希索引和模型/来源信息；`secrets.csv` 负责提供本地明文 key，脚本通过 `key_sha256` 对齐。`secrets.csv` 里缺少 `key_sha256` 时会本地自动计算。私有明文 CSV 可以直接提供 `api_key/base_url`；其中 `base_url` 可以是单个 URL，也可以是单元格内多行 URL，脚本会拆成多个验证候选。某条 key 缺少可匹配 base_url 时，脚本会遍历 `base-url-library.csv` 里的 base_url 作为候选。重复验证过的 `key + base_url + models` 组合会从 `validation-history.json` 跳过；需要全量重验时加：

```bash
./scripts/validate_authorized_models.py findings.csv \
  --secrets-csv secrets.csv \
  --base-url-library base-url-library.csv \
  --history-json validation-history.json \
  --revalidate-all \
  --i-am-authorized
```

脚本只应用于你有权验证的 `base_url + api_key`。网页公开下载的 `findings.csv` 不包含明文 key，不能单独作为验证输入；明文验证请使用 `private.html` 解密后下载的私有 CSV，或另行提供本地 `secrets.csv`。

## 目标配置

复制 `config/targets.example.yml` 为 `config/targets.yml` 后填写：

```yaml
targets:
  keywords:
    - your-brand
  domains:
    - example.com
  owners:
    - github-owner
  repos:
    - github-owner/repo
```

系统会把这些目标套进 `target_templates`，例如：

```yaml
- '"{target}" "OPENAI_API_KEY"'
- '"{target}" "base_url" "sk-"'
```

## GitHub Actions Secrets

仓库 Settings -> Secrets and variables -> Actions：

- `TARGETS_YAML`：可选，完整 YAML 配置；设置后 Actions 会覆盖本地 `config/targets.yml`。
- `SERPAPI_KEY`：可选，启用 Google 搜索；支持多行，每行一个 SerpAPI key。
- `SERPAPI_KEYS`：可选，兼容旧配置；也支持多行或逗号分隔。
- `DINGTALK_WEBHOOK`：可选，完整钉钉机器人 webhook。
- `DINGTALK_TOKEN`：可选，只填 access token 时自动拼接 webhook。
- `DINGTALK_SECRET`：可选，钉钉加签密钥。
- `PRIVATE_REPORT_USER`：可选，明文页登录账号，默认 `admin`。
- `PRIVATE_REPORT_PASSWORD`：可选，明文页解密密码；设置后 Actions artifact 里会生成 `private.html`。
- `AUTHORIZED_VALIDATION_TARGETS_JSON`：可选，授权验证目标 JSON。只用于你自己的 base_url/key，不从泄露结果里取 key。

`GITHUB_TOKEN` 使用 Actions 自动注入的 `github.token`，不需要手动配置。

`private.html` 是静态加密页面，不依赖服务器会话。页面源码里只有 AES-GCM 密文，账号匹配且密码正确后，浏览器本地解密显示完整值。

## 钉钉通知内容

通知只包含摘要和脱敏值：

```text
【AI密钥泄露监测】
时间: 2026-07-07T12:00:00+08:00
新增: 3  需关注: 2  总线索: 18
高危: 4  中危: 7
新增重点:
- high credential openai_compatible: sk-proj-...abcd | owner/repo/.env
```

## 文件说明

- `main.py`：命令入口。
- `leak_monitor/sources.py`：GitHub / Google 来源适配。
- `leak_monitor/detectors.py`：key、base_url、model 特征识别与脱敏。
- `leak_monitor/storage.py`：历史去重和合并。
- `leak_monitor/notify.py`：钉钉通知。
- `.github/workflows/leak-monitor.yml`：每 6 小时定时执行，支持手动触发，默认搜索源为 `github,google`。

## 输出

- GitHub Pages: `https://henryli777.github.io/leak_api_key/`
- `data/history/index.json`：持久化历史清单；每个内容寻址 JSON 分片不超过 4 MiB，保留所有线索 ID、哈希、发现时间及有长度限制的脱敏证据，不按日期丢弃去重状态。
- 旧版 `data/findings.json` 会在下一次成功采集时迁移，历史提交同时删除旧文件。损坏的清单或分片会明确失败，不会默默重置历史。
- Actions 先上传通过安全检查的公开报告，再由独立任务提交脱敏历史；历史推送失败会在任务中显示，但不会阻止 Pages 部署。每 6 小时的采集计划保持不变。
- 推送代码只运行安全测试；采集只由定时任务或 `leak-monitor.yml` 手动触发执行。`publish-support-navigation.yml` 可手动使用原采集任务的已验证报告产物更新公开 UI；必须确认采集、安全检查和报告上传步骤均成功，只有安全测试的推送任务不能充当来源。
- 公开总览和验证页在可见时每 60 秒检查同源快照，回到前台时立即检查；不触发采集或模型验证。报告数据时间保持采集/验证时间，浏览器检查时间单独显示。检查失败时保留现有数据及上次成功检查时间。
- `data/last_run.json`：最近一次运行健康状态。
- `dist/index.html`：本轮 HTML 报告，Actions 上传为 artifact。
- `dist/private.html`：可选明文登录页，只有设置 `PRIVATE_REPORT_PASSWORD` 时生成。
- `dist/validation.html`：后台真实模型验证结果页；展示可用/不可用模型和验证时间，未配置授权目标时显示空状态和默认模型库。
- `dist/validation.json`：授权模型可用性测试数据，不包含 key。
- `dist/findings.csv`：按密钥去重后的脱敏证据 CSV，可从总览页下载。
- `dist/provider_pairs.csv`：按 provider 配置配对去重后的脱敏证据 CSV，适合排查 `/api/providers` 暴露配置。
- `dist/health.json`：统计摘要。
- `dist/findings.json`：脱敏后的报告数据；credential 会规范成 `credential_pair`，`/api/providers` 同块配置会记录为 `provider_config`。
