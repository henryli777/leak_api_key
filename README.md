# leak_api_key

公开来源 AI 密钥、base_url、模型配置泄露线索监测器。项目结构参考 `liebesu/google_ssr_actions` 的定时抓取、去重、历史回写、钉钉通知思路，但这里默认只保存脱敏结果。

## 目标

- 从 GitHub Code / Issues 和 Google SerpAPI 结果里发现疑似泄露线索。
- 识别 AI 相关 `API_KEY`、`base_url`、`OPENAI_BASE_URL`、`model` 等配置。
- 输出脱敏后的 `data/findings.json`、`dist/health.json`、`dist/findings.json` 和 HTML 报告。
- 可选生成 `dist/private.html` 独立明文页，输入账号和密码后在浏览器本地解密查看完整值。
- 生成 `dist/validation.html` 后台真实模型验证结果页；配置授权目标后会对你显式授权的 base_url/key 发起真实后台请求，拉取 `/models` 并测试模型可用性，同时保留验证时间。
- 时间统一按东八区 `Asia/Shanghai` 输出。
- 密钥识别重点覆盖 `sk-` / `sk-proj-` / `sk-ant-` / `sk-or-v1-`，并保留 Groq `gsk_`、Gemini/Google `AIza` 这类明确 AI key 前缀。
- 历史数据仍按 `key + base_url` 细粒度配对保存；报告页、公开 CSV 和私有明文 CSV 会按 `key_sha256` 去重导出，同一 key 的多个 base_url 合并到同一行。
- 公开泄露 findings 不做未授权 live test；报告会给出公开证据强度，只有你主动配置授权凭据的目标才会进入后台真实验证。
- 总览页提供 `findings.csv` 下载，内容为按密钥去重后的脱敏证据、哈希、配对来源和公开证据强度。
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

## Google 搜索定位策略

Google 不能直接按“任意一级/二级域名”做正则搜索，所以搜索阶段用上下文锚点，检测阶段再做正则提取：

- key 锚点：`"OPENAI_API_KEY=" "sk-"`、`"OPENAI_API_KEY:" "sk-"`、`"Authorization: Bearer sk-"`、`"OPENROUTER_API_KEY" "sk-or-v1"`、`"GROQ_API_KEY" "gsk_"`、`"GEMINI_API_KEY" "AIza"`。
- base_url 锚点：`"OPENAI_BASE_URL=" "https://"`、`"base_url" "https://" "sk-"`、`"api_base" "https://" "sk-"`、`"baseURL" "https://" "apiKey"`。
- SDK 写法锚点：`"client = OpenAI" "base_url" "api_key"`、`"OpenAI(" "base_url=" "api_key="`。
- 接口路径锚点：`"chat/completions" "sk-"`、`"v1/models" "sk-"`。

检测器会识别 JSON、env、Python/JS 配置里的 key 和 base_url；`base_url: api.example.com/v1` 这种没有协议的域名会按 `https://api.example.com/v1` 归一化后再脱敏、哈希和配对。

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

输出：

- `validation-results.json`：完整后台真实验证结果，不包含明文 key。
- `validation-results.csv`：目标级摘要，不包含 key。
- `validation-available.csv`：只包含可用组合，包含验证时间、脱敏密钥、key 哈希、可用 base_url、可用模型。
- `validation-history.json`：本地历史记录，重复候选默认跳过。
- `base-url-library.csv`：本地明文 base_url 基础库，会合并保存 `secrets.csv` 中出现过的 base_url。

`findings.csv` 负责提供哈希索引和模型/来源信息；`secrets.csv` 负责提供本地明文 key，脚本通过 `key_sha256` 对齐。`secrets.csv` 里缺少 `key_sha256` 时会本地自动计算。私有明文 CSV 里的 `base_url` 可以是单个 URL，也可以是单元格内多行 URL，脚本会拆成多个验证候选。某条 key 缺少可匹配 base_url 时，脚本会遍历 `base-url-library.csv` 里的 base_url 作为候选。重复验证过的 `key + base_url + models` 组合会从 `validation-history.json` 跳过；需要全量重验时加：

```bash
./scripts/validate_authorized_models.py findings.csv \
  --secrets-csv secrets.csv \
  --base-url-library base-url-library.csv \
  --history-json validation-history.json \
  --revalidate-all \
  --i-am-authorized
```

脚本只应用于你有权验证的 `base_url + api_key`。网页下载的 `findings.csv` 不包含明文 key，不能单独作为验证输入。

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
- `data/findings.json`：脱敏后的持久化历史，Actions 会回写提交。
- `data/last_run.json`：最近一次运行健康状态。
- `dist/index.html`：本轮 HTML 报告，Actions 上传为 artifact。
- `dist/private.html`：可选明文登录页，只有设置 `PRIVATE_REPORT_PASSWORD` 时生成。
- `dist/validation.html`：后台真实模型验证结果页；展示可用/不可用模型和验证时间，未配置授权目标时显示空状态和默认模型库。
- `dist/validation.json`：授权模型可用性测试数据，不包含 key。
- `dist/findings.csv`：按密钥去重后的脱敏证据 CSV，可从总览页下载。
- `dist/health.json`：统计摘要。
- `dist/findings.json`：脱敏后的报告数据；credential 会规范成 `credential_pair`，包含密钥和 base_url 的一组候选。
