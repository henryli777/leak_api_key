# leak_api_key

公开来源 AI 密钥、base_url、模型配置泄露线索监测器。项目结构参考 `liebesu/google_ssr_actions` 的定时抓取、去重、历史回写、钉钉通知思路，但这里默认只保存脱敏结果。

## 目标

- 从 GitHub Code / Issues 和 Google SerpAPI 结果里发现疑似泄露线索。
- 识别 AI 相关 `API_KEY`、`base_url`、`OPENAI_BASE_URL`、`model` 等配置。
- 输出脱敏后的 `data/findings.json`、`dist/health.json`、`dist/findings.json` 和 HTML 报告。
- 可选生成 `dist/private.html` 独立明文页，输入账号和密码后在浏览器本地解密查看完整值。
- 生成 `dist/validation.html` 模型验证页；配置授权目标后会对你显式授权的 base_url/key 做 `/models` 拉取和模型可用性测试。
- 对新增中高风险线索发送钉钉通知。
- 支持后续通过 `config/targets.yml` 或 GitHub Secret `TARGETS_YAML` 设定品牌、域名、仓库、项目名等目标。

## 安全边界

本项目只做公开页面检索、特征识别、脱敏、去重和通知：

- 不验证泄露密钥是否可用。
- 不调用泄露的 base_url 或模型接口。
- 默认不在仓库里保存完整密钥。
- `dist/private.html` 不写入明文，只写入加密密文；需要 `PRIVATE_REPORT_PASSWORD` 才会生成。
- 默认不抓取 Google 结果页面正文，只分析 SerpAPI 返回的标题和摘要；如需正文抓取，请仅在授权监测范围内把 `sources.google.fetch_pages` 设为 `true`。
- 模型可用性测试只读取 `AUTHORIZED_VALIDATION_TARGETS_JSON` 中你主动配置的凭据，不会用泄露 findings 里的 key 发请求。

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
- `.github/workflows/leak-monitor.yml`：每 3 小时定时执行，支持手动触发。

## 输出

- GitHub Pages: `https://henryli777.github.io/leak_api_key/`
- `data/findings.json`：脱敏后的持久化历史，Actions 会回写提交。
- `data/last_run.json`：最近一次运行健康状态。
- `dist/index.html`：本轮 HTML 报告，Actions 上传为 artifact。
- `dist/private.html`：可选明文登录页，只有设置 `PRIVATE_REPORT_PASSWORD` 时生成。
- `dist/validation.html`：授权模型可用性测试页；未配置授权目标时显示空状态和默认模型库。
- `dist/validation.json`：授权模型可用性测试数据，不包含 key。
- `dist/health.json`：统计摘要。
- `dist/findings.json`：脱敏后的报告数据。
