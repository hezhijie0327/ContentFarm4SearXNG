# ContentFarm4SearXNG

[![License](https://img.shields.io/badge/License-Apache%202.0--Commons%20Clause-blue)](LICENSE)
[![Python](https://img.shields.io/badge/Python-3776AB?logo=python&logoColor=white)](https://www.python.org/)

ContentFarm4SearXNG 聚合多个社区内容农场/独立博客名单，压成正则化 YAML 规则供 SearXNG 的 hostnames 插件使用；Python 3.8+（requests + pyyaml），GitHub Actions 每日两次更新。开发规范见 [AGENTS.md](AGENTS.md)。

## 特性

- **多源聚合**：从 10 个社区来源获取内容农场过滤列表与独立博客白名单
- **多格式解析**：支持 uBlock、v2ray、纯域名、CSV 四种来源格式
- **人工裁决**：`custom/classify.txt` 支持 remove / low_priority / high_priority / replace / skip 五种动作
- **正则压缩**：按 TLD 分组、公共前后缀合并、分批控制规则长度
- **自动更新**：GitHub Actions 每日 UTC 08:00 / 20:00 构建并提交

## 快速开始

### 直接下载

| 类别 | 文件 | 说明 |
| ---- | ---- | ---- |
| 主配置 | [hostnames-config.yml](dist/hostnames-config.yml) | 引用其余规则文件的入口 |
| 移除 | [remove-hosts.yml](dist/remove-hosts.yml) | 从搜索结果中移除内容农场 |
| 低优先级 | [low-priority-hosts.yml](dist/low-priority-hosts.yml) | 降低结果排序 |
| 低优先级 + 移除 | [low-priority-hosts-all.yml](dist/low-priority-hosts-all.yml) | 上述两类的并集 |
| 高优先级 | [high-priority-hosts.yml](dist/high-priority-hosts.yml) | 提升结果排序 |
| 替换 | [rewrite-hosts.yml](dist/rewrite-hosts.yml) | 域名替换映射 |

### 本地构建

```bash
python3 -m venv .venv
. .venv/bin/activate
pip install requests pyyaml

python3 build.py
```

可选参数：

```bash
python3 build.py --config your_config.yml   # 深度合并自定义配置
python3 build.py --single-regex             # 每个类别生成单行正则
```

## 用法

### 自定义分类规则

编辑 `custom/classify.txt`，每行一条 `动作:域名`（`#` 开头为注释）：

```text
# 主动添加
high_priority:github.com
low_priority:blog.csdn.net
remove:spam-site.com

# 跳过该域名（不参与源默认分类，但显式规则仍可覆盖）
skip:baidu.com

# 通配符匹配本体与全部子域
low_priority:*.example.com

# 域名替换
replace:youtube.com=yt.example.com
```

同一域名有多条非 skip 规则时取最后一条；显式规则优先于 skip。

### 接入 SearXNG

把 `dist/` 下 6 个 YAML 放到 SearXNG 的 `settings.yml` 同目录（通常是 `/etc/searxng/`），然后引用：

```yaml
hostnames:
  high_priority: 'high-priority-hosts.yml'
  low_priority: 'low-priority-hosts.yml'
  remove: 'remove-hosts.yml'
  replace: 'rewrite-hosts.yml'
```

`hostnames-config.yml` 已包含上述引用，可直接作为模板复制。规则文件内容为 SearXNG hostnames 插件的正则列表。

## 文档

- [AGENTS.md](AGENTS.md) — 开发规范、架构与实现细节（英文）

## License

[Apache License 2.0 with Commons Clause v1.0](LICENSE)
