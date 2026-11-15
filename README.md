# ContentFarm4SearXNG

[![License](https://img.shields.io/badge/License-Apache%202.0--Commons%20Clause-blue)](LICENSE)
[![Python](https://img.shields.io/badge/Python-3776AB?logo=python&logoColor=white)](https://www.python.org/)

ContentFarm4SearXNG 是一个为 SearXNG 搜索引擎生成主机名规则的 Python 工具。它从各种来源获取内容农场过滤列表，处理后生成分类的 YAML 规则文件，帮助 SearXNG 过滤低质量内容农场，同时优先显示可靠来源。开发规范见 [AGENTS.md](AGENTS.md)。

## 特性

- **自动获取规则**：从多个可信来源获取内容农场过滤列表
- **多格式支持**：支持 uBlock、v2ray、CSV 等多种规则格式
- **智能分类**：自动将域名分类为移除、低优先级、高优先级等类别
- **规则优化**：实现域名合并和正则表达式优化以提高性能
- **自动分类**：使用配置文件覆盖源分类，实现精确控制
- **详细统计**：提供处理过程的详细统计信息

## 快速开始

### 环境要求

- Python 3.8+
- 必要的 Python 包：requests, pyyaml, argparse

### 安装依赖

```bash
pip install requests pyyaml argparse
```

### 基本使用

```bash
# 运行主机名生成器
python3 hostname_generator.py
```

### 自定义配置

可以创建自定义配置文件来调整生成行为：

```bash
python3 hostname_generator.py --config your_config.yml
```

## 配置说明

### 自动分类规则

`auto_classify.txt` 文件用于手动覆盖自动分类：

```text
# 语法说明：
# - "remove:example.com"           # 将 example.com 添加到移除列表
# - "low_priority:google.com"      # 将 google.com 添加到低优先级列表
# - "high_priority:wikipedia.org"  # 将 wikipedia.org 添加到高优先级列表
# - "replace:youtube.com=yt.example.com"  # 替换规则
# - "skip:baidu.com"               # 跳过处理此域名

# 示例
high_priority:github.com
high_priority:stackoverflow.com
low_priority:blog.csdn.net
remove:spam-site.com
```

### 测试

```bash
# 运行所有测试
python3 -m unittest discover -s tests -p "test_*.py"

# 运行特定测试文件
python3 -m unittest tests/test_specific_file.py

# 运行特定测试方法
python3 -m unittest tests.test_specific_file.TestClass.test_method
```

## 项目结构

```text
ContentFarm4SearXNG/
├── hostname_generator.py          # 主生成器脚本
├── auto_classify.txt              # 手动分类规则
├── .github/workflows/main.yml      # CI/CD 工作流
└── rules/                          # 生成的规则文件
    ├── hostnames-config.yml        # 主配置文件
    ├── high-priority-hosts.yml     # 高优先级域名
    ├── low-priority-hosts.yml      # 低优先级域名
    ├── remove-hosts.yml            # 要移除的域名
    └── rewrite-hosts.yml           # 域名替换规则
```

## License

[Apache License 2.0 with Commons Clause v1.0](LICENSE)
