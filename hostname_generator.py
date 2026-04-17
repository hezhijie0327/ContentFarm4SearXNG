#!/usr/bin/env python3
"""
SearXNG Hostnames 规则生成器

pip install requests pyyaml argparse
"""

import requests
import yaml
import json
import re
import csv
from urllib.parse import urlparse
from typing import Dict, List, Set, Union, Tuple
import argparse
import sys
import time
import os
from collections import OrderedDict, defaultdict

class SearXNGHostnamesGenerator:
    def __init__(self, config_file: str = None, force_single_regex: bool = False):
        """
        初始化生成器

        Args:
            config_file: 配置文件路径
            force_single_regex: 强制生成单行正则表达式
        """
        self.config = self.load_config(config_file)
        self.force_single_regex = force_single_regex
        self.domains = set()
        self.auto_classify_rules = []  # 自动分类规则
        self.stats = {
            'total_rules': 0,
            'parsed_domains': 0,
            'ignored_with_path': 0,
            'path_to_low_priority': 0,  # 特定路径设置为低优先级的数量
            'path_kept_action': 0,      # 🔧 特定路径保持原动作的数量
            'invalid_domains': 0,
            'duplicate_domains': 0,
            'ignored_comments': 0,
            'auto_classified': 0,  # 自动分类的数量
            'auto_added': 0,  # 主动添加的域名数量
            'skipped_from_sources': 0,  # 从数据源跳过的域名数量
            'skip_overridden': 0,  # skip 规则被其他规则覆盖的数量
            'v2ray_with_tags': 0,  # 带标签的 v2ray 规则数量
            'csv_parsed_rows': 0,  # CSV 解析的行数
            'csv_invalid_urls': 0,  # CSV 中无效 URL 的数量
            'csv_extracted_domains': 0,  # CSV 中成功提取的域名数量
            'wildcard_rules_processed': 0,  # 🔧 处理的通配符规则数量
        }
        # 记录每个类别的域名数量
        self.category_domain_counts = {
            'remove': 0,
            'low_priority': 0,
            'high_priority': 0,
            'replace': 0
        }

        # 加载自动分类规则
        self.load_auto_classify_rules()

    def load_config(self, config_file: str) -> Dict:
        """
        加载配置文件

        Args:
            config_file: 配置文件路径

        Returns:
            配置字典
        """
        default_config = {
            # 数据源配置
            "sources": [
                {
                    "name": "Content Farm Terminator - Content Farm Filters",
                    "url": "https://danny0838.github.io/content-farm-terminator/files/blocklist-ublacklist/content-farms.txt",
                    "action": "remove",
                    "format": "ublock",
                    "enabled": True
                },
                {
                    "name": "Content Farm Terminator - Nearly Content Farm Filters",
                    "url": "https://danny0838.github.io/content-farm-terminator/files/blocklist-ublacklist/nearly-content-farms.txt",
                    "action": "remove",
                    "format": "ublock",
                    "enabled": True
                },
                {
                    "name": "Content Farm Terminator - Bad Cloners",
                    "url": "https://danny0838.github.io/content-farm-terminator/files/blocklist-ublacklist/bad-cloners.txt",
                    "action": "remove",
                    "format": "ublock",
                    "enabled": True
                },
                {
                    "name": "Paxxs - Google Blocklist",
                    "url": "https://raw.githubusercontent.com/Paxxs/Google-Blocklist/refs/heads/develop/uBlacklist_subscription.txt",
                    "action": "remove",
                    "format": "ublock",
                    "enabled": True
                },
                {
                    "name": "cobaltdisco - Google Chinese Results Blocklist",
                    "url": "https://raw.githubusercontent.com/cobaltdisco/Google-Chinese-Results-Blocklist/refs/heads/master/uBlacklist_subscription.txt",
                    "action": "remove",
                    "format": "ublock",
                    "enabled": True
                },
                {
                    "name": "obgnail - Chinese Internet is Dead",
                    "url": "https://raw.githubusercontent.com/obgnail/chinese-internet-is-dead/master/blocklist.txt",
                    "action": "remove",
                    "format": "ublock",
                    "enabled": True
                },
                {
                    "name": "insomnimus - SEO Garbage",
                    "url": "https://raw.githubusercontent.com/insomnimus/seo-garbage/main/list.txt",
                    "action": "remove",
                    "format": "domain",
                    "enabled": True
                },
                {
                    "name": "quenhus - uBlock-Origin-dev-filter",
                    "url": "https://raw.githubusercontent.com/quenhus/uBlock-Origin-dev-filter/main/dist/other_format/domains/all.txt",
                    "action": "remove",
                    "format": "domain",
                    "enabled": True
                },
                {
                    "name": "timqian - Chinese Independent Blogs",
                    "url": "https://raw.githubusercontent.com/timqian/chinese-independent-blogs/refs/heads/master/blogs-original.csv",
                    "action": "high_priority",
                    "format": "csv",
                    "csv_config": {
                        "column": "Address",
                        "has_header": True,
                        "delimiter": ",",
                        "encoding": "utf-8"
                    },
                    "enabled": True
                },
                {
                    "name": "bcaso - Computer Science Whitelist",
                    "url": "https://raw.githubusercontent.com/bcaso/Computer-Science-Whitelist/refs/heads/main/whitelists/domain_name.txt",
                    "action": "high_priority",
                    "format": "ublock",
                    "enabled": True
                },
            ],

            # 自定义规则配置（从文件读取）
            "custom_rules": {
                "enabled": False,
                "sources": []
            },

            # 自动分类语法配置（替换原白名单功能）
            "auto_classify": {
                "enabled": True,
                "sources": [
                    {
                        "name": "Auto Classify Rules",
                        "file": "./auto_classify.txt",
                        "format": "classify",  # 支持 action:domain 语法
                        "enabled": True
                    },
                ],
                # 直接在配置中定义的自动分类规则
                "rules": []
            },

            # 域名替换规则（保留原配置方式）
            "replace_rules": {},

            # 固定的移除规则
            "fixed_remove": [],

            # 固定的低优先级规则
            "fixed_low_priority": [],

            # 固定的高优先级规则
            "fixed_high_priority": [],

            # 解析配置
            "parsing": {
                "ignore_specific_paths": False,     # 不忽略特定路径规则
                # 🔧 修复：特定路径规则处理方式的详细说明和默认值修改
                "specific_path_action": "smart",  # 特定路径规则处理方式：
                                                        # - "keep_action": 保持源的原始动作 (推荐)
                                                        # - "low_priority": 强制设为低优先级
                                                        # - "ignore": 完全忽略
                                                        # - "smart": 智能处理 (remove->low_priority, 其他保持)
                "ignore_ip": True,     # 忽略IP地址
                "ignore_localhost": True,  # 忽略本地主机
                "strict_domain_level_check": True,  # 严格检查域名级别规则
                "preserve_www_prefix": True,  # 保持 www. 前缀
                "preserve_original_structure": True  # 保持原始域名结构
            },

            # 性能优化配置
            "optimization": {
                "merge_domains": True,          # 启用域名合并优化
                "max_domains_per_rule": 256,     # 每个合并规则的最大域名数
                "group_by_tld": True,           # 按顶级域名分组
                "use_trie_optimization": True,  # 使用字典树优化
                "max_rule_length": 65536,       # 单个规则的最大长度限制
                "optimize_tld_grouping": True,   # 优化TLD分组，避免重复
                "enable_prefix_optimization": True,  # 启用前缀优化
                "enable_suffix_optimization": True,  # 启用后缀优化
                "min_common_prefix_length": 3,      # 最小公共前缀长度
                "min_common_suffix_length": 3,      # 最小公共后缀长度
                "force_single_regex": False,         # 强制生成单行正则表达式
                "sort_before_merge": True,          # 合并前排序域名
                "enable_advanced_tld_merge": True   # 启用高级TLD合并
            },

            # 请求配置
            "request_config": {
                "timeout": 30,
                "retry_count": 3,
                "retry_delay": 1
            },

            # 输出配置
            "output": {
                "mode": "separate_files",  # separate_files 或 single_file
                "directory": "./rules/",
                "files": {
                    "replace": "rewrite-hosts.yml",
                    "remove": "remove-hosts.yml",
                    "low_priority": "low-priority-hosts.yml",
                    "low_priority_all": "low-priority-hosts-all.yml",
                    "high_priority": "high-priority-hosts.yml",
                    "main_config": "hostnames-config.yml"
                }
            }
        }

        if config_file:
            try:
                with open(config_file, 'r', encoding='utf-8') as f:
                    user_config = yaml.safe_load(f)
                    # 深度合并配置
                    self._deep_merge(default_config, user_config)
            except FileNotFoundError:
                print(f"配置文件 {config_file} 不存在，使用默认配置")
            except Exception as e:
                print(f"加载配置文件失败: {e}")
                return default_config

        return default_config

    def _deep_merge(self, base_dict: Dict, update_dict: Dict) -> None:
        """
        深度合并字典
        """
        for key, value in update_dict.items():
            if key in base_dict and isinstance(base_dict[key], dict) and isinstance(value, dict):
                self._deep_merge(base_dict[key], value)
            else:
                base_dict[key] = value

    def extract_hostname_from_url(self, url_string: str) -> str:
        """
        从 URL 字符串中提取 hostname

        Args:
            url_string: URL 字符串

        Returns:
            提取的 hostname，如果失败返回 None
        """
        if not url_string:
            return None

        url_string = url_string.strip()

        # 如果没有协议，尝试添加 http://
        if not url_string.startswith(('http://', 'https://', 'ftp://')):
            # 检查是否看起来像一个完整的域名
            if '.' in url_string and not url_string.startswith('/'):
                url_string = 'http://' + url_string
            else:
                return None

        try:
            parsed = urlparse(url_string)
            hostname = parsed.netloc

            if not hostname:
                return None

            # 移除端口号
            if ':' in hostname:
                hostname = hostname.split(':')[0]

            # 验证域名格式
            if self.is_valid_domain(hostname):
                return hostname.lower()

        except Exception as e:
            print(f"  ❌ URL 解析失败: {url_string} - {e}")

        return None

    def parse_csv_rule(self, csv_row: List[str], csv_config: Dict, row_num: int) -> Tuple[str, str]:
        """
        解析 CSV 行，提取域名

        Args:
            csv_row: CSV 行数据列表
            csv_config: CSV 配置
            row_num: 行号（用于错误信息）

        Returns:
            (域名或 None, 忽略原因)
        """
        try:
            # 获取目标列的值
            column = csv_config.get("column")
            column_index = csv_config.get("column_index")

            target_value = None

            if column_index is not None:
                # 使用列索引
                if 0 <= column_index < len(csv_row):
                    target_value = csv_row[column_index].strip()
                else:
                    return None, f"列索引 {column_index} 超出范围 (行 {row_num})"
            elif column:
                # 使用列名（需要 headers）
                return None, "使用列名需要在头部信息中查找，这应该在调用方处理"
            else:
                return None, "未指定列名或列索引"

            if not target_value:
                return None, "目标列值为空"

            # 从 URL 中提取 hostname
            hostname = self.extract_hostname_from_url(target_value)
            if hostname:
                return hostname, None
            else:
                return None, f"无法从 URL 提取域名: {target_value}"

        except Exception as e:
            return None, f"解析 CSV 行时出错 (行 {row_num}): {e}"

    def load_csv_rules_from_file(self, file_path: str, csv_config: Dict, action: str) -> Tuple[Set[str], Dict[str, str], Dict]:
        """
        从 CSV 文件加载规则

        Args:
            file_path: CSV 文件路径
            csv_config: CSV 配置
            action: 动作类型

        Returns:
            (域名集合, 替换规则字典, 统计信息)
        """
        domains = set()
        replace_rules = {}
        stats = {
            'total_rules': 0,
            'parsed_domains': 0,
            'invalid_domains': 0,
            'ignored_comments': 0,
            'csv_parsed_rows': 0,
            'csv_invalid_urls': 0,
            'csv_extracted_domains': 0
        }

        # CSV 配置默认值
        has_header = csv_config.get("has_header", True)
        delimiter = csv_config.get("delimiter", ",")
        encoding = csv_config.get("encoding", "utf-8")
        column = csv_config.get("column")
        column_index = csv_config.get("column_index")

        try:
            with open(file_path, 'r', encoding=encoding) as f:
                csv_reader = csv.reader(f, delimiter=delimiter)

                headers = None
                actual_column_index = None

                for row_num, row in enumerate(csv_reader, 1):
                    if not row or all(cell.strip() == '' for cell in row):
                        continue  # 跳过空行

                    stats['total_rules'] += 1

                    # 处理头部行
                    if has_header and row_num == 1:
                        headers = [cell.strip() for cell in row]

                        # 如果指定了列名，找到对应的索引
                        if column:
                            try:
                                actual_column_index = headers.index(column)
                                print(f"  📍 找到目标列 '{column}' 位于索引 {actual_column_index}")
                            except ValueError:
                                print(f"  ❌ 未找到指定的列名 '{column}'")
                                print(f"  📋 可用的列名: {', '.join(headers)}")
                                return domains, replace_rules, stats
                        elif column_index is not None:
                            actual_column_index = column_index
                            if actual_column_index < len(headers):
                                print(f"  📍 使用列索引 {actual_column_index}: '{headers[actual_column_index]}'")
                            else:
                                print(f"  ❌ 列索引 {actual_column_index} 超出范围")
                                return domains, replace_rules, stats

                        continue  # 跳过头部行，不解析数据

                    # 如果没有设置实际列索引，使用配置的列索引
                    if actual_column_index is None and column_index is not None:
                        actual_column_index = column_index

                    stats['csv_parsed_rows'] += 1

                    try:
                        # 解析 CSV 行
                        if actual_column_index is not None:
                            if actual_column_index < len(row):
                                url_value = row[actual_column_index].strip()
                                if url_value:
                                    domain = self.extract_hostname_from_url(url_value)
                                    if domain:
                                        domains.add(domain)
                                        stats['parsed_domains'] += 1
                                        stats['csv_extracted_domains'] += 1

                                        # 显示一些解析样本
                                        if stats['csv_extracted_domains'] <= 5:
                                            print(f"    ✅ CSV 解析: {url_value} -> {domain}")
                                    else:
                                        stats['csv_invalid_urls'] += 1
                                        if stats['csv_invalid_urls'] <= 3:
                                            print(f"    ❌ 无效 URL: {url_value}")
                                else:
                                    stats['invalid_domains'] += 1
                            else:
                                stats['invalid_domains'] += 1
                                if stats['invalid_domains'] <= 3:
                                    print(f"    ❌ 行 {row_num} 列索引超出范围")
                        else:
                            stats['invalid_domains'] += 1
                            print(f"    ❌ 未设置有效的列索引")

                    except Exception as e:
                        print(f"    ❌ 解析第 {row_num} 行时出错: {e}")
                        stats['invalid_domains'] += 1

                print(f"    ✅ CSV 解析完成: {stats['csv_extracted_domains']} 个有效域名")
                if stats['csv_invalid_urls'] > 0:
                    print(f"    ⚠️  忽略了 {stats['csv_invalid_urls']} 个无效 URL")

        except FileNotFoundError:
            print(f"    ❌ 文件不存在: {file_path}")
        except Exception as e:
            print(f"    ❌ 读取 CSV 文件失败: {e}")

        return domains, replace_rules, stats

    def parse_v2ray_rule(self, rule: str) -> Tuple[str, str]:
        """
        解析 v2ray 格式规则，提取域名，保持原始结构

        支持的格式：
        - domain:example.com          # 匹配域名及所有子域名
        - full:example.com            # 完全匹配域名
        - domain:example.com:@tag     # 带标签的域名规则
        - full:www.example.com:@tag   # 保持 www 前缀

        Args:
            rule: v2ray 规则字符串

        Returns:
            (域名或 None, 忽略原因)
        """
        original_rule = rule  # 保存原始规则用于调试
        rule = rule.strip()

        if not rule or rule.startswith('#'):
            return None, "注释或空行"

        # 处理行末注释
        if '#' in rule:
            comment_pos = rule.find('#')
            rule = rule[:comment_pos].strip()
            if not rule:
                return None, "仅包含注释"

        # 检查是否是 v2ray 格式
        if ':' not in rule:
            return None, "非 v2ray 格式"

        # 分离各部分：prefix:domain[:tag...]
        parts = rule.split(':')
        if len(parts) < 2:
            return None, "无效的 v2ray 格式"

        prefix = parts[0].strip().lower()

        # 验证前缀
        if prefix not in ['domain', 'full']:
            return None, f"不支持的 v2ray 前缀: {prefix}"

        # 提取域名部分
        domain_part = parts[1].strip()

        if not domain_part:
            return None, "域名部分为空"

        # 处理标签部分（如果存在）
        tag_info = None
        if len(parts) > 2:
            tag_parts = parts[2:]
            # 检查是否有标签
            tags = [part.strip() for part in tag_parts if part.strip()]
            if tags:
                tag_info = ':'.join(tags)
                self.stats['v2ray_with_tags'] += 1
                # 显示标签信息用于调试
                print(f"    📝 v2ray 带标签: {original_rule} -> 域名: {domain_part}, 标签: {tag_info}")

        # 验证和清理域名（保持原始结构）
        cleaned_domain = self._clean_v2ray_domain(domain_part)
        if not cleaned_domain:
            return None, "无效域名"

        return cleaned_domain, None

    def _clean_v2ray_domain(self, domain: str) -> str:
        """
        专门为 v2ray 域名清理的方法，保持原始结构

        Args:
            domain: v2ray 域名部分

        Returns:
            清理后的域名（保持原始结构）
        """
        if not domain:
            return None

        # 移除协议（如果意外包含）
        if domain.startswith(('http://', 'https://')):
            parsed = urlparse(domain)
            domain = parsed.netloc
            if parsed.port:
                # 如果URL中有端口，移除它
                domain = domain.replace(f':{parsed.port}', '')

        # 对于 v2ray 格式，通常不应该有端口号
        # 但如果有明显的数字端口则移除
        if ':' in domain:
            parts = domain.split(':')
            if len(parts) == 2 and parts[1].isdigit() and int(parts[1]) <= 65535:
                # 只有当第二部分是有效端口号时才移除
                domain = parts[0]
                print(f"    🔧 移除端口号: {':'.join(parts)} -> {domain}")

        # 移除路径（如果意外包含）
        if '/' in domain:
            domain = domain.split('/')[0]

        # **不移除 www. 前缀 - 保持原始结构**
        # 这里注释掉原来的代码：
        # if domain.startswith('www.'):
        #     domain = domain[4:]

        # 只移除明显无关的字符，保留域名的完整性
        # 不使用激进的字符过滤，只移除明显的空白字符
        domain = domain.strip()

        # 检查是否是IP地址
        if self.config["parsing"]["ignore_ip"] and self.is_ip_address(domain):
            return None

        # 检查是否是localhost
        if self.config["parsing"]["ignore_localhost"] and domain in ['localhost', '127.0.0.1', '0.0.0.0']:
            return None

        # 验证域名格式
        if self.is_valid_domain(domain):
            return domain.lower()

        return None

    def load_auto_classify_rules(self) -> None:
        """
        加载自动分类规则配置
        """
        if not self.config.get("auto_classify", {}).get("enabled", False):
            print("🔄 自动分类功能已禁用")
            return

        print("🔄 正在加载自动分类规则...")
        auto_classify_config = self.config["auto_classify"]

        # 加载直接配置的规则
        rules = auto_classify_config.get("rules", [])
        for rule in rules:
            parsed_rule = self._parse_auto_classify_rule(rule)
            if parsed_rule:
                self.auto_classify_rules.append(parsed_rule)

        if rules:
            print(f"  ✅ 加载了 {len(rules)} 个内置自动分类规则")

        # 从外部源加载规则
        sources = auto_classify_config.get("sources", [])
        for source in sources:
            if not source.get("enabled", True):
                continue

            try:
                if "url" in source:
                    # 从URL加载
                    print(f"  🌐 正在从URL加载自动分类规则: {source['name']}")
                    rules_from_url = self._load_auto_classify_from_url(source)
                    self.auto_classify_rules.extend(rules_from_url)
                elif "file" in source:
                    # 从本地文件加载
                    print(f"  📁 正在从文件加载自动分类规则: {source['name']}")
                    rules_from_file = self._load_auto_classify_from_file(source)
                    self.auto_classify_rules.extend(rules_from_file)
            except Exception as e:
                print(f"  ❌ 加载自动分类源 '{source['name']}' 失败: {e}")

        total_rules = len(self.auto_classify_rules)
        print(f"🔄 自动分类规则加载完成: {total_rules} 个规则")

        # 显示规则统计
        if total_rules > 0:
            stats = defaultdict(int)
            for rule in self.auto_classify_rules:
                stats[rule['action']] += 1

            print(f"  📊 规则分布:")
            for action, count in stats.items():
                print(f"    - {action}: {count} 个")

    def _parse_auto_classify_rule(self, rule_str: str) -> Dict:
        """
        解析自动分类规则

        Args:
            rule_str: 规则字符串，格式如 "action:domain" 或 "replace:old=new"

        Returns:
            解析后的规则字典
        """
        rule_str = rule_str.strip()
        if not rule_str or rule_str.startswith('#'):
            return None

        if ':' not in rule_str:
            return None

        action, content = rule_str.split(':', 1)
        action = action.strip().lower()
        content = content.strip()

        if not content:
            return None

        # 处理替换规则
        if action == 'replace':
            if '=' in content:
                old_domain, new_domain = content.split('=', 1)
                return {
                    'action': 'replace',
                    'old_domain': old_domain.strip(),
                    'new_domain': new_domain.strip()
                }
            else:
                print(f"  ❌ 无效的替换规则格式: {rule_str} (应为 replace:old=new)")
                return None

        # 处理其他动作
        elif action in ['remove', 'low_priority', 'high_priority', 'skip']:
            return {
                'action': action,
                'domain': content
            }
        else:
            print(f"  ❌ 未知的动作类型: {action}")
            return None

    def _load_auto_classify_from_url(self, source: dict) -> List[Dict]:
        """
        从URL加载自动分类规则

        Args:
            source: 规则源配置

        Returns:
            规则列表
        """
        url = source["url"]
        timeout = self.config["request_config"]["timeout"]
        retry_count = self.config["request_config"]["retry_count"]
        retry_delay = self.config["request_config"]["retry_delay"]

        for attempt in range(retry_count):
            try:
                headers = {
                    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
                }
                response = requests.get(url, timeout=timeout, headers=headers)
                response.raise_for_status()

                return self._parse_auto_classify_content(response.text)

            except requests.RequestException as e:
                print(f"    ❌ 获取失败 (尝试 {attempt + 1}/{retry_count}): {e}")
                if attempt < retry_count - 1:
                    time.sleep(retry_delay)

        return []

    def _load_auto_classify_from_file(self, source: dict) -> List[Dict]:
        """
        从本地文件加载自动分类规则

        Args:
            source: 规则源配置

        Returns:
            规则列表
        """
        file_path = source["file"]
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                content = f.read()
            return self._parse_auto_classify_content(content)
        except FileNotFoundError:
            print(f"    ❌ 文件不存在: {file_path}")
        except Exception as e:
            print(f"    ❌ 读取文件失败: {e}")

        return []

    def _parse_auto_classify_content(self, content: str) -> List[Dict]:
        """
        解析自动分类规则内容

        Args:
            content: 文件内容

        Returns:
            规则列表
        """
        rules = []
        for line in content.strip().split('\n'):
            line = line.strip()
            if not line or line.startswith('#'):
                continue

            parsed_rule = self._parse_auto_classify_rule(line)
            if parsed_rule:
                rules.append(parsed_rule)

        return rules

    def load_custom_rules_from_file(self, file_path: str, format_type: str, action: str, csv_config: Dict = None) -> Tuple[Set[str], Dict[str, str], Dict]:
        """
        从文件加载自定义规则，支持 CSV 格式

        Args:
            file_path: 文件路径
            format_type: 格式类型 (domain, regex, ublock, v2ray, replace, csv)
            action: 动作类型 (remove, low_priority, high_priority, replace)
            csv_config: CSV 配置（当 format_type 为 csv 时使用）

        Returns:
            (域名集合, 替换规则字典, 统计信息)
        """
        domains = set()
        replace_rules = {}
        stats = {
            'total_rules': 0,
            'parsed_domains': 0,
            'invalid_domains': 0,
            'ignored_comments': 0,
            'v2ray_with_tags': 0,
            'csv_parsed_rows': 0,
            'csv_invalid_urls': 0,
            'csv_extracted_domains': 0
        }

        try:
            # CSV 格式特殊处理
            if format_type == "csv":
                if not csv_config:
                    print(f"  ❌ CSV 格式需要 csv_config 配置")
                    return domains, replace_rules, stats

                print(f"  📁 正在解析 CSV 文件: {file_path}")
                return self.load_csv_rules_from_file(file_path, csv_config, action)

            # 其他格式的处理逻辑保持不变
            with open(file_path, 'r', encoding='utf-8') as f:
                content = f.read()

            print(f"  📁 正在解析文件: {file_path} (格式: {format_type})")

            for line_num, line in enumerate(content.strip().split('\n'), 1):
                line = line.strip()
                if not line:
                    continue

                stats['total_rules'] += 1

                # 跳过注释
                if line.startswith('#'):
                    stats['ignored_comments'] += 1
                    continue

                try:
                    if format_type == "replace":
                        # 替换规则格式：old_domain=new_domain 或 old_regex=new_domain
                        if '=' in line:
                            old_pattern, new_domain = line.split('=', 1)
                            old_pattern = old_pattern.strip()
                            new_domain = new_domain.strip()

                            if old_pattern and new_domain:
                                replace_rules[old_pattern] = new_domain
                                stats['parsed_domains'] += 1
                            else:
                                stats['invalid_domains'] += 1
                        else:
                            stats['invalid_domains'] += 1

                    elif format_type == "regex":
                        # 正则表达式格式，直接使用
                        if line:
                            domains.add(line)
                            stats['parsed_domains'] += 1

                    elif format_type == "ublock":
                        # uBlock 格式
                        domain, ignore_reason, is_path_rule = self.parse_ublock_rule(line)
                        if domain:
                            domains.add(domain)
                            stats['parsed_domains'] += 1
                        else:
                            stats['invalid_domains'] += 1

                    elif format_type == "v2ray":
                        # v2ray 格式
                        domain, ignore_reason = self.parse_v2ray_rule(line)
                        if domain:
                            domains.add(domain)
                            stats['parsed_domains'] += 1
                            if stats['parsed_domains'] <= 3:  # 显示前3个解析样本
                                print(f"    ✅ v2ray 解析: {line} -> {domain}")
                        else:
                            stats['invalid_domains'] += 1
                            if ignore_reason and stats['invalid_domains'] <= 3:
                                print(f"    ❌ v2ray 忽略: {line} ({ignore_reason})")

                    else:  # domain 格式
                        # 处理行末注释
                        if '#' in line:
                            line = line[:line.find('#')].strip()
                            if not line:
                                stats['ignored_comments'] += 1
                                continue

                        domain = self.clean_domain(line)
                        if domain:
                            domains.add(domain)
                            stats['parsed_domains'] += 1
                        else:
                            stats['invalid_domains'] += 1

                except Exception as e:
                    print(f"    ❌ 解析第 {line_num} 行时出错: {line[:50]}... - {e}")
                    stats['invalid_domains'] += 1

            # 累加 v2ray 标签统计
            stats['v2ray_with_tags'] = self.stats.get('v2ray_with_tags', 0)

            print(f"    ✅ 解析完成: {stats['parsed_domains']} 个有效规则")
            if format_type == "v2ray" and stats['v2ray_with_tags'] > 0:
                print(f"    📝 其中包含标签的规则: {stats['v2ray_with_tags']} 个")
            if stats['invalid_domains'] > 0:
                print(f"    ⚠️  忽略了 {stats['invalid_domains']} 个无效规则")

        except FileNotFoundError:
            print(f"    ❌ 文件不存在: {file_path}")
        except Exception as e:
            print(f"    ❌ 读取文件失败: {e}")

        return domains, replace_rules, stats

    def should_skip_domain_from_source(self, domain: str, source_name: str = None) -> Tuple[bool, str]:
        """
        检查域名是否应该从数据源处理中跳过
        注意：这只影响数据源的默认处理，不影响明确的自动分类规则

        Args:
            domain: 要检查的域名
            source_name: 数据源名称

        Returns:
            (是否跳过, 跳过原因)
        """
        if not self.auto_classify_rules:
            return False, ""

        domain_lower = domain.lower()

        for rule in self.auto_classify_rules:
            if rule['action'] == 'skip':
                rule_domain = rule['domain'].lower()

                # 支持通配符匹配
                if rule_domain.startswith('*.'):
                    # 通配符匹配子域名
                    pattern_domain = rule_domain[2:]  # 移除 *.
                    if domain_lower == pattern_domain or domain_lower.endswith('.' + pattern_domain):
                        return True, f"自动分类跳过规则: {rule['domain']} (仅影响数据源处理)"
                elif domain_lower == rule_domain:
                    # 精确匹配
                    return True, f"自动分类跳过规则: {rule['domain']} (仅影响数据源处理)"

        return False, ""

    def get_auto_classify_action(self, domain: str) -> Tuple[str, str]:
        """
        根据自动分类规则获取域名的动作

        Args:
            domain: 域名

        Returns:
            (动作类型, 匹配原因)
        """
        if not self.auto_classify_rules:
            return None, ""

        domain_lower = domain.lower()

        for rule in self.auto_classify_rules:
            if rule['action'] in ['remove', 'low_priority', 'high_priority']:
                rule_domain = rule['domain'].lower()

                # 支持通配符匹配
                if rule_domain.startswith('*.'):
                    # 通配符匹配子域名
                    pattern_domain = rule_domain[2:]  # 移除 *.
                    if domain_lower == pattern_domain or domain_lower.endswith('.' + pattern_domain):
                        return rule['action'], f"自动分类规则: {rule['domain']}"
                elif domain_lower == rule_domain:
                    # 精确匹配
                    return rule['action'], f"自动分类规则: {rule['domain']}"

        return None, ""

    def get_all_auto_classify_actions_for_domain(self, domain: str) -> List[Tuple[str, str]]:
        """
        获取域名的所有自动分类动作（用于检测冲突和优先级处理）

        Args:
            domain: 域名

        Returns:
            (动作类型, 匹配原因) 的列表
        """
        if not self.auto_classify_rules:
            return []

        domain_lower = domain.lower()
        actions = []

        for rule in self.auto_classify_rules:
            if rule['action'] in ['remove', 'low_priority', 'high_priority', 'skip']:
                rule_domain = rule['domain'].lower()

                # 支持通配符匹配
                if rule_domain.startswith('*.'):
                    # 通配符匹配子域名
                    pattern_domain = rule_domain[2:]  # 移除 *.
                    if domain_lower == pattern_domain or domain_lower.endswith('.' + pattern_domain):
                        actions.append((rule['action'], f"自动分类规则: {rule['domain']}"))
                elif domain_lower == rule_domain:
                    # 精确匹配
                    actions.append((rule['action'], f"自动分类规则: {rule['domain']}"))

        return actions

    def apply_auto_classify_rules_directly(self, categorized_domains: Dict[str, Set[str]]) -> None:
        """
        直接应用自动分类规则中的域名（新增功能）
        不仅重新分类现有域名，还会主动添加规则中定义的域名
        修复版本：skip 规则不会阻止其他明确的自动分类规则

        Args:
            categorized_domains: 分类后的域名字典
        """
        if not self.auto_classify_rules:
            return

        print(f"\n🔄 正在应用自动分类规则中的域名...")

        auto_added_count = 0
        auto_added_samples = []
        skip_overridden_count = 0
        skip_overridden_samples = []

        # 收集所有已存在的域名（用于跳过重复）
        all_existing_domains = set()
        for domain_set in categorized_domains.values():
            all_existing_domains.update(d.lower() for d in domain_set)

        # 按域名分组处理所有规则，以便处理冲突
        domain_rules_map = defaultdict(list)

        for rule in self.auto_classify_rules:
            if rule['action'] in ['remove', 'low_priority', 'high_priority', 'skip']:
                domain = rule['domain']

                # 处理通配符域名
                if domain.startswith('*.'):
                    # 对于通配符规则，我们不直接添加，因为它们是匹配规则而不是具体域名
                    continue

                # 清理域名（使用保持原始结构的清理方法）
                cleaned_domain = self.clean_domain_preserve_structure(domain)
                if not cleaned_domain:
                    continue

                domain_rules_map[cleaned_domain].append(rule)

            elif rule['action'] == 'replace':
                # 处理替换规则
                old_domain = rule['old_domain']
                new_domain = rule['new_domain']

                cleaned_old_domain = self.clean_domain_preserve_structure(old_domain)
                if cleaned_old_domain and new_domain:
                    # 生成正则表达式格式的键
                    old_regex = f"(.*\\.)?{re.escape(cleaned_old_domain)}$"
                    self.config["replace_rules"][old_regex] = new_domain
                    auto_added_count += 1

                    if len(auto_added_samples) < 5:
                        auto_added_samples.append(f"{cleaned_old_domain} -> {new_domain} (替换)")

        # 处理每个域名的规则
        for domain, rules in domain_rules_map.items():
            # 检查是否已存在
            if domain.lower() in all_existing_domains:
                continue

            # 分析规则优先级
            has_skip = any(r['action'] == 'skip' for r in rules)
            non_skip_rules = [r for r in rules if r['action'] != 'skip']

            if non_skip_rules:
                # 有非 skip 的规则，优先处理这些规则
                # 如果有多个非 skip 规则，取最后一个（或者可以根据优先级排序）
                effective_rule = non_skip_rules[-1]  # 取最后一个规则

                action = effective_rule['action']
                if action in categorized_domains:
                    categorized_domains[action].add(domain)
                    all_existing_domains.add(domain.lower())
                    auto_added_count += 1

                    if len(auto_added_samples) < 5:
                        auto_added_samples.append(f"{domain} -> {action}")

                    # 如果同时有 skip 规则，记录覆盖情况
                    if has_skip:
                        skip_overridden_count += 1
                        if len(skip_overridden_samples) < 3:
                            skip_overridden_samples.append(f"{domain} (skip 被 {action} 覆盖)")

            # 如果只有 skip 规则，不做任何处理（但不是错误）

        if auto_added_count > 0:
            print(f"  ✅ 主动添加了 {auto_added_count} 个域名到相应类别")
            self.stats['auto_added'] = auto_added_count

            print(f"  📝 添加的域名样本:")
            for sample in auto_added_samples:
                print(f"    + {sample}")

        if skip_overridden_count > 0:
            print(f"  🔄 skip 规则被覆盖: {skip_overridden_count} 个域名")
            self.stats['skip_overridden'] = skip_overridden_count

            print(f"  📝 覆盖情况样本:")
            for sample in skip_overridden_samples:
                print(f"    ⚡ {sample}")

        if auto_added_count == 0 and skip_overridden_count == 0:
            print(f"  ℹ️  没有需要主动添加的域名")

    def clean_domain_preserve_structure(self, domain: str) -> str:
        """
        清理域名但保持原始结构（用于自动分类规则）

        Args:
            domain: 原始域名字符串

        Returns:
            清理后的域名（保持结构）
        """
        if not domain:
            return None

        # 移除协议
        if domain.startswith(('http://', 'https://')):
            parsed = urlparse(domain)
            domain = parsed.netloc

        # 移除明显的端口号
        if ':' in domain:
            parts = domain.split(':')
            if len(parts) == 2 and parts[1].isdigit():
                domain = parts[0]

        # 移除路径
        if '/' in domain:
            domain = domain.split('/')[0]

        # **保持 www. 前缀**
        # 不做任何前缀移除

        # 只移除空白字符
        domain = domain.strip()

        # 检查是否是IP地址
        if self.config["parsing"]["ignore_ip"] and self.is_ip_address(domain):
            return None

        # 检查是否是localhost
        if self.config["parsing"]["ignore_localhost"] and domain in ['localhost', '127.0.0.1', '0.0.0.0']:
            return None

        # 验证域名格式
        if self.is_valid_domain(domain):
            return domain.lower()

        return None

    def _has_specific_path(self, url_string: str) -> bool:
        """
        简化版：检查URL是否包含具体的路径（非域名级别）
        只要有路径部分（不为空且不是单独的'*'），就认为是特定路径

        Args:
            url_string: URL字符串

        Returns:
            是否包含具体路径
        """
        # 移除协议部分
        if url_string.startswith('*://'):
            url_part = url_string[4:]
        elif url_string.startswith('||'):
            url_part = url_string[2:].rstrip('^')
        else:
            url_part = url_string

        # 检查是否有路径部分
        if '/' in url_part:
            domain_and_path = url_part.split('/', 1)
            if len(domain_and_path) > 1:
                path_part = domain_and_path[1]

                # 简化逻辑：只要路径部分不为空且不是单独的'*'，就认为是特定路径
                if path_part and path_part != '*':
                    return True

        return False

    def extract_domain_from_rule(self, rule: str) -> str:
        """
        🔧 修复：从规则中提取域名，支持更多格式

        Args:
            rule: 规则字符串

        Returns:
            域名或 None
        """
        rule = rule.strip()

        # 🔄 修复：对于特定路径规则，仍然尝试提取域名
        # 首先检查是否包含具体路径
        has_specific_path = self._has_specific_path(rule)

        # 🔧 新增：支持更多的uBlock规则格式
        patterns = [
            # 🔧 新增：*.domain.com/* 格式 (通配符域名)
            r'^\*\.([a-zA-Z0-9.-]+)(?:/.*)?(?:\*)?$',
            # 🔧 新增：*.domain.com/path/* 格式
            r'^\*\.([a-zA-Z0-9.-]+)/.*(?:\*)?$',
            # 原有：*://*.domain.com/* 或 *://*.domain.com (通配符子域名)
            r'^\*://\*\.([a-zA-Z0-9.-]+)(?:/.*)?$',
            # 原有：*://domain.com/* 或 *://domain.com (无通配符)
            r'^\*://([a-zA-Z0-9.-]+)(?:/.*)?$',
            # 🔧 新增：https://domain.com/* 格式
            r'^https?://([a-zA-Z0-9.-]+)(?:/.*)?$',
            # 原有：||domain.com^ 或 ||domain.com/path
            r'^\|\|([a-zA-Z0-9.-]+)(?:/.*)?(?:\^)?$',
            # 🔧 新增：domain.com/* 格式
            r'^([a-zA-Z0-9.-]+)/.*(?:\*)?$',
            # 原有：普通域名格式
            r'^([a-zA-Z0-9.-]+)(?:/.*)?$',
            # 🔧 修复：domain.com* 格式（不带斜杠的通配符）
            r'^([a-zA-Z0-9.-]+)\*$',
        ]

        for pattern in patterns:
            match = re.match(pattern, rule)
            if match:
                candidate = match.group(1)
                # 验证提取的候选域名
                if candidate and '.' in candidate and not candidate.startswith('/'):
                    # 🔧 进一步验证域名格式
                    if self.is_valid_domain(candidate):
                        return candidate
                    else:
                        # 如果域名验证失败，显示调试信息
                        debug_count = getattr(self, '_debug_extract_count', 0)
                        if debug_count < 3:
                            print(f"  🔧 域名格式验证失败: {rule} -> {candidate}")
                            self._debug_extract_count = debug_count + 1

        # 🔄 对于 *://*/filename 这种格式，我们无法提取有效域名，返回 None
        if rule.startswith('*://*/'):
            return None

        # 🔧 增强的通用域名提取（最后的后备方案）
        # 尝试提取所有可能的域名格式
        domain_candidates = re.findall(r'([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})', rule)
        for candidate in domain_candidates:
            if self.is_valid_domain(candidate):
                return candidate

        return None

    def parse_ublock_rule(self, rule: str) -> Tuple[str, str, bool]:
        """
        🐛 修复：解析 uBlock Origin 语法规则，提取域名，正确识别特定路径规则

        Args:
            rule: uBlock 规则字符串

        Returns:
            (域名或 None, 忽略原因, 是否是特定路径规则)
        """
        original_rule = rule  # 保存原始规则用于调试
        rule = rule.strip()
        if not rule or rule.startswith('!') or rule.startswith('#'):
            return None, "注释或空行", False

        # 处理行末注释 - 移除 # 后面的所有内容
        if '#' in rule:
            # 找到第一个 # 的位置，移除它及后面的内容
            comment_pos = rule.find('#')
            rule = rule[:comment_pos].strip()

            # 如果移除注释后规则为空，则忽略
            if not rule:
                return None, "仅包含注释", False

        # 🐛 修复：检查是否是特定路径规则
        has_specific_path = self._has_specific_path(rule)

        # 提取域名
        domain = self.extract_domain_from_rule(rule)

        if domain:
            cleaned_domain = self.clean_domain(domain)
            if cleaned_domain:
                # 🔧 显示解析成功的样本（包括通配符规则）
                debug_count = getattr(self, '_debug_success_count', 0)
                if debug_count < 5:
                    if has_specific_path:
                        print(f"  ✅ 特定路径规则解析: {original_rule} -> 域名: {cleaned_domain}")
                    elif original_rule.startswith('*.'):
                        print(f"  🔧 通配符规则解析: {original_rule} -> 域名: {cleaned_domain}")
                        self.stats['wildcard_rules_processed'] += 1
                    else:
                        print(f"  ✅ 普通规则解析: {original_rule} -> 域名: {cleaned_domain}")
                    self._debug_success_count = debug_count + 1

                return cleaned_domain, None, has_specific_path
            else:
                return None, "域名清理后无效", has_specific_path
        else:
            # 🔄 对于无法提取域名的特定路径规则，也要标记为特定路径
            if has_specific_path:
                return None, "特定路径规则但无法提取域名", True
            else:
                # 显示一些无法解析的规则样本
                debug_count = getattr(self, '_debug_fail_count', 0)
                if debug_count < 3:
                    print(f"  ❌ 无法解析规则: {original_rule}")
                    self._debug_fail_count = debug_count + 1
                return None, "无法解析规则格式", False

    def determine_path_rule_action(self, source_action: str, specific_path_action: str) -> str:
        """
        🔧 新增：确定特定路径规则的最终动作

        Args:
            source_action: 数据源的原始动作
            specific_path_action: 特定路径规则的配置动作

        Returns:
            最终的动作
        """
        if specific_path_action == "keep_action":
            # 保持源的原始动作
            return source_action
        elif specific_path_action == "low_priority":
            # 强制设为低优先级
            return "low_priority"
        elif specific_path_action == "smart":
            # 智能处理：remove->low_priority，其他保持
            if source_action == "remove":
                return "low_priority"
            else:
                return source_action
        elif specific_path_action == "ignore":
            # 忽略，返回 None
            return None
        else:
            # 默认情况，保持原始动作
            return source_action

    def fetch_domain_list(self, url: str, format_type: str = "domain", source_name: str = None, csv_config: Dict = None) -> Tuple[Set[str], Set[str], Dict]:
        """
        🔧 修复：从URL获取域名列表，正确处理特定路径规则的动作分配

        Args:
            url: 域名列表URL
            format_type: 格式类型，"domain", "ublock", "v2ray", 或 "csv"
            source_name: 数据源名称（用于自动分类）
            csv_config: CSV 配置（当 format_type 为 csv 时使用）

        Returns:
            (普通域名集合, 特定路径域名集合(已分类), 统计信息)
        """
        domains = set()
        path_domains_classified = {}  # 🔧 改为字典存储分类后的特定路径域名
        stats = {
            'total_rules': 0,
            'parsed_domains': 0,
            'ignored_with_path': 0,
            'path_to_low_priority': 0,
            'path_kept_action': 0,      # 🔧 新增统计
            'invalid_domains': 0,
            'duplicate_domains': 0,
            'ignored_comments': 0,
            'auto_classified': 0,  # 自动分类处理的数量
            'skipped_domains': 0,   # 跳过的域名数量
            'v2ray_with_tags': 0,   # v2ray 带标签的规则数量
            'csv_parsed_rows': 0,
            'csv_invalid_urls': 0,
            'csv_extracted_domains': 0,
            'wildcard_rules_processed': 0,  # 🔧 处理的通配符规则数量
        }

        retry_count = self.config["request_config"]["retry_count"]
        timeout = self.config["request_config"]["timeout"]
        retry_delay = self.config["request_config"]["retry_delay"]

        for attempt in range(retry_count):
            try:
                print(f"正在获取 {url} (尝试 {attempt + 1}/{retry_count}) - 格式: {format_type}")

                headers = {
                    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
                }

                response = requests.get(url, timeout=timeout, headers=headers)
                response.raise_for_status()

                # CSV 格式特殊处理
                if format_type == "csv":
                    if not csv_config:
                        print(f"  ❌ CSV 格式需要 csv_config 配置")
                        return domains, path_domains_classified, stats

                    return self._parse_csv_from_response(response.text, csv_config, source_name, stats)

                # 记录一些被忽略的规则用于调试
                ignored_samples = []
                accepted_samples = []
                comment_samples = []
                path_samples = []  # 路径规则样本
                skip_samples = []  # 跳过的域名样本
                path_to_low_priority_samples = []  # 特定路径转低优先级样本
                path_kept_action_samples = []      # 🔧 特定路径保持动作样本

                # 重置 v2ray 标签计数器
                initial_v2ray_tags = self.stats.get('v2ray_with_tags', 0)

                # 重置调试计数器
                self._debug_path_count = 0
                self._debug_success_count = 0
                self._debug_fail_count = 0
                self._debug_extract_count = 0

                # 🔧 获取源动作和特定路径处理配置
                source_action = getattr(self, '_current_source_action', 'remove')  # 临时存储当前源动作
                specific_path_action = self.config["parsing"].get("specific_path_action", "keep_action")

                print(f"  🔧 特定路径处理模式: {specific_path_action}")
                print(f"  🔧 源动作: {source_action}")

                # 解析域名
                for line_num, line in enumerate(response.text.strip().split('\n'), 1):
                    line = line.strip()
                    if not line:
                        continue

                    stats['total_rules'] += 1

                    try:
                        if format_type == "ublock":
                            # 🔧 修复：使用新的 parse_ublock_rule 方法
                            domain, ignore_reason, is_path_rule = self.parse_ublock_rule(line)

                            if domain:
                                # 检查是否应该从数据源跳过此域名
                                should_skip, skip_reason = self.should_skip_domain_from_source(domain, source_name)
                                if should_skip:
                                    stats['skipped_domains'] += 1
                                    if len(skip_samples) < 3:
                                        skip_samples.append(f"{line} -> {domain} ({skip_reason})")
                                else:
                                    # 🔧 修复：根据是否是特定路径规则和配置决定如何处理
                                    if is_path_rule:
                                        # 确定特定路径规则的最终动作
                                        final_action = self.determine_path_rule_action(source_action, specific_path_action)

                                        if final_action is None:
                                            # 忽略这个域名
                                            stats['ignored_with_path'] += 1
                                            if len(path_samples) < 3:
                                                path_samples.append(f"{line} -> {domain} (忽略)")
                                        elif final_action == "low_priority":
                                            # 初始化分类字典
                                            if final_action not in path_domains_classified:
                                                path_domains_classified[final_action] = set()
                                            path_domains_classified[final_action].add(domain)
                                            stats['path_to_low_priority'] += 1
                                            if len(path_to_low_priority_samples) < 5:
                                                path_to_low_priority_samples.append(f"{line} -> {domain} (路径规则->低优先级)")
                                        else:
                                            # 保持原动作或其他动作
                                            if final_action not in path_domains_classified:
                                                path_domains_classified[final_action] = set()
                                            path_domains_classified[final_action].add(domain)
                                            stats['path_kept_action'] += 1
                                            if len(path_kept_action_samples) < 5:
                                                path_kept_action_samples.append(f"{line} -> {domain} (路径规则->{final_action})")
                                    else:
                                        # 普通域名规则
                                        if domain in domains:
                                            stats['duplicate_domains'] += 1
                                        else:
                                            domains.add(domain)
                                            stats['parsed_domains'] += 1
                                            if len(accepted_samples) < 3:
                                                accepted_samples.append(f"{line} -> {domain}")
                            else:
                                # 统计忽略原因
                                if "特定路径" in (ignore_reason or ""):
                                    stats['ignored_with_path'] += 1
                                    if len(path_samples) < 3:
                                        path_samples.append(line)
                                elif ignore_reason in ["注释或空行", "仅包含注释"]:
                                    stats['ignored_comments'] += 1
                                    if len(comment_samples) < 3:
                                        comment_samples.append(line)
                                else:
                                    stats['invalid_domains'] += 1
                                    if len(ignored_samples) < 3:
                                        ignored_samples.append(line)

                        elif format_type == "v2ray":
                            # 使用 v2ray 语法解析
                            domain, ignore_reason = self.parse_v2ray_rule(line)
                            if domain and len(accepted_samples) < 3:
                                accepted_samples.append(f"v2ray: {line} -> {domain}")
                            elif ignore_reason and len(ignored_samples) < 3:
                                ignored_samples.append(f"v2ray: {line} ({ignore_reason})")

                            if domain:
                                # 检查是否应该从数据源跳过此域名
                                should_skip, skip_reason = self.should_skip_domain_from_source(domain, source_name)
                                if should_skip:
                                    stats['skipped_domains'] += 1
                                    if len(skip_samples) < 3:
                                        skip_samples.append(f"{line} -> {domain} ({skip_reason})")
                                else:
                                    if domain in domains:
                                        stats['duplicate_domains'] += 1
                                    else:
                                        domains.add(domain)
                                        stats['parsed_domains'] += 1
                            else:
                                # 统计忽略原因
                                if ignore_reason in ["注释或空行", "仅包含注释"]:
                                    stats['ignored_comments'] += 1
                                    if len(comment_samples) < 3:
                                        comment_samples.append(line)
                                elif ignore_reason == "无效域名":
                                    stats['invalid_domains'] += 1
                                    if len(ignored_samples) < 3:
                                        ignored_samples.append(line)

                        else:
                            # 普通域名格式 - 也需要处理行末注释
                            cleaned_line = line
                            if '#' in line:
                                cleaned_line = line[:line.find('#')].strip()
                                if not cleaned_line:
                                    stats['ignored_comments'] += 1
                                    if len(comment_samples) < 3:
                                        comment_samples.append(line)
                                    continue

                            domain = self.clean_domain(self.extract_domain_from_rule(cleaned_line))
                            if domain:
                                # 检查是否应该从数据源跳过此域名
                                should_skip, skip_reason = self.should_skip_domain_from_source(domain, source_name)
                                if should_skip:
                                    stats['skipped_domains'] += 1
                                    if len(skip_samples) < 3:
                                        skip_samples.append(f"{line} -> {domain} ({skip_reason})")
                                else:
                                    if domain in domains:
                                        stats['duplicate_domains'] += 1
                                    else:
                                        domains.add(domain)
                                        stats['parsed_domains'] += 1
                                        if len(accepted_samples) < 3:
                                            accepted_samples.append(f"{line} -> {domain}")
                            else:
                                stats['invalid_domains'] += 1
                                if len(ignored_samples) < 3:
                                    ignored_samples.append(line)

                    except Exception as e:
                        print(f"解析第 {line_num} 行时出错: {line[:50]}... - {e}")
                        stats['invalid_domains'] += 1
                        continue

                # 计算本次请求中的 v2ray 标签数量和通配符规则数量
                current_v2ray_tags = self.stats.get('v2ray_with_tags', 0) - initial_v2ray_tags
                stats['v2ray_with_tags'] = current_v2ray_tags
                stats['wildcard_rules_processed'] = self.stats.get('wildcard_rules_processed', 0)

                # 计算特定路径域名总数
                total_path_domains = sum(len(domain_set) for domain_set in path_domains_classified.values())

                print(f"成功获取 {len(domains)} 个普通域名，{total_path_domains} 个特定路径域名")
                print(f"  - 总规则: {stats['total_rules']}")
                print(f"  - 成功解析: {stats['parsed_domains']}")
                print(f"  - 忽略(特定路径): {stats['ignored_with_path']}")
                print(f"  - 🔧 特定路径->低优先级: {stats['path_to_low_priority']}")
                print(f"  - 🔧 特定路径保持原动作: {stats['path_kept_action']}")
                print(f"  - 忽略(注释): {stats['ignored_comments']}")
                print(f"  - 忽略(无效域名): {stats['invalid_domains']}")
                print(f"  - 重复域名: {stats['duplicate_domains']}")
                print(f"  - 跳过域名: {stats['skipped_domains']}")
                if format_type == "v2ray" and stats['v2ray_with_tags'] > 0:
                    print(f"  - v2ray 带标签规则: {stats['v2ray_with_tags']}")
                if stats['wildcard_rules_processed'] > 0:
                    print(f"  - 🔧 通配符规则处理: {stats['wildcard_rules_processed']}")

                # 显示样本
                if accepted_samples:
                    print(f"  - 接受的规则样本:")
                    for sample in accepted_samples:
                        print(f"    ✓ {sample}")

                if path_to_low_priority_samples:
                    print(f"  - 🔧 特定路径->低优先级样本:")
                    for sample in path_to_low_priority_samples:
                        print(f"    📍 {sample}")

                if path_kept_action_samples:
                    print(f"  - 🔧 特定路径保持动作样本:")
                    for sample in path_kept_action_samples:
                        print(f"    🎯 {sample}")

                if skip_samples:
                    print(f"  - 跳过的域名样本:")
                    for sample in skip_samples:
                        print(f"    ⏭️ {sample}")

                if path_samples:
                    print(f"  - 忽略的路径规则样本:")
                    for sample in path_samples:
                        print(f"    🛤️  {sample}")

                if comment_samples:
                    print(f"  - 忽略的注释规则样本:")
                    for sample in comment_samples:
                        print(f"    # {sample}")

                if ignored_samples:
                    print(f"  - 其他忽略的规则样本:")
                    for sample in ignored_samples:
                        print(f"    ✗ {sample}")

                return domains, path_domains_classified, stats

            except requests.RequestException as e:
                print(f"获取失败 (尝试 {attempt + 1}/{retry_count}): {e}")
                if attempt < retry_count - 1:
                    time.sleep(retry_delay)
                else:
                    print(f"放弃获取 {url}")

        return domains, {}, stats

    def _parse_csv_from_response(self, csv_content: str, csv_config: Dict, source_name: str, stats: Dict) -> Tuple[Set[str], Dict[str, Set[str]], Dict]:
        """
        🔧 修复：从 HTTP 响应内容解析 CSV 格式的域名

        Args:
            csv_content: CSV 内容字符串
            csv_config: CSV 配置
            source_name: 数据源名称
            stats: 统计信息字典

        Returns:
            (域名集合, 特定路径域名分类字典, 统计信息)
        """
        domains = set()
        path_domains = {}  # CSV 通常不包含特定路径规则，但为了接口一致性

        # CSV 配置默认值
        has_header = csv_config.get("has_header", True)
        delimiter = csv_config.get("delimiter", ",")
        column = csv_config.get("column")
        column_index = csv_config.get("column_index")

        try:
            csv_reader = csv.reader(csv_content.strip().split('\n'), delimiter=delimiter)

            headers = None
            actual_column_index = None
            skip_samples = []  # 跳过的域名样本
            accepted_samples = []  # 接受的域名样本

            for row_num, row in enumerate(csv_reader, 1):
                if not row or all(cell.strip() == '' for cell in row):
                    continue  # 跳过空行

                stats['total_rules'] += 1

                # 处理头部行
                if has_header and row_num == 1:
                    headers = [cell.strip() for cell in row]

                    # 如果指定了列名，找到对应的索引
                    if column:
                        try:
                            actual_column_index = headers.index(column)
                            print(f"  📍 CSV 找到目标列 '{column}' 位于索引 {actual_column_index}")
                        except ValueError:
                            print(f"  ❌ CSV 未找到指定的列名 '{column}'")
                            print(f"  📋 CSV 可用的列名: {', '.join(headers)}")
                            return domains, path_domains, stats
                    elif column_index is not None:
                        actual_column_index = column_index
                        if actual_column_index < len(headers):
                            print(f"  📍 CSV 使用列索引 {actual_column_index}: '{headers[actual_column_index]}'")
                        else:
                            print(f"  ❌ CSV 列索引 {actual_column_index} 超出范围")
                            return domains, path_domains, stats

                    continue  # 跳过头部行

                # 如果没有设置实际列索引，使用配置的列索引
                if actual_column_index is None and column_index is not None:
                    actual_column_index = column_index

                stats['csv_parsed_rows'] += 1

                try:
                    # 解析 CSV 行
                    if actual_column_index is not None and actual_column_index < len(row):
                        url_value = row[actual_column_index].strip()
                        if url_value:
                            domain = self.extract_hostname_from_url(url_value)
                            if domain:
                                # 检查是否应该从数据源跳过此域名
                                should_skip, skip_reason = self.should_skip_domain_from_source(domain, source_name)
                                if should_skip:
                                    stats['skipped_domains'] += 1
                                    if len(skip_samples) < 3:
                                        skip_samples.append(f"{url_value} -> {domain} ({skip_reason})")
                                else:
                                    if domain not in domains:
                                        domains.add(domain)
                                        stats['parsed_domains'] += 1
                                        stats['csv_extracted_domains'] += 1

                                        # 显示一些解析样本
                                        if len(accepted_samples) < 5:
                                            accepted_samples.append(f"{url_value} -> {domain}")
                                    else:
                                        stats['duplicate_domains'] += 1
                            else:
                                stats['csv_invalid_urls'] += 1
                        else:
                            stats['invalid_domains'] += 1
                    else:
                        stats['invalid_domains'] += 1

                except Exception as e:
                    print(f"    ❌ CSV 解析第 {row_num} 行时出错: {e}")
                    stats['invalid_domains'] += 1

            print(f"  ✅ CSV 解析完成: {stats['csv_extracted_domains']} 个有效域名")

            # 显示样本
            if accepted_samples:
                print(f"  - CSV 接受的域名样本:")
                for sample in accepted_samples:
                    print(f"    ✅ {sample}")

            if skip_samples:
                print(f"  - CSV 跳过的域名样本:")
                for sample in skip_samples:
                    print(f"    ⏭️ {sample}")

            if stats['csv_invalid_urls'] > 0:
                print(f"  ⚠️  CSV 忽略了 {stats['csv_invalid_urls']} 个无效 URL")

        except Exception as e:
            print(f"    ❌ 解析 CSV 内容失败: {e}")

        return domains, path_domains, stats

    def clean_domain(self, domain: str) -> str:
        """
        清理域名字符串
        根据配置决定是否保持原始结构

        Args:
            domain: 原始域名字符串

        Returns:
            清理后的域名
        """
        if not domain:
            return None

        # 如果配置为保持原始结构，使用专门的方法
        if self.config["parsing"].get("preserve_original_structure", True):
            return self.clean_domain_preserve_structure(domain)

        # 原来的清理逻辑（可能移除 www. 前缀）
        return self._clean_domain_legacy(domain)

    def _clean_domain_legacy(self, domain: str) -> str:
        """
        传统的域名清理方法（可能移除 www. 前缀）

        Args:
            domain: 原始域名字符串

        Returns:
            清理后的域名
        """
        if not domain:
            return None

        # 移除协议
        if domain.startswith(('http://', 'https://')):
            domain = urlparse(domain).netloc

        # 移除端口
        if ':' in domain:
            domain = domain.split(':')[0]

        # 检查是否包含路径（这里不应该有，但以防万一）
        if '/' in domain:
            domain = domain.split('/')[0]

        # 移除 www. 前缀（传统行为）
        if not self.config["parsing"].get("preserve_www_prefix", True):
            if domain.startswith('www.'):
                domain = domain[4:]

        # 移除空格和特殊字符
        domain = re.sub(r'[^\w.-]', '', domain)

        # 检查是否是IP地址
        if self.config["parsing"]["ignore_ip"] and self.is_ip_address(domain):
            return None

        # 检查是否是localhost
        if self.config["parsing"]["ignore_localhost"] and domain in ['localhost', '127.0.0.1', '0.0.0.0']:
            return None

        # 验证域名格式
        if self.is_valid_domain(domain):
            return domain.lower()

        return None

    def is_ip_address(self, domain: str) -> bool:
        """
        检查是否是IP地址

        Args:
            domain: 域名字符串

        Returns:
            是否是IP地址
        """
        ip_pattern = re.compile(r'^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$')
        return bool(ip_pattern.match(domain))

    def is_valid_domain(self, domain: str) -> bool:
        """
        🔧 改进：验证域名格式，更宽松的验证逻辑

        Args:
            domain: 域名字符串

        Returns:
            是否为有效域名
        """
        if not domain or len(domain) > 255:
            return False

        # 🔧 改进的域名格式验证，更宽松
        # 允许更多字符，包括一些特殊情况

        # 基本检查：至少包含一个点
        if '.' not in domain:
            return False

        # 分割域名各部分
        parts = domain.split('.')

        # 检查是否有空的部分
        if any(not part for part in parts):
            return False

        # 检查每个部分的格式
        for part in parts:
            # 🔧 允许更宽松的字符集，包括连字符
            if not re.match(r'^[a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?$', part):
                # 🔧 特殊情况：单个字符的部分也允许
                if len(part) == 1 and re.match(r'^[a-zA-Z0-9]$', part):
                    continue
                return False

            # 检查长度限制
            if len(part) > 63:
                return False

        # 检查最后一个部分（TLD）是否至少有2个字符
        if len(parts[-1]) < 2:
            return False

        return True

    def domain_to_regex(self, domain: str) -> str:
        """
        将域名转换为正则表达式

        Args:
            domain: 域名

        Returns:
            正则表达式字符串
        """
        # 转义特殊字符
        escaped_domain = re.escape(domain)
        # 添加子域名匹配
        return f'(.*\.)?{escaped_domain}$'

    def smart_sort_domains(self, domains: Set[str]) -> List[str]:
        """
        智能排序域名，便于后续合并
        先按TLD排序，再按域名主体排序

        Args:
            domains: 域名集合

        Returns:
            排序后的域名列表
        """
        def domain_sort_key(domain: str) -> Tuple[str, str]:
            """
            生成域名排序键：(TLD, 反向域名主体)
            这样可以将同TLD的域名聚集在一起，便于合并
            """
            parts = domain.split('.')
            if len(parts) >= 2:
                # TLD 作为主要排序键
                tld = parts[-1]
                # 域名主体作为次要排序键，反向排序便于找到公共后缀
                base = '.'.join(parts[:-1])
                return (tld, base)
            else:
                return (domain, '')

        if self.config["optimization"].get("sort_before_merge", True):
            sorted_domains = sorted(list(domains), key=domain_sort_key)
            print(f"  🔄 域名已按TLD智能排序，便于合并优化")
            return sorted_domains
        else:
            return list(domains)

    def group_domains_by_tld(self, domains: Union[Set[str], List[str]]) -> Dict[str, List[str]]:
        """
        按顶级域名分组域名，并保持排序

        Args:
            domains: 域名集合或列表

        Returns:
            按TLD分组的域名字典，值为排序后的列表
        """
        tld_groups = defaultdict(list)

        # 如果输入是集合，先转换为智能排序的列表
        if isinstance(domains, set):
            domains = self.smart_sort_domains(domains)

        for domain in domains:
            parts = domain.split('.')
            if len(parts) >= 2:
                # 获取顶级域名（如 .com, .org）
                tld = parts[-1]
                tld_groups[tld].append(domain)
            else:
                # 处理无效域名
                tld_groups['other'].append(domain)

        return dict(tld_groups)

    def get_domain_base_and_tld(self, domain: str) -> Tuple[str, str]:
        """
        提取域名的主体部分和TLD

        Args:
            domain: 完整域名

        Returns:
            (域名主体, TLD)
        """
        parts = domain.split('.')
        if len(parts) >= 2:
            tld = parts[-1]
            base = '.'.join(parts[:-1])
            return base, tld
        return domain, ''

    def find_common_prefix(self, strings: List[str]) -> str:
        """
        找到字符串列表的公共前缀

        Args:
            strings: 字符串列表

        Returns:
            公共前缀
        """
        if not strings:
            return ""

        strings = [s for s in strings if s]  # 过滤空字符串
        if not strings:
            return ""

        min_len = min(len(s) for s in strings)
        prefix = ""

        for i in range(min_len):
            char = strings[0][i]
            if all(s[i] == char for s in strings):
                prefix += char
            else:
                break

        return prefix

    def find_common_suffix(self, strings: List[str]) -> str:
        """
        找到字符串列表的公共后缀

        Args:
            strings: 字符串列表

        Returns:
            公共后缀
        """
        if not strings:
            return ""

        strings = [s for s in strings if s]  # 过滤空字符串
        if not strings:
            return ""

        # 反转字符串，找前缀，再反转回来
        reversed_strings = [s[::-1] for s in strings]
        reversed_suffix = self.find_common_prefix(reversed_strings)
        return reversed_suffix[::-1]

    def create_advanced_tld_regex(self, tld_domains: List[str], tld: str) -> str:
        """
        为同一TLD的域名创建高级优化正则表达式
        修复版本：确保TLD不会丢失

        Args:
            tld_domains: 同一TLD的域名列表（已排序）
            tld: 顶级域名

        Returns:
            优化后的正则表达式
        """
        if len(tld_domains) == 1:
            return re.escape(tld_domains[0])

        # 提取域名主体部分
        domain_bases = []
        for domain in tld_domains:
            base, domain_tld = self.get_domain_base_and_tld(domain)
            if domain_tld == tld:
                domain_bases.append(base)
            else:
                # TLD不匹配的情况，使用完整域名
                domain_bases.append(domain)

        if not domain_bases:
            return '|'.join(re.escape(d) for d in tld_domains)

        # 尝试找到公共模式
        optimized_pattern = self.optimize_domain_bases(domain_bases)

        # 检查域名基础部分的结构
        simple_domains = [base for base in domain_bases if '.' not in base]  # 二级域名
        complex_domains = [base for base in domain_bases if '.' in base]     # 多级域名

        if len(simple_domains) == len(domain_bases):
            # 所有都是二级域名，可以进行TLD优化
            return f"({optimized_pattern})\\.{re.escape(tld)}"
        elif len(complex_domains) == len(domain_bases):
            # 所有都是多级域名，需要检查是否有公共的二级+TLD后缀
            return self._optimize_complex_domains_with_tld(domain_bases, tld)
        else:
            # 混合情况：二级域名+多级域名
            return self._optimize_mixed_domains_with_tld(simple_domains, complex_domains, tld)

    def _optimize_complex_domains_with_tld(self, domain_bases: List[str], tld: str) -> str:
        """
        优化多级域名，确保保留TLD

        Args:
            domain_bases: 域名基础部分列表（都是多级域名）
            tld: 顶级域名

        Returns:
            优化后的正则表达式
        """
        # 检查是否有公共的二级域名+TLD模式
        # 例如：a.pixnet.net, b.pixnet.net -> (a|b).pixnet.net

        # 找到所有域名的公共后缀（不包括第一部分）
        if len(domain_bases) <= 1:
            if domain_bases:
                return f"{re.escape(domain_bases[0])}\\.{re.escape(tld)}"
            return f".*\\.{re.escape(tld)}"

        # 分析结构：检查是否所有域名都有相同的后缀结构
        common_suffix_parts = None
        prefixes = []

        for base in domain_bases:
            parts = base.split('.')
            if common_suffix_parts is None:
                # 第一个域名，设置公共后缀候选
                if len(parts) >= 2:
                    common_suffix_parts = parts[1:]  # 除了第一部分的其余部分
                    prefixes.append(parts[0])
                else:
                    # 处理异常情况
                    common_suffix_parts = []
                    prefixes.append(base)
            else:
                # 检查是否与公共后缀匹配
                if len(parts) >= len(common_suffix_parts) + 1:
                    current_suffix = parts[-(len(common_suffix_parts)):]
                    if current_suffix == common_suffix_parts:
                        prefixes.append(parts[0])
                    else:
                        # 后缀不匹配，无法优化，直接返回完整域名列表
                        escaped_bases = [re.escape(base) for base in domain_bases]
                        return f"({'|'.join(escaped_bases)})\\.{re.escape(tld)}"
                else:
                    # 长度不够，无法优化
                    escaped_bases = [re.escape(base) for base in domain_bases]
                    return f"({'|'.join(escaped_bases)})\\.{re.escape(tld)}"

        # 如果找到了公共后缀，进行优化
        if common_suffix_parts and len(set(prefixes)) > 1:
            # 优化前缀部分
            optimized_prefixes = self.optimize_domain_bases(prefixes)
            escaped_suffix = '\\.'.join(re.escape(part) for part in common_suffix_parts)
            return f"({optimized_prefixes})\\.{escaped_suffix}\\.{re.escape(tld)}"
        else:
            # 无法找到公共模式，使用基础优化
            optimized_pattern = self.optimize_domain_bases(domain_bases)
            return f"({optimized_pattern})\\.{re.escape(tld)}"

    def _optimize_mixed_domains_with_tld(self, simple_domains: List[str], complex_domains: List[str], tld: str) -> str:
        """
        优化混合域名（二级+多级），确保保留TLD

        Args:
            simple_domains: 二级域名列表
            complex_domains: 多级域名列表
            tld: 顶级域名

        Returns:
            优化后的正则表达式
        """
        patterns = []

        # 处理二级域名
        if simple_domains:
            if len(simple_domains) == 1:
                patterns.append(f"{re.escape(simple_domains[0])}\\.{re.escape(tld)}")
            else:
                optimized_simple = self.optimize_domain_bases(simple_domains)
                patterns.append(f"({optimized_simple})\\.{re.escape(tld)}")

        # 处理多级域名
        if complex_domains:
            complex_pattern = self._optimize_complex_domains_with_tld(complex_domains, tld)
            patterns.append(complex_pattern)

        # 合并所有模式
        if len(patterns) == 1:
            return patterns[0]
        else:
            return f"({'|'.join(patterns)})"

    def optimize_domain_bases(self, domain_bases: List[str]) -> str:
        """
        优化域名基础部分列表

        Args:
            domain_bases: 域名基础部分列表

        Returns:
            优化后的正则表达式模式
        """
        if len(domain_bases) <= 1:
            return '|'.join(re.escape(base) for base in domain_bases)

        optimization_config = self.config["optimization"]

        # 尝试前缀优化
        if optimization_config.get("enable_prefix_optimization", True):
            common_prefix = self.find_common_prefix(domain_bases)
            min_prefix_len = optimization_config.get("min_common_prefix_length", 3)

            if len(common_prefix) >= min_prefix_len:
                # 移除公共前缀
                suffixes = [base[len(common_prefix):] for base in domain_bases]
                suffixes = [s for s in suffixes if s]  # 过滤空后缀
                if suffixes and len(set(suffixes)) > 1:  # 确保有不同的后缀
                    suffix_pattern = self.optimize_domain_bases(suffixes)
                    return f"{re.escape(common_prefix)}({suffix_pattern})"

        # 尝试后缀优化
        if optimization_config.get("enable_suffix_optimization", True):
            common_suffix = self.find_common_suffix(domain_bases)
            min_suffix_len = optimization_config.get("min_common_suffix_length", 3)

            if len(common_suffix) >= min_suffix_len:
                # 移除公共后缀
                prefixes = [base[:-len(common_suffix)] for base in domain_bases]
                prefixes = [p for p in prefixes if p]  # 过滤空前缀
                if prefixes and len(set(prefixes)) > 1:  # 确保有不同的前缀
                    prefix_pattern = self.optimize_domain_bases(prefixes)
                    return f"({prefix_pattern}){re.escape(common_suffix)}"

        # 没有找到优化模式，直接连接
        return '|'.join(re.escape(base) for base in domain_bases)

    def create_single_regex_rule(self, domains: Union[Set[str], List[str]]) -> str:
        """
        创建包含所有域名的单行正则表达式（高级TLD优化）

        Args:
            domains: 域名集合或列表

        Returns:
            单行正则表达式
        """
        if not domains:
            return ""

        # 转换为排序列表
        if isinstance(domains, set):
            domains = self.smart_sort_domains(domains)

        if len(domains) == 1:
            return f"(.*\\.)?{re.escape(domains[0])}$"

        print(f"🚀 正在生成高级TLD优化单行正则表达式，包含 {len(domains)} 个域名")

        # 启用高级TLD合并
        if self.config["optimization"].get("enable_advanced_tld_merge", True):
            # 按TLD分组
            tld_groups = self.group_domains_by_tld(domains)
            tld_patterns = []

            print(f"  📊 TLD分布情况:")
            for tld, tld_domains in sorted(tld_groups.items(), key=lambda x: len(x[1]), reverse=True):
                print(f"    .{tld}: {len(tld_domains)} 个域名")
                # 显示一些域名样本
                if len(tld_domains) <= 3:
                    for domain in tld_domains:
                        print(f"      - {domain}")
                else:
                    for domain in tld_domains[:3]:
                        print(f"      - {domain}")
                    print(f"      - ... 还有 {len(tld_domains)-3} 个域名")

            for tld, tld_domains in tld_groups.items():
                if len(tld_domains) == 1:
                    # 单个域名直接处理
                    domain = tld_domains[0]
                    tld_patterns.append(re.escape(domain))
                else:
                    # 多个域名进行高级优化
                    optimized_pattern = self.create_advanced_tld_regex(tld_domains, tld)
                    tld_patterns.append(optimized_pattern)
                    print(f"  ✅ TLD .{tld}: {len(tld_domains)} 个域名已优化合并")

            # 合并所有TLD组的模式
            if len(tld_patterns) == 1:
                combined_pattern = tld_patterns[0]
            else:
                combined_pattern = f"({'|'.join(tld_patterns)})"

            single_regex = f"(.*\\.)?{combined_pattern}$"
        else:
            # 简单合并模式
            escaped_domains = [re.escape(d) for d in domains]
            combined_pattern = '|'.join(escaped_domains)
            single_regex = f"(.*\\.)?({combined_pattern})$"

        # 显示规则长度信息
        rule_length = len(single_regex)
        print(f"  📏 生成的单行规则长度: {rule_length:,} 字符")

        if rule_length > 100000:
            print("  ⚠️  规则极长，可能严重影响性能，建议分割")
        elif rule_length > 50000:
            print("  ⚠️  规则很长，可能影响匹配性能")
        elif rule_length > 10000:
            print("  ⚠️  规则较长，请注意性能")
        else:
            print("  ✅ 规则长度适中")

        return single_regex

    def create_multiple_optimized_rules(self, domains: Union[Set[str], List[str]]) -> List[str]:
        """
        创建多个优化的规则（非单行模式）

        Args:
            domains: 域名集合或列表

        Returns:
            优化后的规则列表
        """
        if not domains:
            return []

        # 转换为排序列表
        if isinstance(domains, set):
            domains = self.smart_sort_domains(domains)

        optimization_config = self.config["optimization"]
        max_domains_per_rule = optimization_config.get("max_domains_per_rule", 30)
        max_rule_length = optimization_config.get("max_rule_length", 4000)

        # 按TLD分组处理
        if optimization_config.get("group_by_tld", True):
            tld_groups = self.group_domains_by_tld(domains)
            rules = []

            for tld, tld_domains in tld_groups.items():
                if len(tld_domains) <= 1:
                    # 单个域名直接转换
                    rules.extend([self.domain_to_regex(domain) for domain in tld_domains])
                else:
                    # 多个域名分批处理
                    tld_rules = self._create_batched_rules(tld_domains, tld, max_domains_per_rule, max_rule_length)
                    rules.extend(tld_rules)
                    print(f"  📦 TLD .{tld}: {len(tld_domains)} 个域名 -> {len(tld_rules)} 个规则")

            return rules
        else:
            # 不分组，直接分批处理
            return self._create_batched_rules(domains, None, max_domains_per_rule, max_rule_length)

    def _create_batched_rules(self, domains: List[str], tld: str = None, max_domains_per_rule: int = 30, max_rule_length: int = 4000) -> List[str]:
        """
        为域名列表创建分批的规则

        Args:
            domains: 域名列表
            tld: 顶级域名（可选，用于优化）
            max_domains_per_rule: 每个规则的最大域名数
            max_rule_length: 最大规则长度

        Returns:
            分批后的规则列表
        """
        rules = []
        current_batch = []

        for domain in domains:
            test_batch = current_batch + [domain]

            # 创建测试规则
            if tld and self.config["optimization"].get("enable_advanced_tld_merge", True):
                test_rule = self._create_tld_optimized_rule(test_batch, tld)
            else:
                test_rule = self._create_simple_rule(test_batch)

            # 检查是否超过限制
            if (len(test_batch) > max_domains_per_rule or
                len(test_rule) > max_rule_length):

                # 保存当前批次
                if current_batch:
                    if tld and self.config["optimization"].get("enable_advanced_tld_merge", True):
                        rules.append(self._create_tld_optimized_rule(current_batch, tld))
                    else:
                        rules.append(self._create_simple_rule(current_batch))

                # 开始新批次
                current_batch = [domain]
            else:
                current_batch.append(domain)

        # 处理最后一个批次
        if current_batch:
            if tld and self.config["optimization"].get("enable_advanced_tld_merge", True):
                rules.append(self._create_tld_optimized_rule(current_batch, tld))
            else:
                rules.append(self._create_simple_rule(current_batch))

        return rules

    def _create_tld_optimized_rule(self, domains: List[str], tld: str) -> str:
        """
        为同TLD域名创建优化规则

        Args:
            domains: 域名列表
            tld: 顶级域名

        Returns:
            TLD优化的正则表达式规则
        """
        if len(domains) == 1:
            return f"(.*\\.)?{re.escape(domains[0])}$"

        optimized_pattern = self.create_advanced_tld_regex(domains, tld)
        return f"(.*\\.)?{optimized_pattern}$"

    def _create_simple_rule(self, domains: List[str]) -> str:
        """
        为域名列表创建简单规则

        Args:
            domains: 域名列表

        Returns:
            简单的正则表达式规则
        """
        if len(domains) == 1:
            return f"(.*\\.)?{re.escape(domains[0])}$"
        else:
            pattern = self.optimize_domain_bases(domains)
            return f"(.*\\.)?({pattern})$"

    def merge_domains_to_regex(self, domains: Set[str]) -> List[str]:
        """
        将多个域名合并为优化的正则表达式列表

        Args:
            domains: 域名集合

        Returns:
            优化后的正则表达式列表
        """
        if not domains:
            return []

        # 检查是否强制生成单行正则
        if self.force_single_regex or self.config["optimization"].get("force_single_regex", False):
            print(f"🚀 启用强制单行正则表达式模式")
            single_rule = self.create_single_regex_rule(domains)
            return [single_rule] if single_rule else []

        optimization_config = self.config["optimization"]

        # 如果未启用合并优化，返回单独的规则
        if not optimization_config.get("merge_domains", True):
            return [self.domain_to_regex(domain) for domain in domains]

        # 使用多规则优化模式
        print(f"🔧 启用多规则优化模式，处理 {len(domains)} 个域名")
        rules = self.create_multiple_optimized_rules(domains)

        print(f"  ✅ 优化完成: {len(domains)} 个域名 -> {len(rules)} 个规则")
        return rules

    def collect_domains(self) -> Dict[str, Set[str]]:
        """
        🔧 修复：从所有配置的源收集域名，正确处理特定路径规则的动作分配

        Returns:
            按动作分类的域名集合
        """
        categorized_domains = {
            'remove': set(),
            'low_priority': set(),
            'high_priority': set()
        }

        # 重置统计信息
        self.stats = {
            'total_rules': 0,
            'parsed_domains': 0,
            'ignored_with_path': 0,
            'path_to_low_priority': 0,  # 特定路径转低优先级数量
            'path_kept_action': 0,      # 🔧 特定路径保持原动作数量
            'invalid_domains': 0,
            'duplicate_domains': 0,
            'ignored_comments': 0,
            'auto_classified': 0,
            'skipped_domains': 0,
            'auto_added': 0,
            'skipped_from_sources': 0,
            'skip_overridden': 0,
            'v2ray_with_tags': 0,
            'csv_parsed_rows': 0,
            'csv_invalid_urls': 0,
            'csv_extracted_domains': 0,
            'wildcard_rules_processed': 0,  # 🔧 处理的通配符规则数量
        }

        # 记录每个类别的域名数量
        self.category_domain_counts = {
            'remove': 0,
            'low_priority': 0,
            'low_priority_all': 0,
            'high_priority': 0,
            'replace': 0
        }

        # 从在线源收集域名
        for source in self.config["sources"]:
            if not source.get("enabled", True):
                continue

            print(f"\n处理数据源: {source['name']}")
            format_type = source.get("format", "domain")
            csv_config = source.get("csv_config") if format_type == "csv" else None
            source_action = source.get("action", "remove")
            print(f"格式类型: {format_type}，原始动作: {source_action}")

            # 🔧 设置临时变量供 fetch_domain_list 使用
            self._current_source_action = source_action

            # 🔧 修复：获取普通域名和已分类的特定路径域名
            domains, path_domains_classified, source_stats = self.fetch_domain_list(source["url"], format_type, source["name"], csv_config)

            # 累加统计信息
            for key in self.stats:
                if key in source_stats:
                    self.stats[key] += source_stats[key]

            # 🔧 处理普通域名分类
            auto_classified_count = 0

            for domain in list(domains):
                # 检查自动分类规则
                auto_action, reason = self.get_auto_classify_action(domain)
                if auto_action:
                    # 从原始集合中移除，添加到相应类别
                    domains.remove(domain)
                    categorized_domains[auto_action].add(domain)
                    auto_classified_count += 1
                    if auto_classified_count <= 5:  # 显示前5个样本
                        print(f"  🔄 自动分类: {domain} -> {auto_action} ({reason})")
                else:
                    # 使用源的默认动作
                    if source_action in categorized_domains:
                        categorized_domains[source_action].add(domain)

            # 🔧 处理特定路径域名（已经按动作分类）
            path_auto_classified_count = 0
            total_path_domains = 0

            for path_action, path_domain_set in path_domains_classified.items():
                for domain in path_domain_set:
                    # 检查自动分类规则（优先级最高）
                    auto_action, reason = self.get_auto_classify_action(domain)
                    if auto_action:
                        categorized_domains[auto_action].add(domain)
                        path_auto_classified_count += 1
                        if path_auto_classified_count <= 3:
                            print(f"  🔄 特定路径域名自动分类覆盖: {domain} -> {auto_action} ({reason}) (原为 {path_action})")
                    else:
                        # 使用已确定的路径动作
                        if path_action in categorized_domains:
                            categorized_domains[path_action].add(domain)
                        total_path_domains += 1

            auto_classified_count += path_auto_classified_count

            if auto_classified_count > 0:
                print(f"  ✅ 自动分类处理: {auto_classified_count} 个域名 (普通: {auto_classified_count - path_auto_classified_count}, 特定路径: {path_auto_classified_count})")
                self.stats['auto_classified'] += auto_classified_count

            # 记录从数据源跳过的域名数量
            self.stats['skipped_from_sources'] += source_stats.get('skipped_domains', 0)

            total_added = len(domains) + total_path_domains
            print(f"已添加 {total_added} 个域名到相应类别 (普通: {len(domains)}, 特定路径: {total_path_domains})")

            # 清除临时变量
            delattr(self, '_current_source_action')

        # 从自定义规则文件加载
        print(f"\n处理自定义规则文件...")
        if self.config.get("custom_rules", {}).get("enabled", False):
            custom_sources = self.config["custom_rules"]["sources"]

            for source in custom_sources:
                if not source.get("enabled", True):
                    continue

                print(f"\n处理自定义规则: {source['name']}")
                file_path = source["file"]
                format_type = source.get("format", "domain")
                action = source.get("action", "remove")
                csv_config = source.get("csv_config") if format_type == "csv" else None

                if not os.path.exists(file_path):
                    print(f"  ❌ 文件不存在: {file_path}")
                    continue

                domains, replace_rules, source_stats = self.load_custom_rules_from_file(
                    file_path, format_type, action, csv_config
                )

                # 累加统计信息
                self.stats['total_rules'] += source_stats['total_rules']
                self.stats['parsed_domains'] += source_stats['parsed_domains']
                self.stats['invalid_domains'] += source_stats['invalid_domains']
                self.stats['ignored_comments'] += source_stats['ignored_comments']
                self.stats['csv_parsed_rows'] += source_stats.get('csv_parsed_rows', 0)
                self.stats['csv_invalid_urls'] += source_stats.get('csv_invalid_urls', 0)
                self.stats['csv_extracted_domains'] += source_stats.get('csv_extracted_domains', 0)

                # 将域名添加到相应类别
                if action in categorized_domains:
                    categorized_domains[action].update(domains)

                # 处理替换规则
                if action == "replace" and replace_rules:
                    # 更新配置中的替换规则
                    self.config["replace_rules"].update(replace_rules)

                print(f"  ✅ 从文件加载了 {len(domains) + len(replace_rules)} 个规则到 {action} 类别")

        # 🔥 应用自动分类规则中的域名
        self.apply_auto_classify_rules_directly(categorized_domains)

        return categorized_domains

    def sort_rules(self, rules: Union[Dict, List]) -> Union[Dict, List]:
        """
        对规则进行排序

        Args:
            rules: 规则数据

        Returns:
            排序后的规则
        """
        if isinstance(rules, dict):
            # 对字典按键排序
            return OrderedDict(sorted(rules.items()))
        elif isinstance(rules, list):
            # 对列表按值排序
            return sorted(rules)
        else:
            return rules

    def generate_rules(self) -> Dict[str, any]:
        """
        生成各类规则

        Returns:
            规则字典
        """
        print("\n开始生成 SearXNG hostnames 规则...")

        # 显示优化模式信息
        if self.force_single_regex or self.config["optimization"].get("force_single_regex", False):
            print("🚀 已启用高级TLD优化单行正则表达式模式")
            print("   每个类别将生成单个包含所有域名的高级优化正则表达式")
        else:
            print("🔧 已启用多规则优化模式")
            print("   将生成多个性能优化的正则表达式规则")

        # 显示解析配置
        parsing_config = self.config["parsing"]
        print(f"📝 解析配置:")
        print(f"   - 忽略特定路径规则: {parsing_config.get('ignore_specific_paths', False)}")
        print(f"   - 🔧 特定路径规则处理: {parsing_config.get('specific_path_action', 'keep_action')}")
        print(f"   - 严格域名级别检查: {parsing_config.get('strict_domain_level_check', True)}")
        print(f"   - 保持原始结构: {parsing_config.get('preserve_original_structure', True)}")
        print(f"   - 保持 www. 前缀: {parsing_config.get('preserve_www_prefix', True)}")

        # 收集域名
        categorized_domains = self.collect_domains()

        # 处理自动分类替换规则
        auto_replace_rules = {}
        for rule in self.auto_classify_rules:
            if rule['action'] == 'replace':
                old_regex = f"(.*\\.)?{re.escape(rule['old_domain'])}$"
                auto_replace_rules[old_regex] = rule['new_domain']

        rules = {}

        # 替换规则 (字典格式)
        all_replace_rules = {}
        all_replace_rules.update(self.config["replace_rules"])
        all_replace_rules.update(auto_replace_rules)

        if all_replace_rules:
            rules["replace"] = all_replace_rules
            # 记录替换规则的域名数量
            self.category_domain_counts["replace"] = len(all_replace_rules)
        else:
            # 即使没有替换规则，也创建空规则以确保文件被创建
            self.category_domain_counts["replace"] = 0

        # 移除规则 (列表格式) - 使用优化的合并
        print(f"\n生成移除规则...")
        remove_rules = []
        remove_rules.extend(self.config["fixed_remove"])

        # 记录固定移除规则数量
        fixed_remove_count = len(self.config["fixed_remove"])

        if categorized_domains["remove"]:
            print(f"正在优化 {len(categorized_domains['remove'])} 个移除域名...")
            self.category_domain_counts["remove"] = len(categorized_domains["remove"]) + fixed_remove_count
            merged_remove_rules = self.merge_domains_to_regex(categorized_domains["remove"])
            remove_rules.extend(merged_remove_rules)
        else:
            self.category_domain_counts["remove"] = fixed_remove_count

        if remove_rules:
            rules["remove"] = remove_rules
        else:
            # 创建空移除规则列表，确保文件被创建
            rules["remove"] = []

        # 低优先级规则 (列表格式) - 使用优化的合并
        print(f"\n生成低优先级规则...")
        low_priority_rules = []
        low_priority_rules.extend(self.config["fixed_low_priority"])

        # 记录固定低优先级规则数量
        fixed_low_priority_count = len(self.config["fixed_low_priority"])

        if categorized_domains["low_priority"]:
            print(f"正在优化 {len(categorized_domains['low_priority'])} 个低优先级域名...")
            self.category_domain_counts["low_priority"] = len(categorized_domains["low_priority"]) + fixed_low_priority_count
            merged_low_priority_rules = self.merge_domains_to_regex(categorized_domains["low_priority"])
            low_priority_rules.extend(merged_low_priority_rules)
        else:
            self.category_domain_counts["low_priority"] = fixed_low_priority_count

        if low_priority_rules:
            rules["low_priority"] = low_priority_rules
        else:
            # 创建空低优先级规则列表，确保文件被创建
            rules["low_priority"] = []

        # 低优先级 + 移除组合规则 (列表格式)
        print(f"\n生成低优先级(含移除)组合规则...")
        low_priority_all_rules = sorted(set(remove_rules + low_priority_rules))
        rules["low_priority_all"] = low_priority_all_rules
        self.category_domain_counts["low_priority_all"] = len(
            set(categorized_domains["remove"] | categorized_domains["low_priority"])
        ) + fixed_remove_count + fixed_low_priority_count

        # 高优先级规则 (列表格式) - 使用优化的合并
        print(f"\n生成高优先级规则...")
        high_priority_rules = []
        high_priority_rules.extend(self.config["fixed_high_priority"])

        # 记录固定高优先级规则数量
        fixed_high_priority_count = len(self.config["fixed_high_priority"])

        if categorized_domains["high_priority"]:
            print(f"正在优化 {len(categorized_domains['high_priority'])} 个高优先级域名...")
            self.category_domain_counts["high_priority"] = len(categorized_domains["high_priority"]) + fixed_high_priority_count
            merged_high_priority_rules = self.merge_domains_to_regex(categorized_domains["high_priority"])
            high_priority_rules.extend(merged_high_priority_rules)
        else:
            self.category_domain_counts["high_priority"] = fixed_high_priority_count

        if high_priority_rules:
            rules["high_priority"] = high_priority_rules
        else:
            # 创建空高优先级规则列表，确保文件被创建
            rules["high_priority"] = []

        # 对所有规则进行排序和去重
        for rule_type in rules:
            if rule_type == "replace":
                # 替换规则按键排序
                rules[rule_type] = self.sort_rules(rules[rule_type])
            else:
                # 列表规则去重并排序
                rules[rule_type] = self.sort_rules(list(set(rules[rule_type])))

        return rules

    def save_separate_files(self, rules: Dict[str, any]) -> None:
        """
        保存为分离的文件

        Args:
            rules: 规则字典
        """
        output_dir = self.config["output"]["directory"]
        files_config = self.config["output"]["files"]

        # 创建输出目录
        os.makedirs(output_dir, exist_ok=True)

        # 生成主配置文件 (用于引用外部文件)
        main_config = {"hostnames": {}}

        # 保存各类规则到单独文件 - 确保所有类别的文件都被创建
        expected_rule_types = ["replace", "remove", "low_priority", "low_priority_all", "high_priority"]

        for rule_type in expected_rule_types:
            if rule_type in files_config:
                filename = files_config[rule_type]
                filepath = os.path.join(output_dir, filename)

                # 获取规则数据，如果不存在则创建空数据
                rule_data = rules.get(rule_type, [] if rule_type != "replace" else {})

                try:
                    with open(filepath, 'w', encoding='utf-8') as f:
                        # 简化的文件头注释
                        rule_count = len(rule_data) if isinstance(rule_data, (list, dict)) else 0
                        domain_count = self.category_domain_counts.get(rule_type, 0)

                        f.write(f"# SearXNG {rule_type} rules\n")
                        f.write(f"# Total rules: {rule_count}, Total domains: {domain_count}\n")
                        f.write("\n")

                        # 直接写入规则内容，不包含顶级键
                        if rule_data or rule_type in rules:  # 只有当有数据或原本就在rules中才写入内容
                            yaml.dump(rule_data, f, default_flow_style=False, allow_unicode=True, indent=2)
                        else:
                            # 写入空内容标记
                            if rule_type == "replace":
                                f.write("{}\n")  # 空字典
                            else:
                                f.write("[]\n")  # 空列表

                    print(f"已保存 {rule_type} 规则到: {filepath} ({rule_count} 条规则)")

                    # 在主配置中引用外部文件
                    main_config["hostnames"][rule_type] = filename

                except Exception as e:
                    print(f"保存 {rule_type} 规则失败: {e}")

        # 保存主配置文件
        if main_config["hostnames"]:
            main_config_path = os.path.join(output_dir, files_config["main_config"])
            try:
                with open(main_config_path, 'w', encoding='utf-8') as f:
                    # 简化的主配置文件头
                    f.write("# SearXNG hostnames configuration\n")
                    f.write("# This file references external rule files\n")
                    f.write("\n")
                    yaml.dump(main_config, f, default_flow_style=False, allow_unicode=True, indent=2)
                print(f"已保存主配置到: {main_config_path}")
            except Exception as e:
                print(f"保存主配置失败: {e}")

    def save_single_file(self, rules: Dict[str, any]) -> None:
        """
        保存为单个文件

        Args:
            rules: 规则字典
        """
        output_dir = self.config["output"]["directory"]
        os.makedirs(output_dir, exist_ok=True)

        # 确保所有类别都在规则中
        expected_rule_types = ["replace", "remove", "low_priority", "high_priority"]
        for rule_type in expected_rule_types:
            if rule_type not in rules:
                if rule_type == "replace":
                    rules[rule_type] = {}
                else:
                    rules[rule_type] = []

        # 构建完整的 hostnames 配置
        hostnames_config = {"hostnames": rules}

        filepath = os.path.join(output_dir, "hostnames.yml")

        try:
            with open(filepath, 'w', encoding='utf-8') as f:
                # 简化的文件头注释
                total_rules = sum(len(rule_data) if isinstance(rule_data, (list, dict)) else 0 for rule_data in rules.values())
                total_domains = sum(self.category_domain_counts.values())

                f.write("# SearXNG hostnames configuration\n")
                f.write(f"# Total rules: {total_rules}, Total domains: {total_domains}\n")
                f.write("\n")

                yaml.dump(hostnames_config, f, default_flow_style=False, allow_unicode=True, indent=2)

            print(f"已保存完整配置到: {filepath}")

        except Exception as e:
            print(f"保存配置失败: {e}")

    def run(self) -> None:
        """
        运行生成器
        """
        print("SearXNG Hostnames 规则生成器启动 - 域名提取修复版")
        print("🔧 修复：改进域名提取逻辑，支持更多规则格式")
        print("🔧 修复：改进域名验证逻辑，减少误判")
        print("🔧 新增：支持通配符规则处理")
        print("=" * 60)

        try:
            # 生成规则
            rules = self.generate_rules()

            # 根据配置保存文件
            if self.config["output"]["mode"] == "separate_files":
                self.save_separate_files(rules)
            else:
                self.save_single_file(rules)

            # 输出统计信息
            self.print_statistics(rules)

        except KeyboardInterrupt:
            print("\n用户中断操作")
        except Exception as e:
            print(f"\n生成过程中发生错误: {e}")
            import traceback
            traceback.print_exc()
            sys.exit(1)

    def print_statistics(self, rules: Dict[str, any]) -> None:
        """
        输出统计信息

        Args:
            rules: 生成的规则
        """
        print("\n" + "=" * 70)
        print("📊 统计信息:")

        total_rules = 0
        total_domains = 0

        for rule_type, rule_data in rules.items():
            if isinstance(rule_data, dict):
                rule_count = len(rule_data)
                domain_count = self.category_domain_counts.get(rule_type, 0)
                print(f"  {rule_type} 规则: {rule_count} 条 (包含 {domain_count} 个域名)")
                total_rules += rule_count
                total_domains += domain_count
            elif isinstance(rule_data, list):
                rule_count = len(rule_data)
                domain_count = self.category_domain_counts.get(rule_type, 0)
                print(f"  {rule_type} 规则: {rule_count} 条 (包含 {domain_count} 个域名)")
                total_rules += rule_count
                total_domains += domain_count

        print(f"\n📈 总计: {total_rules} 条规则 (包含 {total_domains} 个域名)")

        print(f"\n🔍 解析统计:")
        print(f"  - 总输入规则: {self.stats['total_rules']:,}")
        print(f"  - 成功解析域名: {self.stats['parsed_domains']:,}")
        print(f"  - 忽略(特定路径): {self.stats['ignored_with_path']:,}")
        print(f"  - 🔧 特定路径->低优先级: {self.stats.get('path_to_low_priority', 0):,}")
        print(f"  - 🔧 特定路径保持原动作: {self.stats.get('path_kept_action', 0):,}")
        print(f"  - 忽略(注释): {self.stats['ignored_comments']:,}")
        print(f"  - 忽略(无效域名): {self.stats['invalid_domains']:,}")
        print(f"  - 重复域名: {self.stats['duplicate_domains']:,}")

        if self.stats.get('wildcard_rules_processed', 0) > 0:
            print(f"  - 🔧 通配符规则处理: {self.stats.get('wildcard_rules_processed', 0):,}")
        if self.stats.get('auto_classified', 0) > 0:
            print(f"  - 自动分类处理: {self.stats.get('auto_classified', 0):,}")
        if self.stats.get('auto_added', 0) > 0:
            print(f"  - 主动添加域名: {self.stats.get('auto_added', 0):,}")
        if self.stats.get('skipped_from_sources', 0) > 0:
            print(f"  - 从数据源跳过: {self.stats.get('skipped_from_sources', 0):,}")
        if self.stats.get('v2ray_with_tags', 0) > 0:
            print(f"  - v2ray 带标签规则: {self.stats.get('v2ray_with_tags', 0):,}")
        if self.stats.get('csv_extracted_domains', 0) > 0:
            print(f"  - CSV 提取域名: {self.stats.get('csv_extracted_domains', 0):,}")

        print(f"\n📁 输出目录: {self.config['output']['directory']}")

        print(f"\n🔧 特定路径规则处理:")
        specific_path_action = self.config['parsing'].get('specific_path_action', 'keep_action')
        print(f"  - 处理模式: {specific_path_action}")
        if specific_path_action == 'low_priority':
            print(f"  - 转为低优先级的数量: {self.stats.get('path_to_low_priority', 0):,}")
            print(f"  - 效果: 所有特定路径规则强制设置为低优先级")
        elif specific_path_action == 'keep_action':
            print(f"  - 保持原动作的数量: {self.stats.get('path_kept_action', 0):,}")
            print(f"  - 转为低优先级的数量: {self.stats.get('path_to_low_priority', 0):,}")
            print(f"  - 效果: 特定路径规则保持源的原始动作 (推荐)")
        elif specific_path_action == 'smart':
            print(f"  - 智能处理的数量: {self.stats.get('path_kept_action', 0):,} + {self.stats.get('path_to_low_priority', 0):,}")
            print(f"  - 效果: remove->low_priority，其他动作保持不变")
        elif specific_path_action == 'ignore':
            print(f"  - 效果: 特定路径规则被完全忽略")

        print(f"\n✨ 优化效果:")
        if total_domains > 0 and total_rules > 0:
            compression_ratio = (total_rules / total_domains) * 100
            print(f"  - 压缩比率: {compression_ratio:.1f}% ({total_domains:,} 个域名 -> {total_rules} 条规则)")

        print(f"\n💡 使用方法:")
        if self.config["output"]["mode"] == "separate_files":
            print("在 SearXNG settings.yml 中添加:")
            print("hostnames:")
            for rule_type, filename in self.config["output"]["files"].items():
                if rule_type != "main_config" and rule_type in ["replace", "remove", "low_priority", "high_priority"]:
                    print(f"  {rule_type}: '{filename}'")
        else:
            print("将生成的 hostnames.yml 内容复制到 SearXNG settings.yml 中")


def main():
    parser = argparse.ArgumentParser(description="SearXNG Hostnames 规则生成器 - 域名提取修复版")
    parser.add_argument("-c", "--config", help="配置文件路径")
    parser.add_argument("--single-regex", action="store_true", help="强制生成高级TLD优化的单行正则表达式")

    args = parser.parse_args()

    generator = SearXNGHostnamesGenerator(args.config, force_single_regex=args.single_regex)
    generator.run()


if __name__ == "__main__":
    main()
