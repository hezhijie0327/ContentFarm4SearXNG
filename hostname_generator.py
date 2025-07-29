#!/usr/bin/env python3
"""
SearXNG Hostnames 规则生成器 - 完善版 (支持 v2ray 格式 - 保持原始结构)
- 支持低优先级/高优先级/替换规则从外部文件读取
- 白名单功能改为自动分类语法功能，支持 remove:baidu.com 等语法
- 修复：skip 规则只影响数据源处理，不阻止明确的自动分类规则
- 新增：支持 v2ray 格式 (domain:example.com, full:example.com, domain:example.com:@tag)
- 修正：保持原始域名结构，不移除 www. 等前缀

pip install requests pyyaml argparse
"""

import requests
import yaml
import json
import re
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
            'invalid_domains': 0,
            'duplicate_domains': 0,
            'ignored_comments': 0,
            'auto_classified': 0,  # 自动分类的数量
            'auto_added': 0,  # 主动添加的域名数量
            'skipped_from_sources': 0,  # 从数据源跳过的域名数量
            'skip_overridden': 0,  # skip 规则被其他规则覆盖的数量
            'v2ray_with_tags': 0,  # 带标签的 v2ray 规则数量
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
                    "name": "hezhijie0327 - Geosite2Domain - dev",
                    "url": "https://raw.githubusercontent.com/hezhijie0327/Geosite2Domain/refs/heads/main/category/category-dev.txt",
                    "action": "high_priority",
                    "format": "v2ray",
                    "enabled": True
                },
                {
                    "name": "hezhijie0327 - Geosite2Domain - scholar-!cn",
                    "url": "https://raw.githubusercontent.com/hezhijie0327/Geosite2Domain/refs/heads/main/category/category-scholar-!cn.txt",
                    "action": "high_priority",
                    "format": "v2ray",
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
                "rules": [
                    # 语法示例：
                    # "remove:example.com",           # 将 example.com 添加到移除列表
                    # "low_priority:google.com",      # 将 google.com 添加到低优先级列表
                    # "high_priority:wikipedia.org",  # 将 wikipedia.org 添加到高优先级列表
                    # "replace:youtube.com=yt.example.com",  # 替换规则
                    # "skip:baidu.com",               # 跳过从数据源处理此域名（但不阻止其他自动分类规则）
                ]
            },

            # 域名替换规则（保留原配置方式）
            "replace_rules": {
                #'(.*\.)?youtube\.com$': 'yt.example.com',
                #'(.*\.)?youtu\.be$': 'yt.example.com',
                #'(.*\.)?reddit\.com$': 'teddit.example.com',
                #'(.*\.)?redd\.it$': 'teddit.example.com',
                #'(www\.)?twitter\.com$': 'nitter.example.com'
            },

            # 固定的移除规则
            "fixed_remove": [
                #'(.*\.)?facebook.com$'
            ],

            # 固定的低优先级规则
            "fixed_low_priority": [
                #'(.*\.)?google(\..*)?$'
            ],

            # 固定的高优先级规则
            "fixed_high_priority": [
                #'(.*\.)?wikipedia.org$'
            ],

            # 解析配置
            "parsing": {
                "ignore_specific_paths": True,  # 忽略指向特定路径的规则
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

    def load_custom_rules_from_file(self, file_path: str, format_type: str, action: str) -> Tuple[Set[str], Dict[str, str], Dict]:
        """
        从文件加载自定义规则

        Args:
            file_path: 文件路径
            format_type: 格式类型 (domain, regex, ublock, v2ray, replace)
            action: 动作类型 (remove, low_priority, high_priority, replace)

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
            'v2ray_with_tags': 0
        }

        try:
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
                        domain, ignore_reason = self.parse_ublock_rule(line)
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

    def is_domain_level_rule(self, url_string: str) -> bool:
        """
        判断是否是域名级别的规则（而非特定路径规则）

        Args:
            url_string: URL字符串

        Returns:
            是否是域名级别的规则
        """
        url_string = url_string.strip()

        # 严格检查模式
        if self.config["parsing"].get("strict_domain_level_check", True):
            # 这些模式被认为是域名级别的规则：
            domain_level_patterns = [
                # uBlock 域名级别模式 - 精确模式
                r'^\*://\*?\.?[a-zA-Z0-9.-]+/?$',                    # *://*.example.com 或 *://*.example.com/
                r'^\*://\*?\.?[a-zA-Z0-9.-]+/\*?$',                 # *://*.example.com/*
                r'^\*://[a-zA-Z0-9.-]+/?$',                         # *://example.com 或 *://example.com/
                r'^\*://[a-zA-Z0-9.-]+/\*?$',                       # *://example.com/*
                r'^\|\|[a-zA-Z0-9.-]+\^?$',                         # ||example.com^
                r'^[a-zA-Z0-9.-]+/?$',                              # example.com 或 example.com/
                r'^[a-zA-Z0-9.-]+/\*?$',                            # example.com/* 或 example.com/
            ]

            # 检查是否匹配域名级别模式
            for pattern in domain_level_patterns:
                if re.match(pattern, url_string):
                    # 额外检查：如果包含具体路径（除了/和/*），则不是域名级别
                    if self._has_specific_path(url_string):
                        return False
                    return True

            return False
        else:
            # 兼容模式（原来的逻辑）
            domain_level_patterns = [
                r'^\*://\*?\.?[a-zA-Z0-9.-]+/?$',
                r'^\*://\*?\.?[a-zA-Z0-9.-]+/\*$',
                r'^\|\|[a-zA-Z0-9.-]+\^?$',
                r'^[a-zA-Z0-9.-]+/?$',
                r'^[a-zA-Z0-9.-]+/\*$',
            ]

            for pattern in domain_level_patterns:
                if re.match(pattern, url_string):
                    return True

            return False

    def _has_specific_path(self, url_string: str) -> bool:
        """
        检查URL是否包含具体的路径（非域名级别）

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
                # 如果路径不是空、单个*或空字符串，则认为是具体路径
                if path_part and path_part not in ['', '*']:
                    return True

        return False

    def extract_domain_from_rule(self, rule: str) -> str:
        """
        从规则中提取域名

        Args:
            rule: 规则字符串

        Returns:
            域名或 None
        """
        rule = rule.strip()

        # 首先检查是否包含具体路径
        if self._has_specific_path(rule):
            # 对于包含具体路径的规则，需要更谨慎地提取域名
            return self._extract_domain_from_path_rule(rule)

        # uBlock 语法模式 - 仅用于域名级别规则
        patterns = [
            # *://*.domain.com/* 或 *://*.domain.com (通配符子域名)
            r'^\*://\*\.([a-zA-Z0-9.-]+)(?:/\*?)?$',
            # *://domain.com/* 或 *://domain.com (无通配符)
            r'^\*://([a-zA-Z0-9.-]+)(?:/\*?)?$',
            # ||domain.com^
            r'^\|\|([a-zA-Z0-9.-]+)\^?$',
            # 普通域名格式
            r'^([a-zA-Z0-9.-]+)(?:/\*?)?$',
        ]

        for pattern in patterns:
            match = re.match(pattern, rule)
            if match:
                return match.group(1)

        # 通用域名提取（最后的后备方案）
        domain_match = re.search(r'([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})', rule)
        if domain_match:
            candidate = domain_match.group(1)
            # 验证这个域名是否合理
            if self.is_valid_domain(candidate):
                return candidate

        return None

    def _extract_domain_from_path_rule(self, rule: str) -> str:
        """
        从包含路径的规则中提取域名

        Args:
            rule: 包含路径的规则字符串

        Returns:
            域名或 None
        """
        rule = rule.strip()

        # 对于包含具体路径的规则，我们通常不提取域名
        # 除非用户明确配置允许
        if self.config["parsing"]["ignore_specific_paths"]:
            return None

        # 如果用户允许处理路径规则，使用更精确的模式
        path_patterns = [
            # *://*.subdomain.domain.com/path/* -> 提取 subdomain.domain.com
            r'^\*://\*\.([a-zA-Z0-9.-]+)/[^/]+',
            # *://subdomain.domain.com/path/* -> 提取 subdomain.domain.com
            r'^\*://([a-zA-Z0-9.-]+)/[^/]+',
        ]

        for pattern in path_patterns:
            match = re.match(pattern, rule)
            if match:
                domain = match.group(1)
                # 只有当这是一个子域名时才返回，避免提取主域名
                if '.' in domain and len(domain.split('.')) >= 2:
                    return domain

        return None

    def parse_ublock_rule(self, rule: str) -> Tuple[str, str]:
        """
        解析 uBlock Origin 语法规则，提取域名

        Args:
            rule: uBlock 规则字符串

        Returns:
            (域名或 None, 忽略原因)
        """
        rule = rule.strip()
        if not rule or rule.startswith('!') or rule.startswith('#'):
            return None, "注释或空行"

        # 处理行末注释 - 移除 # 后面的所有内容
        if '#' in rule:
            # 找到第一个 # 的位置，移除它及后面的内容
            comment_pos = rule.find('#')
            rule = rule[:comment_pos].strip()

            # 如果移除注释后规则为空，则忽略
            if not rule:
                return None, "仅包含注释"

        # 首先检查是否是域名级别的规则
        if not self.is_domain_level_rule(rule):
            if self.config["parsing"]["ignore_specific_paths"]:
                return None, "指向特定路径"

        # 提取域名
        domain = self.extract_domain_from_rule(rule)

        if domain:
            cleaned_domain = self.clean_domain(domain)
            return cleaned_domain, None if cleaned_domain else "无效域名"

        return None, "无法解析规则格式"

    def fetch_domain_list(self, url: str, format_type: str = "domain", source_name: str = None) -> Tuple[Set[str], Dict]:
        """
        从URL获取域名列表

        Args:
            url: 域名列表URL
            format_type: 格式类型，"domain", "ublock", 或 "v2ray"
            source_name: 数据源名称（用于自动分类）

        Returns:
            (域名集合, 统计信息)
        """
        domains = set()
        stats = {
            'total_rules': 0,
            'parsed_domains': 0,
            'ignored_with_path': 0,
            'invalid_domains': 0,
            'duplicate_domains': 0,
            'ignored_comments': 0,
            'auto_classified': 0,  # 自动分类处理的数量
            'skipped_domains': 0,   # 跳过的域名数量
            'v2ray_with_tags': 0   # v2ray 带标签的规则数量
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

                # 记录一些被忽略的规则用于调试
                ignored_samples = []
                accepted_samples = []
                comment_samples = []
                path_samples = []  # 路径规则样本
                skip_samples = []  # 跳过的域名样本

                # 重置 v2ray 标签计数器
                initial_v2ray_tags = self.stats.get('v2ray_with_tags', 0)

                # 解析域名
                for line_num, line in enumerate(response.text.strip().split('\n'), 1):
                    line = line.strip()
                    if not line:
                        continue

                    stats['total_rules'] += 1

                    try:
                        if format_type == "ublock":
                            # 使用 uBlock 语法解析
                            domain, ignore_reason = self.parse_ublock_rule(line)
                        elif format_type == "v2ray":
                            # 使用 v2ray 语法解析
                            domain, ignore_reason = self.parse_v2ray_rule(line)
                            # 显示 v2ray 解析样本
                            if domain and len(accepted_samples) < 3:
                                accepted_samples.append(f"v2ray: {line} -> {domain}")
                            elif ignore_reason and len(ignored_samples) < 3:
                                ignored_samples.append(f"v2ray: {line} ({ignore_reason})")
                        else:
                            # 普通域名格式 - 也需要处理行末注释
                            cleaned_line = line
                            if '#' in line:
                                cleaned_line = line[:line.find('#')].strip()
                                if not cleaned_line:
                                    domain, ignore_reason = None, "仅包含注释"
                                else:
                                    if self.config["parsing"]["ignore_specific_paths"] and not self.is_domain_level_rule(cleaned_line):
                                        domain, ignore_reason = None, "指向特定路径"
                                    else:
                                        domain = self.clean_domain(self.extract_domain_from_rule(cleaned_line))
                                        ignore_reason = None if domain else "无效域名"
                            else:
                                if self.config["parsing"]["ignore_specific_paths"] and not self.is_domain_level_rule(cleaned_line):
                                    domain, ignore_reason = None, "指向特定路径"
                                else:
                                    domain = self.clean_domain(self.extract_domain_from_rule(cleaned_line))
                                    ignore_reason = None if domain else "无效域名"

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
                                    # 记录一些被接受的规则样本（非 v2ray 格式的）
                                    if format_type != "v2ray" and len(accepted_samples) < 3:
                                        accepted_samples.append(f"{line} -> {domain}")
                        else:
                            # 统计忽略原因
                            if ignore_reason == "指向特定路径":
                                stats['ignored_with_path'] += 1
                                # 记录一些被忽略的路径规则样本
                                if len(path_samples) < 3:
                                    path_samples.append(line)
                            elif ignore_reason in ["注释或空行", "仅包含注释"]:
                                stats['ignored_comments'] += 1
                                if len(comment_samples) < 3:
                                    comment_samples.append(line)
                            elif ignore_reason == "无效域名":
                                stats['invalid_domains'] += 1
                                if format_type != "v2ray" and len(ignored_samples) < 3:
                                    ignored_samples.append(line)

                    except Exception as e:
                        print(f"解析第 {line_num} 行时出错: {line[:50]}... - {e}")
                        stats['invalid_domains'] += 1
                        continue

                # 计算本次请求中的 v2ray 标签数量
                current_v2ray_tags = self.stats.get('v2ray_with_tags', 0) - initial_v2ray_tags
                stats['v2ray_with_tags'] = current_v2ray_tags

                print(f"成功获取 {len(domains)} 个域名")
                print(f"  - 总规则: {stats['total_rules']}")
                print(f"  - 成功解析: {stats['parsed_domains']}")
                print(f"  - 忽略(特定路径): {stats['ignored_with_path']}")
                print(f"  - 忽略(注释): {stats['ignored_comments']}")
                print(f"  - 忽略(无效域名): {stats['invalid_domains']}")
                print(f"  - 重复域名: {stats['duplicate_domains']}")
                print(f"  - 跳过域名: {stats['skipped_domains']}")
                if format_type == "v2ray" and stats['v2ray_with_tags'] > 0:
                    print(f"  - v2ray 带标签规则: {stats['v2ray_with_tags']}")

                # 显示样本
                if accepted_samples:
                    print(f"  - 接受的规则样本:")
                    for sample in accepted_samples:
                        print(f"    ✓ {sample}")

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

                return domains, stats

            except requests.RequestException as e:
                print(f"获取失败 (尝试 {attempt + 1}/{retry_count}): {e}")
                if attempt < retry_count - 1:
                    time.sleep(retry_delay)
                else:
                    print(f"放弃获取 {url}")

        return domains, stats

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
        验证域名格式

        Args:
            domain: 域名字符串

        Returns:
            是否为有效域名
        """
        if not domain or len(domain) > 255:
            return False

        # 基本的域名格式验证
        domain_pattern = re.compile(
            r'^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)*[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?$'
        )

        return bool(domain_pattern.match(domain))

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
        从所有配置的源收集域名

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
            'invalid_domains': 0,
            'duplicate_domains': 0,
            'ignored_comments': 0,
            'auto_classified': 0,
            'skipped_domains': 0,
            'auto_added': 0,
            'skipped_from_sources': 0,
            'skip_overridden': 0,
            'v2ray_with_tags': 0
        }

        # 从在线源收集域名
        for source in self.config["sources"]:
            if not source.get("enabled", True):
                continue

            print(f"\n处理数据源: {source['name']}")
            format_type = source.get("format", "domain")
            print(f"格式类型: {format_type}")

            domains, source_stats = self.fetch_domain_list(source["url"], format_type, source["name"])

            # 累加统计信息
            for key in self.stats:
                if key in source_stats:
                    self.stats[key] += source_stats[key]

            # 处理域名分类
            source_action = source.get("action", "remove")
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

            if auto_classified_count > 0:
                print(f"  ✅ 自动分类处理: {auto_classified_count} 个域名")
                self.stats['auto_classified'] += auto_classified_count

            # 记录从数据源跳过的域名数量
            self.stats['skipped_from_sources'] += source_stats.get('skipped_domains', 0)

            print(f"已添加 {len(domains)} 个域名到 {source_action} 类别")

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

                if not os.path.exists(file_path):
                    print(f"  ❌ 文件不存在: {file_path}")
                    continue

                domains, replace_rules, source_stats = self.load_custom_rules_from_file(
                    file_path, format_type, action
                )

                # 累加统计信息
                self.stats['total_rules'] += source_stats['total_rules']
                self.stats['parsed_domains'] += source_stats['parsed_domains']
                self.stats['invalid_domains'] += source_stats['invalid_domains']
                self.stats['ignored_comments'] += source_stats['ignored_comments']

                # 将域名添加到相应类别
                if action in categorized_domains:
                    categorized_domains[action].update(domains)

                # 处理替换规则
                if action == "replace" and replace_rules:
                    # 更新配置中的替换规则
                    self.config["replace_rules"].update(replace_rules)

                print(f"  ✅ 从文件加载了 {len(domains) + len(replace_rules)} 个规则到 {action} 类别")

        # 🔥 新增功能：主动应用自动分类规则中的域名
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
        print(f"   - 忽略特定路径规则: {parsing_config.get('ignore_specific_paths', True)}")
        print(f"   - 严格域名级别检查: {parsing_config.get('strict_domain_level_check', True)}")
        print(f"   - 保持原始结构: {parsing_config.get('preserve_original_structure', True)}")
        print(f"   - 保持 www. 前缀: {parsing_config.get('preserve_www_prefix', True)}")

        # 显示自动分类配置
        auto_classify_config = self.config.get("auto_classify", {})
        if auto_classify_config.get("enabled", False):
            print(f"🔄 自动分类配置:")
            print(f"   - 内置规则: {len(auto_classify_config.get('rules', []))} 个")
            print(f"   - 外部源: {len([s for s in auto_classify_config.get('sources', []) if s.get('enabled', True)])} 个")
            print(f"   - 总计规则: {len(self.auto_classify_rules)} 个")
        else:
            print(f"🔄 自动分类功能已禁用")

        # 显示自定义规则配置
        custom_rules_config = self.config.get("custom_rules", {})
        if custom_rules_config.get("enabled", False):
            enabled_sources = [s for s in custom_rules_config.get("sources", []) if s.get("enabled", True)]
            print(f"📁 自定义规则文件:")
            print(f"   - 启用的文件源: {len(enabled_sources)} 个")
            for source in enabled_sources:
                print(f"     • {source['name']}: {source['file']} ({source.get('action', 'remove')}) - 格式: {source.get('format', 'domain')}")
        else:
            print(f"📁 自定义规则文件功能已禁用")

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
        保存为分离的文件 - 简化版文件头

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
        expected_rule_types = ["replace", "remove", "low_priority", "high_priority"]

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
        保存为单个文件 - 简化版文件头

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
        print("SearXNG Hostnames 规则生成器启动 (完整版 - 自动分类 + 自定义文件 + TLD优化 + v2ray 格式 - 保持原始结构)")
        print("🔧 修复版本：skip 规则只影响数据源处理，不阻止明确的自动分类规则")
        print("🆕 新增功能：支持 v2ray 格式 (domain:example.com, full:example.com, domain:example.com:@tag)")
        print("🔧 修正功能：保持原始域名结构，不移除 www. 等前缀")
        print("=" * 90)

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

                # 如果是单行正则模式，显示规则长度信息
                if (self.force_single_regex or self.config["optimization"].get("force_single_regex", False)) and rule_data:
                    for i, rule in enumerate(rule_data, 1):
                        rule_length = len(rule)
                        if rule_length > 1000:
                            print(f"    规则 {i} 长度: {rule_length:,} 字符")

        print(f"\n📈 总计: {total_rules} 条规则 (包含 {total_domains} 个域名)")

        print(f"\n🔍 解析统计:")
        print(f"  - 总输入规则: {self.stats['total_rules']:,}")
        print(f"  - 成功解析域名: {self.stats['parsed_domains']:,}")
        print(f"  - 忽略(特定路径): {self.stats['ignored_with_path']:,}")
        print(f"  - 忽略(注释): {self.stats['ignored_comments']:,}")
        print(f"  - 忽略(无效域名): {self.stats['invalid_domains']:,}")
        print(f"  - 重复域名: {self.stats['duplicate_domains']:,}")
        print(f"  - 自动分类处理: {self.stats.get('auto_classified', 0):,}")
        print(f"  - 🆕 主动添加域名: {self.stats.get('auto_added', 0):,}")
        print(f"  - 🔄 从数据源跳过: {self.stats.get('skipped_from_sources', 0):,}")
        print(f"  - 🔄 skip 规则被覆盖: {self.stats.get('skip_overridden', 0):,}")
        if self.stats.get('v2ray_with_tags', 0) > 0:
            print(f"  - 📝 v2ray 带标签规则: {self.stats.get('v2ray_with_tags', 0):,}")

        print(f"\n📁 输出目录: {self.config['output']['directory']}")

        print(f"\n📡 数据源:")
        for source in self.config["sources"]:
            if source.get("enabled", True):
                print(f"  ✅ {source['name']} ({source.get('format', 'domain')})")
            else:
                print(f"  ❌ {source['name']} (已禁用)")

        print(f"\n⚙️  配置:")
        print(f"  - 忽略特定路径规则: {self.config['parsing']['ignore_specific_paths']}")
        print(f"  - 严格域名级别检查: {self.config['parsing'].get('strict_domain_level_check', True)}")
        print(f"  - 忽略IP地址: {self.config['parsing']['ignore_ip']}")
        print(f"  - 忽略localhost: {self.config['parsing']['ignore_localhost']}")
        print(f"  - 保持原始结构: {self.config['parsing'].get('preserve_original_structure', True)}")
        print(f"  - 保持 www. 前缀: {self.config['parsing'].get('preserve_www_prefix', True)}")

        # 自动分类配置
        auto_classify_config = self.config.get("auto_classify", {})
        print(f"\n🔄 自动分类配置:")
        if auto_classify_config.get("enabled", False):
            print(f"  - 状态: 已启用")
            print(f"  - 内置规则: {len(auto_classify_config.get('rules', []))} 个")
            print(f"  - 外部源: {len([s for s in auto_classify_config.get('sources', []) if s.get('enabled', True)])} 个")
            print(f"  - 总计规则: {len(self.auto_classify_rules)} 个")
            print(f"  - 重新分类域名: {self.stats.get('auto_classified', 0):,} 个")
            print(f"  - 🆕 主动添加域名: {self.stats.get('auto_added', 0):,} 个")
            print(f"  - 🔄 从数据源跳过: {self.stats.get('skipped_from_sources', 0):,} 个")
            print(f"  - 🔄 skip 规则覆盖: {self.stats.get('skip_overridden', 0):,} 个")
        else:
            print(f"  - 状态: 已禁用")

        # 自定义规则配置
        custom_rules_config = self.config.get("custom_rules", {})
        print(f"\n📁 自定义规则文件:")
        if custom_rules_config.get("enabled", False):
            print(f"  - 状态: 已启用")
            enabled_sources = [s for s in custom_rules_config.get("sources", []) if s.get("enabled", True)]
            print(f"  - 启用的文件源: {len(enabled_sources)} 个")
            for source in enabled_sources:
                file_exists = "✅" if os.path.exists(source['file']) else "❌"
                format_info = f" - 格式: {source.get('format', 'domain')}"
                print(f"    {file_exists} {source['name']}: {source['file']} ({source.get('action', 'remove')}){format_info}")
        else:
            print(f"  - 状态: 已禁用")

        # 性能优化配置
        opt_config = self.config["optimization"]
        print(f"\n🚀 性能优化:")
        print(f"  - 启用域名合并: {opt_config.get('merge_domains', True)}")
        print(f"  - 智能域名排序: {opt_config.get('sort_before_merge', True)}")
        print(f"  - 高级TLD优化: {opt_config.get('enable_advanced_tld_merge', True)}")
        print(f"  - 强制单行正则: {self.force_single_regex or opt_config.get('force_single_regex', False)}")

        if not (self.force_single_regex or opt_config.get('force_single_regex', False)):
            print(f"  - 每规则最大域名数: {opt_config.get('max_domains_per_rule', 30)}")
            print(f"  - 按TLD分组: {opt_config.get('group_by_tld', True)}")
            print(f"  - 最大规则长度: {opt_config.get('max_rule_length', 4000):,}")

        print(f"  - 前缀优化: {opt_config.get('enable_prefix_optimization', True)}")
        print(f"  - 后缀优化: {opt_config.get('enable_suffix_optimization', True)}")

        print(f"\n💡 使用方法:")
        if self.config["output"]["mode"] == "separate_files":
            print("在 SearXNG settings.yml 中添加:")
            print("hostnames:")
            for rule_type, filename in self.config["output"]["files"].items():
                if rule_type != "main_config" and rule_type in ["replace", "remove", "low_priority", "high_priority"]:
                    print(f"  {rule_type}: '{filename}'")
        else:
            print("将生成的 hostnames.yml 内容复制到 SearXNG settings.yml 中")

        print(f"\n✨ 优化效果:")
        if total_domains > 0 and total_rules > 0:
            compression_ratio = (total_rules / total_domains) * 100
            print(f"  - 压缩比率: {compression_ratio:.1f}% ({total_domains:,} 个域名 -> {total_rules} 条规则)")
            if compression_ratio < 10:
                print("  - 🎉 压缩效果极佳！大量域名被合并优化")
            elif compression_ratio < 50:
                print("  - 👍 压缩效果良好")
            else:
                print("  - 📝 规则较多，可考虑启用单行正则模式")

        # 显示各类别的压缩情况
        print(f"\n📈 各类别压缩详情:")
        for rule_type in ["replace", "remove", "low_priority", "high_priority"]:
            if rule_type in rules:
                rule_data = rules[rule_type]
                rule_count = len(rule_data) if isinstance(rule_data, (list, dict)) else 0
                domain_count = self.category_domain_counts.get(rule_type, 0)
                if domain_count > 0 and rule_count > 0:
                    category_ratio = (rule_count / domain_count) * 100
                    print(f"  - {rule_type}: {category_ratio:.1f}% ({domain_count} 个域名 -> {rule_count} 条规则)")
                elif domain_count == 0 and rule_count == 0:
                    print(f"  - {rule_type}: 空 (0 个域名 -> 0 条规则)")
                else:
                    print(f"  - {rule_type}: {domain_count} 个域名 -> {rule_count} 条规则")

        print(f"\n🆕 v2ray 格式支持:")
        print(f"  - domain:example.com         # 匹配域名及其所有子域名")
        print(f"  - full:example.com           # 完全匹配指定域名")
        print(f"  - domain:example.com:@tag    # 带标签的域名规则")
        print(f"  - 标签信息会被记录但不影响域名匹配")
        print(f"  - 只有明确的端口号(纯数字)才会被移除")
        if self.stats.get('v2ray_with_tags', 0) > 0:
            print(f"  - 本次处理了 {self.stats.get('v2ray_with_tags', 0)} 个带标签的 v2ray 规则")

        print(f"\n🔧 原始结构保持:")
        print(f"  - 保持 www.example.com 的 www. 前缀")
        print(f"  - 保持子域名的完整结构")
        print(f"  - 只移除明确的协议和端口信息")
        print(f"  - v2ray 格式域名完全保持原始结构")

        print(f"\n📁 支持的文件格式:")
        print(f"  - domain: 纯域名格式 (每行一个域名)")
        print(f"  - regex: 正则表达式格式 (直接使用的正则)")
        print(f"  - ublock: uBlock Origin 格式")
        print(f"  - v2ray: v2ray 格式 (domain:example.com, full:example.com, domain:example.com:@tag)")
        print(f"  - replace: 替换格式 (old_domain=new_domain)")
        print(f"  - classify: 自动分类格式 (action:domain)")

        print(f"\n🔧 自动分类语法示例:")
        print(f"  - skip:csdn.net              # 从数据源跳过（但不阻止其他规则）")
        print(f"  - low_priority:csdn.net      # 添加到低优先级（会覆盖 skip）")
        print(f"  - remove:baidu.com           # 将 baidu.com 添加到移除列表")
        print(f"  - high_priority:wikipedia.org # 将 wikipedia.org 添加到高优先级列表")
        print(f"  - replace:youtube.com=yt.example.com # 替换规则")

        print(f"\n🔧 修复后的 Skip 规则行为:")
        print(f"  - skip:csdn.net - 只会从数据源的默认处理中跳过 csdn.net")
        print(f"  - low_priority:csdn.net - 会主动将 csdn.net 添加到低优先级列表")
        print(f"  - 如果同时存在，low_priority 规则会生效，skip 被覆盖")

        if self.stats.get('skip_overridden', 0) > 0:
            print(f"\n🔄 Skip 规则覆盖详情:")
            print(f"  - 有 {self.stats.get('skip_overridden', 0)} 个域名的 skip 规则被其他自动分类规则覆盖")
            print(f"  - 这意味着这些域名不会从数据源跳过，但会被添加到指定类别")
            print(f"  - 这正是期望的行为：明确的分类规则优先级高于 skip 规则")


def create_sample_config():
    """
    创建示例配置文件 (支持 v2ray 格式，保持原始结构)
    """
    sample_config = {
        "sources": [
            {
                "name": "Google Chinese Results Blocklist",
                "url": "https://raw.githubusercontent.com/cobaltdisco/Google-Chinese-Results-Blocklist/refs/heads/master/GHHbD_perma_ban_list.txt",
                "action": "remove",
                "format": "domain",
                "enabled": True
            },
            {
                "name": "Chinese Internet is Dead",
                "url": "https://raw.githubusercontent.com/obgnail/chinese-internet-is-dead/master/blocklist.txt",
                "action": "remove",
                "format": "ublock",
                "enabled": True
            },
            {
                "name": "Luxirty Search Block List",
                "url": "https://raw.githubusercontent.com/KoriIku/luxirty-search/refs/heads/main/docs/block_list.txt",
                "action": "remove",
                "format": "domain",
                "enabled": True
            },
            {
                "name": "Example v2ray Rules",
                "url": "https://example.com/v2ray-rules.txt",
                "action": "remove",
                "format": "v2ray",
                "enabled": False
            }
        ],

        "custom_rules": {
            "enabled": True,
            "sources": [
                {
                    "name": "Custom Remove Rules",
                    "file": "./custom_remove.txt",
                    "action": "remove",
                    "format": "domain",
                    "enabled": False
                },
                {
                    "name": "Custom Low Priority Rules",
                    "file": "./custom_low_priority.txt",
                    "action": "low_priority",
                    "format": "domain",
                    "enabled": False
                },
                {
                    "name": "Custom High Priority Rules",
                    "file": "./custom_high_priority.txt",
                    "action": "high_priority",
                    "format": "domain",
                    "enabled": False
                },
                {
                    "name": "Custom Replace Rules",
                    "file": "./custom_replace.txt",
                    "action": "replace",
                    "format": "replace",
                    "enabled": False
                },
                {
                    "name": "Custom v2ray Rules",
                    "file": "./custom_v2ray.txt",
                    "action": "remove",
                    "format": "v2ray",
                    "enabled": False
                }
            ]
        },

        "auto_classify": {
            "enabled": True,
            "sources": [
                {
                    "name": "Auto Classify Rules",
                    "file": "./auto_classify.txt",
                    "format": "classify",
                    "enabled": True
                }
            ],
            "rules": [
                "remove:example.com",
                "low_priority:google.com",
                "high_priority:wikipedia.org",
                "replace:youtube.com=yt.example.com",
                "skip:github.com"
            ]
        },

        "replace_rules": {
            '(.*\.)?youtube\.com$': 'yt.example.com',
            '(.*\.)?youtu\.be$': 'yt.example.com',
            '(.*\.)?reddit\.com$': 'teddit.example.com'
        },

        "fixed_remove": [
            '(.*\.)?facebook.com$'
        ],

        "fixed_low_priority": [
            '(.*\.)?google(\..*)?$'
        ],

        "fixed_high_priority": [
            '(.*\.)?wikipedia.org$'
        ],

        "parsing": {
            "ignore_specific_paths": True,
            "ignore_ip": True,
            "ignore_localhost": True,
            "strict_domain_level_check": True,
            "preserve_www_prefix": True,  # 保持 www. 前缀
            "preserve_original_structure": True  # 保持原始域名结构
        },

        "optimization": {
            "merge_domains": True,
            "max_domains_per_rule": 256,
            "group_by_tld": True,
            "use_trie_optimization": True,
            "max_rule_length": 65536,
            "optimize_tld_grouping": True,
            "enable_prefix_optimization": True,
            "enable_suffix_optimization": True,
            "min_common_prefix_length": 3,
            "min_common_suffix_length": 3,
            "force_single_regex": False,
            "sort_before_merge": True,
            "enable_advanced_tld_merge": True
        },

        "request_config": {
            "timeout": 30,
            "retry_count": 3,
            "retry_delay": 1
        },

        "output": {
            "mode": "separate_files",
            "directory": "./rules/",
            "files": {
                "replace": "rewrite-hosts.yml",
                "remove": "remove-hosts.yml",
                "low_priority": "low-priority-hosts.yml",
                "high_priority": "high-priority-hosts.yml",
                "main_config": "hostnames-config.yml"
            }
        }
    }

    with open("config.yaml", "w", encoding="utf-8") as f:
        yaml.dump(sample_config, f, default_flow_style=False, allow_unicode=True, indent=2)

    # 创建示例自动分类文件
    with open("auto_classify.txt", "w", encoding="utf-8") as f:
        f.write("""# 自动分类规则示例文件
# 语法：action:domain
# 支持的 action：remove, low_priority, high_priority, replace, skip

# 移除规则 - 将域名添加到移除列表
remove:baidu.com
remove:*.csdn.net
remove:zhihu.com

# 低优先级规则
low_priority:google.com
low_priority:*.google.com

# 高优先级规则
high_priority:wikipedia.org
high_priority:*.wikipedia.org
high_priority:www.wikipedia.org  # 会保持 www. 前缀

# 替换规则 - 格式：replace:old_domain=new_domain
replace:youtube.com=yt.example.com
replace:www.youtube.com=yt.example.com  # www 前缀会被保留在匹配中
replace:twitter.com=nitter.example.com

# 跳过规则 - 只跳过数据源处理，不阻止明确的自动分类规则
skip:github.com
skip:*.github.com
skip:stackoverflow.com

# 示例：同时有 skip 和 low_priority 规则
# skip 规则会被 low_priority 覆盖，域名会被添加到低优先级列表
skip:csdn.net
low_priority:csdn.net
""")

    # 创建示例自定义规则文件
    with open("custom_remove.txt", "w", encoding="utf-8") as f:
        f.write("""# 自定义移除规则示例
# 每行一个域名，支持注释

example1.com  # 示例域名1
example2.com  # 示例域名2
www.example3.com  # www 前缀会被保持
*.example4.com  # 示例通配符域名
""")

    with open("custom_replace.txt", "w", encoding="utf-8") as f:
        f.write("""# 自定义替换规则示例
# 格式：old_domain=new_domain

old.example.com=new.example.com
www.old.example.com=new.example.com
another.old.com=another.new.com
""")

    # 创建示例 v2ray 规则文件
    with open("custom_v2ray.txt", "w", encoding="utf-8") as f:
        f.write("""# v2ray 格式规则示例文件
# 支持的格式：
# domain:example.com     - 匹配域名及其所有子域名
# full:example.com       - 完全匹配指定域名
# domain:example.com:@tag - 带标签的域名规则

# 域名级别匹配（包括子域名）
domain:scopus.com
domain:researchgate.net
domain:academia.edu
domain:www.researchkit.cn  # www 前缀会被保持

# 完全匹配
full:scholar.google.ae
full:scholar.google.com.hk
full:pubmed.ncbi.nlm.nih.gov
full:www.scholar.google.com  # www 前缀会被保持

# 内容农场域名
domain:csdn.net
domain:jianshu.com
domain:zhihu.com
domain:www.cnblogs.com  # www 前缀会被保持

# 带标签的规则示例
domain:researchkit.cn:@cn  # 带地区标签
full:www.example.com:@test:@demo  # 多个标签
domain:academic.example.com:@academic:@high_priority  # 复合标签

# 注释示例
# domain:example.com  # 这是注释
""")

    print("示例配置文件已创建: config.yaml")
    print("示例自动分类文件已创建: auto_classify.txt")
    print("示例自定义规则文件已创建: custom_remove.txt, custom_replace.txt")
    print("🆕 示例 v2ray 规则文件已创建: custom_v2ray.txt")

    print("\n🆕 v2ray 格式说明:")
    print("  - domain:example.com         # 匹配域名及其所有子域名")
    print("  - full:example.com           # 完全匹配指定域名")
    print("  - domain:example.com:@tag    # 带标签的域名规则")
    print("  - 标签信息会被显示但不影响域名处理")
    print("  - 域名的原始结构(包括www前缀)完全保持")

    print("\n🔧 原始结构保持说明:")
    print("  - www.example.com 会保持 www. 前缀")
    print("  - sub.example.com 会保持完整的子域名结构")
    print("  - 只有明确的协议(http://)和端口号(:8080)才会被移除")
    print("  - v2ray 格式中的标签(:@tag)会被识别但不影响域名本身")

    print("\n🔄 修复后的自动分类语法说明:")
    print("  - skip:domain.com            # 只从数据源跳过，不阻止其他规则")
    print("  - remove:domain.com          # 将域名添加到移除列表")
    print("  - low_priority:domain.com    # 将域名添加到低优先级列表")
    print("  - high_priority:domain.com   # 将域名添加到高优先级列表")
    print("  - replace:old.com=new.com    # 替换规则")
    print("  - remove:*.domain.com        # 支持通配符匹配子域名")

    print("\n🔄 Skip 规则行为说明:")
    print("  - skip 只影响从数据源的默认处理")
    print("  - 如果同一域名有多个规则，明确的分类规则会覆盖 skip")
    print("  - 例如：skip:csdn.net + low_priority:csdn.net = csdn.net 被添加到低优先级")

    print("\n📁 支持的文件格式:")
    print("  - domain: 纯域名格式，每行一个域名")
    print("  - regex: 正则表达式格式，直接使用")
    print("  - ublock: uBlock Origin 格式")
    print("  - v2ray: v2ray 格式 (domain:example.com, full:example.com, domain:example.com:@tag)")
    print("  - replace: 替换格式，old_domain=new_domain")
    print("  - classify: 自动分类格式，action:domain")


def main():
    parser = argparse.ArgumentParser(description="SearXNG Hostnames 规则生成器 (完整版 - 自动分类 + 自定义文件 + TLD优化 + v2ray格式 - 保持原始结构) - Skip 修复版")
    parser.add_argument("-c", "--config", help="配置文件路径")
    parser.add_argument("--create-config", action="store_true", help="创建示例配置文件和示例规则文件")
    parser.add_argument("--single-regex", action="store_true", help="强制生成高级TLD优化的单行正则表达式")

    args = parser.parse_args()

    if args.create_config:
        create_sample_config()
        return

    generator = SearXNGHostnamesGenerator(args.config, force_single_regex=args.single_regex)
    generator.run()


if __name__ == "__main__":
    main()
