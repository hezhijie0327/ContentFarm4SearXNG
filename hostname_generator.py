#!/usr/bin/env python3
"""
SearXNG Hostnames 规则生成器 - 性能优化版
从多个云端配置文件中获取域名列表，生成 SearXNG hostnames 规则
修复了路径规则误判和域名提取的问题

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
        self.stats = {
            'total_rules': 0,
            'parsed_domains': 0,
            'ignored_with_path': 0,
            'invalid_domains': 0,
            'duplicate_domains': 0,
            'ignored_comments': 0
        }
        # 新增：记录每个类别的域名数量
        self.category_domain_counts = {
            'remove': 0,
            'low_priority': 0,
            'high_priority': 0,
            'replace': 0
        }

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
                    "name": "Chinese Internet is Dead",
                    "url": "https://raw.githubusercontent.com/obgnail/chinese-internet-is-dead/master/blocklist.txt",
                    "action": "remove",
                    "format": "ublock",
                    "enabled": True
                },
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
            ],
            # 域名替换规则
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
                "strict_domain_level_check": True  # 严格检查域名级别规则
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
                "directory": "./hostnames_rules/",
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

    def is_domain_level_rule(self, url_string: str) -> bool:
        """
        判断是否是域名级别的规则（而非特定路径规则）
        修复版本：更严格地检查路径规则

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
        修复版本：更好地处理路径规则

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
        这个函数更加谨慎，避免过度泛化
        
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

    def fetch_domain_list(self, url: str, format_type: str = "domain") -> Tuple[Set[str], Dict]:
        """
        从URL获取域名列表

        Args:
            url: 域名列表URL
            format_type: 格式类型，"domain" 或 "ublock"

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
            'ignored_comments': 0
        }

        retry_count = self.config["request_config"]["retry_count"]
        timeout = self.config["request_config"]["timeout"]
        retry_delay = self.config["request_config"]["retry_delay"]

        for attempt in range(retry_count):
            try:
                print(f"正在获取 {url} (尝试 {attempt + 1}/{retry_count})")

                headers = {
                    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
                }

                response = requests.get(url, timeout=timeout, headers=headers)
                response.raise_for_status()

                # 记录一些被忽略的规则用于调试
                ignored_samples = []
                accepted_samples = []
                comment_samples = []
                path_samples = []  # 新增：路径规则样本

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
                            if domain in domains:
                                stats['duplicate_domains'] += 1
                            else:
                                domains.add(domain)
                                stats['parsed_domains'] += 1
                                # 记录一些被接受的规则样本
                                if len(accepted_samples) < 3:
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
                                if len(ignored_samples) < 3:
                                    ignored_samples.append(line)

                    except Exception as e:
                        print(f"解析第 {line_num} 行时出错: {line[:50]}... - {e}")
                        stats['invalid_domains'] += 1
                        continue

                print(f"成功获取 {len(domains)} 个域名")
                print(f"  - 总规则: {stats['total_rules']}")
                print(f"  - 成功解析: {stats['parsed_domains']}")
                print(f"  - 忽略(特定路径): {stats['ignored_with_path']}")
                print(f"  - 忽略(注释): {stats['ignored_comments']}")
                print(f"  - 忽略(无效域名): {stats['invalid_domains']}")
                print(f"  - 重复域名: {stats['duplicate_domains']}")

                # 显示样本
                if accepted_samples:
                    print(f"  - 接受的规则样本:")
                    for sample in accepted_samples:
                        print(f"    ✓ {sample}")

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

        # 移除 www. 前缀
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

        # 如果所有域名基础部分都不包含点，说明都是二级域名，可以进行TLD优化
        if all('.' not in base for base in domain_bases):
            return f"({optimized_pattern})\\.{re.escape(tld)}"
        else:
            # 混合情况，有些是多级域名，直接使用完整域名
            return optimized_pattern

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
            'ignored_comments': 0
        }

        for source in self.config["sources"]:
            if not source.get("enabled", True):
                continue

            print(f"\n处理数据源: {source['name']}")
            format_type = source.get("format", "domain")
            print(f"格式类型: {format_type}")

            domains, source_stats = self.fetch_domain_list(source["url"], format_type)

            # 累加统计信息
            for key in self.stats:
                self.stats[key] += source_stats[key]

            action = source.get("action", "remove")
            if action in categorized_domains:
                categorized_domains[action].update(domains)
                print(f"已添加 {len(domains)} 个域名到 {action} 类别")
            else:
                print(f"警告: 未知的动作类型 '{action}'")

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

        # 收集域名
        categorized_domains = self.collect_domains()

        rules = {}

        # 替换规则 (字典格式)
        if self.config["replace_rules"]:
            rules["replace"] = self.config["replace_rules"]
            # 记录替换规则的域名数量（替换规则是键值对，键就是域名规则）
            self.category_domain_counts["replace"] = len(self.config["replace_rules"])

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

        # 保存各类规则到单独文件
        for rule_type, rule_data in rules.items():
            if rule_type in files_config and rule_data:
                filename = files_config[rule_type]
                filepath = os.path.join(output_dir, filename)

                try:
                    with open(filepath, 'w', encoding='utf-8') as f:
                        # 添加文件头注释
                        rule_count = len(rule_data) if isinstance(rule_data, (list, dict)) else 0
                        domain_count = self.category_domain_counts.get(rule_type, 0)

                        f.write(f"# SearXNG {rule_type} rules\n")
                        f.write(f"# Generated by SearXNG Hostnames Generator (Enhanced - Fixed Path Rules)\n")
                        f.write(f"# Total rules: {rule_count}\n")
                        f.write(f"# Total domains: {domain_count}\n")

                        if domain_count > 0 and rule_count > 0:
                            compression_ratio = (rule_count / domain_count) * 100
                            f.write(f"# Compression ratio: {compression_ratio:.1f}% ({domain_count} domains -> {rule_count} rules)\n")

                        # 根据是否启用单行正则显示不同注释
                        if self.force_single_regex or self.config["optimization"].get("force_single_regex", False):
                            f.write(f"# Advanced TLD-optimized single-line regex mode enabled\n")
                        else:
                            f.write(f"# Multi-rule performance optimized with advanced pattern matching\n")

                        f.write(f"# Note: Rules targeting specific paths are ignored to prevent over-blocking\n")
                        f.write(f"# Fixed: Improved path rule detection to avoid domain extraction issues\n")
                        f.write(f"# Smart domain sorting and TLD grouping applied for optimal performance\n\n")

                        # 直接写入规则内容，不包含顶级键
                        yaml.dump(rule_data, f, default_flow_style=False, allow_unicode=True, indent=2)

                    print(f"已保存 {rule_type} 规则到: {filepath}")

                    # 在主配置中引用外部文件
                    main_config["hostnames"][rule_type] = filename

                except Exception as e:
                    print(f"保存 {rule_type} 规则失败: {e}")

        # 保存主配置文件
        if main_config["hostnames"]:
            main_config_path = os.path.join(output_dir, files_config["main_config"])
            try:
                with open(main_config_path, 'w', encoding='utf-8') as f:
                    f.write("# SearXNG hostnames configuration\n")
                    f.write("# This file references external rule files\n")
                    f.write("# Generated by SearXNG Hostnames Generator (Enhanced - Fixed Path Rules)\n")

                    if self.force_single_regex or self.config["optimization"].get("force_single_regex", False):
                        f.write("# Advanced TLD-optimized single-line regex mode enabled\n")
                    else:
                        f.write("# Multi-rule performance optimized with advanced pattern matching\n")

                    f.write("# Fixed: Improved path rule detection to avoid CSDN-like issues\n")
                    f.write("# Smart domain sorting and TLD grouping applied\n\n")
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

        # 构建完整的 hostnames 配置
        hostnames_config = {"hostnames": rules}

        filepath = os.path.join(output_dir, "hostnames.yml")

        try:
            with open(filepath, 'w', encoding='utf-8') as f:
                f.write("# SearXNG hostnames configuration\n")
                f.write("# Generated by SearXNG Hostnames Generator (Enhanced - Fixed Path Rules)\n")

                # 添加总体统计信息
                total_rules = sum(len(rule_data) if isinstance(rule_data, (list, dict)) else 0 for rule_data in rules.values())
                total_domains = sum(self.category_domain_counts.values())
                f.write(f"# Total rules: {total_rules}\n")
                f.write(f"# Total domains: {total_domains}\n")

                if total_domains > 0 and total_rules > 0:
                    compression_ratio = (total_rules / total_domains) * 100
                    f.write(f"# Overall compression ratio: {compression_ratio:.1f}%\n")

                if self.force_single_regex or self.config["optimization"].get("force_single_regex", False):
                    f.write("# Advanced TLD-optimized single-line regex mode enabled\n")
                else:
                    f.write("# Multi-rule performance optimized with advanced pattern matching\n")

                f.write("# Note: Rules targeting specific paths are ignored to prevent over-blocking\n")
                f.write("# Fixed: Improved path rule detection to avoid CSDN-like domain extraction issues\n")
                f.write("# Smart domain sorting and TLD grouping applied for optimal performance\n\n")
                yaml.dump(hostnames_config, f, default_flow_style=False, allow_unicode=True, indent=2)

            print(f"已保存完整配置到: {filepath}")

        except Exception as e:
            print(f"保存配置失败: {e}")

    def run(self) -> None:
        """
        运行生成器
        """
        print("SearXNG Hostnames 规则生成器启动 (高级优化版 - 修复路径规则)")
        print("=" * 70)

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
        print("\n" + "=" * 60)
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
                if rule_type != "main_config" and rule_type in rules:
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
        for rule_type, rule_data in rules.items():
            if isinstance(rule_data, (list, dict)):
                rule_count = len(rule_data)
                domain_count = self.category_domain_counts.get(rule_type, 0)
                if domain_count > 0 and rule_count > 0:
                    category_ratio = (rule_count / domain_count) * 100
                    print(f"  - {rule_type}: {category_ratio:.1f}% ({domain_count} 个域名 -> {rule_count} 条规则)")

        print(f"\n🔧 修复说明:")
        print(f"  - 修复了路径规则误判问题，如 '*://*.csdn.net/tags/*' 现在会被正确忽略")
        print(f"  - 改进了域名提取逻辑，避免从路径规则中错误提取主域名")
        print(f"  - 启用了严格的域名级别检查，提高规则生成的准确性")


def create_sample_config():
    """
    创建示例配置文件
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
                "name": "Custom Blocklist",
                "url": "https://example.com/blocklist.txt",
                "action": "remove",
                "format": "domain",
                "enabled": False
            }
        ],
        "replace_rules": {
            '(.*\.)?youtube\.com$': 'yt.example.com',
            '(.*\.)?youtu\.be$': 'yt.example.com',
            '(.*\.)?reddit\.com$': 'teddit.example.com',
            '(.*\.)?redd\.it$': 'teddit.example.com',
            '(www\.)?twitter\.com$': 'nitter.example.com'
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
            "strict_domain_level_check": True  # 新增：严格检查域名级别规则
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
            "directory": "./hostnames_rules/",
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

    print("示例配置文件已创建: config.yaml")


def main():
    parser = argparse.ArgumentParser(description="SearXNG Hostnames 规则生成器 (高级优化版 - 修复路径规则)")
    parser.add_argument("-c", "--config", help="配置文件路径")
    parser.add_argument("--create-config", action="store_true", help="创建示例配置文件")
    parser.add_argument("--single-regex", action="store_true", help="强制生成高级TLD优化的单行正则表达式（将所有域名合并为一个规则）")

    args = parser.parse_args()

    if args.create_config:
        create_sample_config()
        return

    generator = SearXNGHostnamesGenerator(args.config, force_single_regex=args.single_regex)
    generator.run()


if __name__ == "__main__":
    main()
