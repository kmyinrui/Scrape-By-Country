import asyncio
import aiohttp
import json
import re
import logging
from bs4 import BeautifulSoup
import os
import shutil
from datetime import datetime
import pytz
import base64
from urllib.parse import parse_qs, unquote
import platform
import time

# --- 配置常量 ---
# 获取当前脚本所在目录的绝对路径
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
# 配置文件夹路径（使用绝对路径，确保在任何位置运行都能正确找到配置文件）
CONFIG_DIR = SCRIPT_DIR
# 输入文件路径（使用绝对路径）
URLS_FILE = os.path.join(CONFIG_DIR, 'urls.txt')
KEYWORDS_FILE = os.path.join(CONFIG_DIR, 'keywords.json') # 应包含国家的两字母代码
# 输出文件夹路径（使用绝对路径，基于脚本所在目录的父目录）
OUTPUT_DIR = os.path.join(os.path.dirname(SCRIPT_DIR), 'output_configs')
COUNTRY_SUBDIR = 'countries'  # 国家配置文件夹
PROTOCOL_SUBDIR = 'protocols' # 协议配置文件夹
README_FILE = os.path.join(os.path.dirname(SCRIPT_DIR), 'README.md')
UPDATE_LOG_FILE = os.path.join(os.path.dirname(SCRIPT_DIR), 'update_log.txt')  # 每日更新日志文件，放在项目根目录中
REQUEST_TIMEOUT = 15
CONCURRENT_REQUESTS = 10
MAX_CONFIG_LENGTH = 5000  # 增加最大配置长度，允许更长的节点信息
MIN_PERCENT25_COUNT = 50  # 增加URL编码阈值，减少误过滤
FILTERED_PHRASE = 'i_love_'  # 要过滤的特定短语，保持不变

# --- Logging Setup ---
logging.basicConfig(level=logging.INFO,
                    format='%(asctime)s - %(levelname)s - %(message)s')

# --- 协议类别 ---  
PROTOCOL_CATEGORIES = [
    "Vmess", "Vless", "Trojan", "ShadowSocks", "ShadowSocksR",
    "Tuic", "Hysteria2", "WireGuard", "Hysteria", "Hysteria1"
]
# 预编译协议前缀列表，提高性能
PROTOCOL_PREFIXES = [p.lower() + "://" for p in PROTOCOL_CATEGORIES]

# 配置常量定义

# --- 检查非英语文本的辅助函数 ---
def is_non_english_text(text):
    """检查文本是否包含非英语字符（如波斯语、阿拉伯语等特殊字符）"""
    if not isinstance(text, str) or not text.strip():
        return False
    
    # 定义非拉丁字符范围，但排除常见的国家名称和代码可能使用的字符
    # 我们需要更精确地识别真正需要过滤的字符
    problematic_char_ranges = [
        ('\u0600', '\u06FF'),  # 阿拉伯语及波斯语
        ('\u0750', '\u077F'),  # 阿拉伯文补充
        ('\u08A0', '\u08FF'),  # 阿拉伯文扩展-A
    ]
    
    # 检查是否包含问题字符
    for char in text:
        # 只检查真正可能导致问题的字符范围
        for start, end in problematic_char_ranges:
            if start <= char <= end:
                return True
    
    # 只过滤零宽连接符等真正的问题字符
    problematic_chars = ['\u200C', '\u200D']  # 零宽连接符
    for char in text:
        if char in problematic_chars:
            return True
    
    # 保留常见的国家名称字符，包括中文、日语、韩语等
    # 这些字符对于国家识别很重要，不应该被过滤
    return False

# --- Base64 Decoding Helper ---
def decode_base64(data):
    """安全地解码Base64字符串，处理URL安全的Base64格式"""
    if not data or not isinstance(data, str):
        return None
    try:
        # 替换URL安全的Base64字符
        data = data.replace('_', '/').replace('-', '+')
        # 添加必要的填充
        missing_padding = len(data) % 4
        if missing_padding:
            data += '=' * (4 - missing_padding)
        return base64.b64decode(data).decode('utf-8')
    except Exception:
        return None

# --- 协议名称提取辅助函数 ---
def get_vmess_name(vmess_config):
    """
    从VMess配置中提取名称信息
    参数:
        vmess_config: VMess配置字符串
    返回:
        提取的名称字符串或None
    """
    try:
        # 确保输入是字符串
        if not isinstance(vmess_config, str) or not vmess_config.startswith('vmess://'):
            return None
        
        # 移除前缀
        encoded_part = vmess_config[8:]
        
        # 尝试解码
        try:
            # 添加必要的填充
            padded = encoded_part + '=' * ((4 - len(encoded_part) % 4) % 4)
            decoded = base64.b64decode(padded).decode('utf-8')
        except Exception:
            # 如果标准解码失败，尝试URL解码后再base64解码
            try:
                encoded_part = unquote(encoded_part)
                padded = encoded_part + '=' * ((4 - len(encoded_part) % 4) % 4)
                decoded = base64.b64decode(padded).decode('utf-8')
            except Exception:
                return None
        
        # 解析JSON并尝试获取名称
        try:
            vmess_data = json.loads(decoded)
            # 尝试从不同字段获取名称
            for name_field in ['ps', 'name', 'remarks', 'tag']:
                if name_field in vmess_data and isinstance(vmess_data[name_field], str):
                    return vmess_data[name_field].strip()
        except Exception:
            return None
        
        return None
    except Exception:
        return None

def get_ssr_name(ssr_config):
    """
    从SSR配置中提取名称信息
    参数:
        ssr_config: SSR配置字符串
    返回:
        提取的名称字符串或None
    """
    try:
        # 确保输入是字符串
        if not isinstance(ssr_config, str) or not ssr_config.startswith('ssr://'):
            return None
        
        # 移除前缀
        encoded_part = ssr_config[6:]
        
        # 尝试解码
        try:
            # 添加必要的填充
            padded = encoded_part + '=' * ((4 - len(encoded_part) % 4) % 4)
            decoded = base64.b64decode(padded).decode('utf-8')
        except Exception:
            # 如果标准解码失败，尝试URL解码后再base64解码
            try:
                encoded_part = unquote(encoded_part)
                padded = encoded_part + '=' * ((4 - len(encoded_part) % 4) % 4)
                decoded = base64.b64decode(padded).decode('utf-8')
            except Exception:
                return None
        
        # SSR格式: server:port:protocol:method:obfs:password_base64/?params
        parts = decoded.split('/?')
        if len(parts) < 2:
            return None
            
        # 解析参数部分并获取remarks
        params = parse_qs(parts[1])
        if 'remarks' in params:
            try:
                remarks_encoded = params['remarks'][0]
                # 解码remarks
                padded_remarks = remarks_encoded + '=' * ((4 - len(remarks_encoded) % 4) % 4)
                return base64.b64decode(padded_remarks).decode('utf-8', errors='ignore')
            except Exception:
                return None
        
        return None
    except Exception:
        return None

def get_trojan_name(trojan_config):
    """
    从Trojan配置中提取名称信息
    参数:
        trojan_config: Trojan配置字符串
    返回:
        提取的名称字符串或None
    """
    try:
        # 确保输入是字符串
        if not isinstance(trojan_config, str) or not trojan_config.startswith('trojan://'):
            return None
        
        # Trojan URL 格式: trojan://password@hostname:port#name
        # 检查是否有 # 后的名称部分
        if '#' in trojan_config:
            try:
                name_part = trojan_config.split('#', 1)[1]
                return unquote(name_part).strip()
            except Exception:
                pass
        
        # 尝试从URL路径或查询参数中提取名称
        parts = trojan_config.split('?')
        if len(parts) > 1:
            try:
                params = parse_qs(parts[1])
                for name_key in ['name', 'remarks', 'ps']:
                    if name_key in params:
                        return unquote(params[name_key][0]).strip()
            except Exception:
                pass
        
        return None
    except Exception:
        return None

def get_vless_name(vless_config):
    """
    从VLESS配置中提取名称信息
    参数:
        vless_config: VLESS配置字符串
    返回:
        提取的名称字符串或None
    """
    try:
        # 确保输入是字符串
        if not isinstance(vless_config, str) or not vless_config.startswith('vless://'):
            return None
        
        # 检查是否有 # 后的名称部分
        if '#' in vless_config:
            try:
                name_part = vless_config.split('#', 1)[1]
                return unquote(name_part).strip()
            except Exception:
                pass
        
        # 尝试从URL查询参数中提取名称
        parts = vless_config.split('?')
        if len(parts) > 1:
            try:
                params = parse_qs(parts[1])
                for name_key in ['name', 'remarks', 'ps']:
                    if name_key in params:
                        return unquote(params[name_key][0]).strip()
            except Exception:
                pass
        
        return None
    except Exception:
        return None

def get_shadowsocks_name(ss_config):
    """
    从Shadowsocks配置中提取名称信息
    参数:
        ss_config: Shadowsocks配置字符串
    返回:
        提取的名称字符串或None
    """
    try:
        # 确保输入是字符串
        if not isinstance(ss_config, str) or not ss_config.startswith('ss://'):
            return None
        
        # 检查是否有 # 后的名称部分
        if '#' in ss_config:
            try:
                name_part = ss_config.split('#', 1)[1]
                return unquote(name_part).strip()
            except Exception:
                pass
        
        return None
    except Exception:
        return None

# --- New Filter Function ---
def should_filter_config(config, filter_stats):
    """根据特定规则过滤无效或低质量的配置，并收集过滤统计信息"""
    if not config or not isinstance(config, str):
        filter_stats['format'] += 1
        return True
    
    # 检查是否包含过滤短语
    if FILTERED_PHRASE in config.lower():
        filter_stats['format'] += 1
        return True
    
    # 修复URL编码检查逻辑
    percent25_count = config.count('%25')
    if percent25_count >= MIN_PERCENT25_COUNT:
        filter_stats['url_encoding'] += 1
        logging.debug(f"配置被过滤: URL编码过度 ({percent25_count} 个 %25)")
        return True
    
    # 使用更大的长度限制，减少误过滤
    if len(config) >= MAX_CONFIG_LENGTH:
        filter_stats['length'] += 1
        logging.debug(f"配置被过滤: 长度超过限制 ({len(config)} 字符)")
        return True
    
    # 使用更全面的协议关键词列表，确保新添加的协议类型也能被识别
    common_protocol_keywords = ['vmess', 'vless', 'trojan', 'ss://', 'ssr://', 
                               'tuic', 'hy2', 'wireguard', 'hysteria', 'hysteria1']
    
    # 优化协议关键词检查逻辑，使用更高效的集合查找
    config_lower = config.lower()
    has_protocol_keyword = any(keyword in config_lower for keyword in common_protocol_keywords)
    
    # 如果没有找到协议关键词，但配置看起来像URL，也保留
    if not has_protocol_keyword and ('://' in config):
        has_protocol_keyword = True
    
    # 修复返回值与函数名的一致性问题
    # should_filter_config 应该返回 True 表示需要过滤，False 表示保留
    if not has_protocol_keyword:
        filter_stats['protocol'] += 1
        return True
    
    return False

# 移除V2Ray兼容检查函数

async def fetch_url(session, url, response_times_sum, response_times_count, response_times, error_stats):
    """异步获取URL内容并提取文本，同时收集响应时间数据"""
    start_time = datetime.now()
    try:
        async with session.get(url, timeout=REQUEST_TIMEOUT) as response:
            response.raise_for_status()
            # 计算响应时间
            end_time = datetime.now()
            response_time = (end_time - start_time).total_seconds()
            
            # 更新响应时间统计
            if response_time > 0:
                response_times_sum[0] += response_time  # 使用列表作为可变对象传递
                response_times_count[0] += 1
                response_times['max'] = max(response_times['max'], response_time)
                response_times['min'] = min(response_times['min'], response_time)
            
            # 尝试处理不同的内容类型
            content_type = response.headers.get('Content-Type', '')
            
            # 如果是JSON内容，直接处理
            if 'application/json' in content_type:
                try:
                    json_data = await response.json()
                    # 将JSON转换为字符串以方便后续处理
                    text_content = json.dumps(json_data, ensure_ascii=False)
                    logging.debug(f"处理JSON内容: {url}")
                except json.JSONDecodeError:
                    # 如果无法解析为JSON，回退到文本处理
                    html = await response.text()
                    soup = BeautifulSoup(html, 'html.parser')
                    text_content = soup.get_text(separator='\n', strip=True)
            else:
                # 处理HTML或纯文本
                html = await response.text()
                soup = BeautifulSoup(html, 'html.parser')
                
                # 优先从代码相关标签提取内容
                text_content = ""
                code_elements = soup.find_all(['pre', 'code'])
                if code_elements:
                    for element in code_elements:
                        text_content += element.get_text(separator='\n', strip=True) + "\n"
                
                # 如果没有足够的代码内容，再提取其他文本元素
                if not text_content or len(text_content) < 100:
                    for element in soup.find_all(['p', 'div', 'li', 'span', 'td']):
                        text_content += element.get_text(separator='\n', strip=True) + "\n"
                
                # 最后的备用方案
                if not text_content: 
                    text_content = soup.get_text(separator=' ', strip=True)
                    
            # 修复日志级别，使用debug而不是info，避免日志过于冗长
            logging.debug(f"成功获取: {url}")
            return url, text_content
    except asyncio.TimeoutError:
        error_stats['url_request'] += 1
        logging.warning(f"请求超时: {url}")
    except aiohttp.ClientError as e:
        error_stats['url_request'] += 1
        logging.warning(f"客户端错误获取URL: {url} - {e}")
    except Exception as e:
        error_stats['url_request'] += 1
        logging.warning(f"获取URL时发生意外错误: {url} - {e}")
    return url, None

def find_matches(text, categories_data):
    """根据正则表达式模式在文本中查找匹配项，优化内存使用"""
    if not text or not isinstance(text, str):
        return {}
        
    # 只初始化有模式的类别，节省内存
    matches = {}
    
    for category, patterns in categories_data.items():
        # 只处理非空的模式列表
        if not patterns or not isinstance(patterns, list):
            continue
            
        category_matches = set()
        
        for pattern_str in patterns:
            if not isinstance(pattern_str, str):
                continue
                
            try:
                # 使用预编译的协议前缀列表提高性能
                is_protocol_pattern = any(proto_prefix in pattern_str.lower() for proto_prefix in PROTOCOL_PREFIXES)
                
                if category in PROTOCOL_CATEGORIES or is_protocol_pattern:
                    # 优化正则表达式性能，避免同时使用过多标志
                    # 移除DOTALL标志以减少匹配范围，提高性能
                    pattern = re.compile(pattern_str, re.IGNORECASE | re.MULTILINE)
                    found = pattern.findall(text)
                    
                    if found:
                        # 清理并去重匹配结果
                        for item in found:
                            if item and isinstance(item, str):
                                cleaned_item = item.strip()
                                if cleaned_item:
                                    category_matches.add(cleaned_item)
                                    # 如果匹配项数量过大，实际上限制数量以避免内存问题
                                    if len(category_matches) > 10000:
                                        logging.warning(f"类别 {category} 的匹配项超过10000，已停止添加更多匹配项")
                                        break  # 跳出item循环
                        if len(category_matches) > 10000:
                            break  # 跳出pattern循环
            except re.error as e:
                logging.error(f"正则表达式错误 - 模式 '{pattern_str}' 在类别 '{category}': {e}")
                continue
        
        if category_matches:
            matches[category] = category_matches
    
    # 直接返回匹配结果，不再进行额外过滤
    return matches

def save_to_file(directory, category_name, items_set, error_stats=None):
    """将项目集合保存到指定目录的文本文件中"""
    if error_stats is None:
        error_stats = {'file_save': 0}
        
    if not items_set:
        logging.debug(f"跳过空集合的保存: {category_name}")
        return False, 0
        
    # 确保目录存在
    try:
        # 使用绝对路径确保文件位置正确
        directory_abs = os.path.abspath(directory)
        os.makedirs(directory_abs, exist_ok=True)
        file_path = os.path.join(directory_abs, f"{category_name}.txt")
        count = len(items_set)
        
        # 写入排序后的项目，每行一个
        with open(file_path, 'w', encoding='utf-8') as f:
            for item in sorted(list(items_set)): 
                f.write(f"{item}\n")
        
        logging.info(f"已保存 {count} 项到 {file_path}")
        return True, count
    except IOError as e:
        error_stats['file_save'] += 1
        logging.error(f"写入文件失败 {file_path}: {e}")
        return False, 0
    except Exception as e:
        error_stats['file_save'] += 1
        logging.error(f"保存文件时发生未知错误 {file_path}: {e}")
        return False, 0

# --- 使用旗帜图像生成简单的README函数 ---
def generate_simple_readme(protocol_counts, country_counts, all_keywords_data, use_local_paths=True):
    """生成README.md文件，展示抓取结果统计信息"""
    # 确保输入参数是字典类型
    if not isinstance(protocol_counts, dict):
        protocol_counts = {}
    if not isinstance(country_counts, dict):
        country_counts = {}
    
    # 确保使用正确的当前时间
    tz = pytz.timezone('Asia/Shanghai')
    # 使用datetime.now()获取系统当前时间，并应用正确的时区
    now = datetime.now(tz)
    timestamp = now.strftime("%Y-%m-%d %H:%M:%S %Z")
    logging.info(f"生成README时的当前时间戳: {timestamp}")
    
    # 计算统计信息
    total_protocol_configs = sum(protocol_counts.values())
    total_country_configs = sum(country_counts.values())
    countries_with_data = len(country_counts)
    protocols_with_data = len(protocol_counts)

    # 构建子目录的路径
    if use_local_paths:
        # 使用相对于README文件的路径
        protocol_base_url = f"{os.path.basename(OUTPUT_DIR)}/{PROTOCOL_SUBDIR}"
        country_base_url = f"{os.path.basename(OUTPUT_DIR)}/{COUNTRY_SUBDIR}"
    else:
        # 使用raw.githubusercontent.com格式的URL，确保与代码中定义的格式一致
        github_repo_path = "Eleven1985/Scrape-By-Country"  # 更新为正确的仓库路径
        github_branch = "main"
        # 使用标准的raw.githubusercontent.com格式，不带/refs/heads/部分
        protocol_base_url = f"https://raw.githubusercontent.com/{github_repo_path}/{github_branch}/{os.path.basename(OUTPUT_DIR)}/{PROTOCOL_SUBDIR}"
        country_base_url = f"https://raw.githubusercontent.com/{github_repo_path}/{github_branch}/{os.path.basename(OUTPUT_DIR)}/{COUNTRY_SUBDIR}"

    md_content = f"# 📊 提取结果 (最后更新: {timestamp})\n\n"
    md_content += "此文件是自动生成的。\n\n"
    md_content += f"## 📋 统计概览\n\n"
    md_content += f"- **配置总数**: {total_protocol_configs}\n"
    md_content += f"- **有数据的协议数**: {protocols_with_data}\n"
    md_content += f"- **国家相关配置数**: {total_country_configs}\n"
    md_content += f"- **有配置的国家数**: {countries_with_data}\n\n"
    
    md_content += "## ℹ️ 说明\n\n"
    md_content += "国家文件仅包含在**配置名称**中找到国家名称/旗帜的配置。配置名称首先从链接的`#`部分提取，如果不存在，则从内部名称(对于Vmess/SSR)提取。\n\n"
    md_content += "所有输出文件已按类别整理到不同目录中，便于查找和使用。\n\n"

    md_content += "## 📁 协议文件\n\n"
    if protocol_counts:
        md_content += "| 协议 | 总数 | 链接 |\n"
        md_content += "|---|---|---|\n"
        for category_name, count in sorted(protocol_counts.items()):
            file_link = f"{protocol_base_url}/{category_name}.txt"
            # 确保URL不包含/refs/heads/部分
            file_link = file_link.replace("/refs/heads/", "/")
            md_content += f"| {category_name} | {count} | [`{category_name}.txt`]({file_link}) |\n"
    else:
        md_content += "没有找到协议配置。\n"
    md_content += "\n"

    md_content += "## 🌍 国家文件 (包含配置)\n\n"
    if country_counts:
        md_content += "| 国家 | 相关配置数量 | 链接 |\n"
        md_content += "|---|---|---|\n"
        for country_category_name, count in sorted(country_counts.items()):
            flag_image_markdown = "" # 用于保存旗帜图像HTML标签
            
            # 查找国家的两字母ISO代码用于旗帜图像URL
            if country_category_name in all_keywords_data:
                keywords_list = all_keywords_data[country_category_name]
                if keywords_list and isinstance(keywords_list, list):
                    for item in keywords_list:
                        if isinstance(item, str) and len(item) == 2 and item.isupper() and item.isalpha():
                            iso_code_lowercase_for_url = item.lower()
                            # 使用flagcdn.com，宽度为20像素
                            flag_image_url = f"https://flagcdn.com/w20/{iso_code_lowercase_for_url}.png"
                            flag_image_markdown = f'<img src="{flag_image_url}" width="20" alt="{country_category_name} flag">'
                            break 

            # 为"国家"列构建最终文本
            display_parts = []
            # 如果旗帜图像标签已创建
            if flag_image_markdown:
                display_parts.append(flag_image_markdown)
            
            display_parts.append(country_category_name) # 原始名称 (键)
            
            country_display_text = " ".join(display_parts)
            
            file_link = f"{country_base_url}/{country_category_name}.txt"
            # 确保URL不包含/refs/heads/部分
            file_link = file_link.replace("/refs/heads/", "/")
            link_text = f"{country_category_name}.txt"
            md_content += f"| {country_display_text} | {count} | [`{link_text}`]({file_link}) |\n"
    else:
        md_content += "没有找到与国家相关的配置。\n"
    md_content += "\n"

    try:
        # 使用绝对路径确保文件写入正确位置
        readme_abs_path = os.path.abspath(README_FILE)
        with open(readme_abs_path, 'w', encoding='utf-8') as f:
            f.write(md_content)
        logging.info(f"成功生成 {readme_abs_path}")
        
        # 更新README文件所在目录的时间戳
        try:
            readme_dir = os.path.dirname(readme_abs_path) or '.'
            os.utime(readme_dir)
            logging.debug(f"已更新README文件所在目录的修改时间: {os.path.abspath(readme_dir)}")
        except Exception as dir_e:
            logging.warning(f"更新README目录时间失败: {dir_e}")
            
    except Exception as e:
        logging.error(f"写入 {README_FILE} 失败: {e}")

# main函数和其他函数实现
async def main():
    """主函数，协调整个抓取和处理流程"""
    # 确保配置文件夹存在（CONFIG_DIR现在是脚本所在目录，应该已经存在）
    # 但仍然检查一下确保它是一个目录
    if not os.path.isdir(CONFIG_DIR):
        logging.critical(f"配置文件夹 '{CONFIG_DIR}' 不是一个有效的目录")
        return
        
    # 检查必要的输入文件是否存在（使用绝对路径）
    urls_file_abs = os.path.abspath(URLS_FILE)
    keywords_file_abs = os.path.abspath(KEYWORDS_FILE)
    
    if not os.path.exists(urls_file_abs) or not os.path.exists(keywords_file_abs):
        missing_files = []
        if not os.path.exists(urls_file_abs):
            missing_files.append(f"URLs文件: {urls_file_abs}")
        if not os.path.exists(keywords_file_abs):
            missing_files.append(f"关键词文件: {keywords_file_abs}")
        
        config_dir_abs = os.path.abspath(CONFIG_DIR)
        logging.critical(f"未找到输入文件:\n- {chr(10)}- ".join(missing_files))
        logging.info(f"请确保这些文件已放在 {config_dir_abs} 文件夹中")
        return

    # 加载URL和关键词数据
    try:
        with open(URLS_FILE, 'r', encoding='utf-8') as f:
            urls = [line.strip() for line in f if line.strip()]
            
        if not urls:
            logging.critical("URLs文件为空，没有要抓取的URL。")
            return
            
        logging.info(f"已从 {urls_file_abs} 加载 {len(urls)} 个URL")
        
        with open(keywords_file_abs, 'r', encoding='utf-8') as f:
            categories_data = json.load(f)
            
        # 验证categories_data是字典类型
        if not isinstance(categories_data, dict):
            logging.critical("keywords.json必须包含字典格式的数据。")
            return
            
        # 验证协议类别是否在配置中
        missing_protocols = [p for p in PROTOCOL_CATEGORIES if p not in categories_data]
        if missing_protocols:
            logging.warning(f"keywords.json中缺少以下协议类别的配置: {', '.join(missing_protocols)}")
            
        # 验证每个值都是列表
        invalid_entries = [(k, v) for k, v in categories_data.items() if not isinstance(v, list)]
        if invalid_entries:
            logging.warning(f"keywords.json包含非列表格式的值: {invalid_entries}")
            # 过滤掉非列表的值
            categories_data = {k: v for k, v in categories_data.items() if isinstance(v, list)}
            
        if not categories_data:
            logging.critical("keywords.json中没有有效的类别数据。")
            return
            
    except json.JSONDecodeError as e:
        logging.critical(f"解析keywords.json文件失败: {e}")
        return
    except IOError as e:
        logging.critical(f"读取输入文件时出错: {e}")
        return

    # 分离协议模式和国家关键词
    # 确保所有PROTOCOL_CATEGORIES中的协议都能被识别，即使在keywords.json中没有定义
    protocol_patterns_for_matching = {}
    country_keywords_for_naming = {}
    
    for cat, patterns in categories_data.items():
        if cat in PROTOCOL_CATEGORIES:
            protocol_patterns_for_matching[cat] = patterns
        else:
            country_keywords_for_naming[cat] = patterns
    
    # 确保所有协议类别都有对应的模式
    for protocol in PROTOCOL_CATEGORIES:
        if protocol not in protocol_patterns_for_matching:
            # 为没有模式的协议添加基本匹配模式
            base_pattern = [f"{protocol.lower()}://[^\n\r<\"']+"]
            protocol_patterns_for_matching[protocol] = base_pattern
            logging.debug(f"为协议 {protocol} 添加基本匹配模式")
    
    country_category_names = list(country_keywords_for_naming.keys())

    logging.info(f"已加载 {len(urls)} 个URL和 "
                 f"{len(categories_data)} 个总类别从keywords.json。")

    # 初始化统计变量
    success_count = 0
    processed_pages = 0
    found_configs = 0
    filtered_out_configs = 0
    
    # 初始化增强日志所需的统计数据
    response_times = {'max': 0, 'min': float('inf')}
    response_times_sum = [0]  # 使用列表作为可变对象传递
    response_times_count = [0]  # 使用列表作为可变对象传递
    
    filter_stats = {
        'url_encoding': 0,
        'length': 0,
        'protocol': 0,
        'format': 0
    }
    
    error_stats = {
        'url_request': 0,
        'config_parse': 0,
        'file_save': 0,
        'dir_create': 0
    }
    
    resource_stats = {
        'memory': 'N/A',
        'cpu': 'N/A'
    }
    
    execution_time = {
        'start': datetime.now(),
        'total': 'N/A'
    }
    
    # 异步获取所有页面
    sem = asyncio.Semaphore(CONCURRENT_REQUESTS)  # 限制并发请求数
    
    async def fetch_with_semaphore(session, url_to_fetch):
        """使用信号量限制并发的fetch_url，并传递统计参数"""
        async with sem:
            return await fetch_url(session, url_to_fetch, response_times_sum, response_times_count, response_times, error_stats)
    
    # 创建HTTP会话并执行所有获取任务
    async with aiohttp.ClientSession() as session:
        logging.info(f"开始获取 {len(urls)} 个URLs (最大并发: {CONCURRENT_REQUESTS})...")
        fetched_pages = await asyncio.gather(
            *[fetch_with_semaphore(session, u) for u in urls],
            return_exceptions=True  # 即使某些任务失败也继续执行
        )
        
        # 过滤出成功获取的页面并统计失败情况
        success_count = 0
        exception_count = 0
        filtered_pages = []
        
        for result in fetched_pages:
            if isinstance(result, tuple) and len(result) == 2 and isinstance(result[0], str) and result[1] is not None:
                filtered_pages.append(result)
                success_count += 1
            elif isinstance(result, Exception):
                exception_count += 1
                logging.warning(f"URL获取任务异常: {type(result).__name__}: {result}")
            else:
                logging.debug(f"无效的URL获取结果: {type(result)}")
        
        fetched_pages = filtered_pages
        logging.info(f"URL获取完成: 成功 {success_count}, 异常 {exception_count}, 总计 {len(filtered_pages)} 个页面待处理")

    # 初始化结果集合
    # 修复潜在的空集合引用问题
    final_configs_by_country = {}
    final_all_protocols = {}
    
    # 确保所有国家类别都有对应的集合
    for cat in country_category_names:
        final_configs_by_country[cat] = set()
    
    # 确保所有协议类别都有对应的集合
    for cat in PROTOCOL_CATEGORIES:
        final_all_protocols[cat] = set()

    logging.info("处理页面并关联配置名称...")
    
    # 统计成功处理的页面数量
    processed_pages = 0
    found_configs = 0
    filtered_out_configs = 0
    
    for url, text in fetched_pages:
        if not text:
            continue
            
        processed_pages += 1
        page_protocol_matches = find_matches(text, protocol_patterns_for_matching)
        all_page_configs_after_filter = set()
        
        # 处理找到的协议配置
        page_filtered_count = 0
        for protocol_cat_name, configs_found in page_protocol_matches.items():
            # 检查是否是带有Grpc后缀的协议，如果是则归类到基础协议
            base_protocol = protocol_cat_name
            if protocol_cat_name.endswith('Grpc'):
                base_protocol = protocol_cat_name[:-4]  # 移除Grpc后缀
                
            # 确保使用的是有效的协议类别
            if base_protocol in PROTOCOL_CATEGORIES:
                for config in configs_found:
                    if not should_filter_config(config, filter_stats):
                        all_page_configs_after_filter.add(config)
                        final_all_protocols[base_protocol].add(config)
                    else:
                        page_filtered_count += 1
        
        found_configs += len(all_page_configs_after_filter)
        filtered_out_configs += page_filtered_count
        
        # 每10个页面输出一次进度
        if processed_pages % 10 == 0:
            logging.info(f"处理进度: {processed_pages}/{len(fetched_pages)} 页面, " \
                      f"已找到 {found_configs} 配置, 已过滤 {filtered_out_configs} 配置")

        # 为每个配置关联国家信息
        for config in all_page_configs_after_filter:
            name_to_check = None
            
            # 1. 首先尝试从URL片段中提取名称（#后面的部分）
            if '#' in config:
                try:
                    potential_name = config.split('#', 1)[1]
                    name_to_check = unquote(potential_name).strip()
                    if not name_to_check:
                        name_to_check = None
                except (IndexError, Exception) as e:
                    logging.debug(f"从URL片段提取名称失败: {e}")

            # 2. 如果URL片段中没有名称，尝试从协议特定字段提取
            if not name_to_check:
                if config.startswith('ssr://'):
                    name_to_check = get_ssr_name(config)
                elif config.startswith('vmess://'):
                    name_to_check = get_vmess_name(config)
                elif config.startswith('trojan://'):
                    name_to_check = get_trojan_name(config)
                elif config.startswith('vless://'):
                    name_to_check = get_vless_name(config)
                elif config.startswith('ss://'):
                    name_to_check = get_shadowsocks_name(config)
                # 其他协议的名称提取支持

            # 如果无法获取名称，跳过此配置
            if not name_to_check or not isinstance(name_to_check, str):
                continue
                
            current_name_to_check_str = name_to_check.strip()

            # 遍历每个国家的关键词列表，寻找匹配
            for country_name_key, keywords_for_country_list in country_keywords_for_naming.items():
                # 只处理有效的关键词列表
                if not isinstance(keywords_for_country_list, list):
                    continue
                    
                # 准备此国家的文本关键词，保留所有有效的关键词
                text_keywords_for_country = []
                for kw in keywords_for_country_list:
                    if isinstance(kw, str) and kw.strip():
                        # 只添加唯一的有效关键词
                        if kw not in text_keywords_for_country:
                            text_keywords_for_country.append(kw)
                
                # 检查是否匹配任何关键词
                match_found = False
                current_name_lower = current_name_to_check_str.lower()
                
                # 添加调试日志
                if processed_pages % 50 == 0:
                    logging.debug(f"处理配置名称: '{current_name_to_check_str}' 长度: {len(current_name_to_check_str)}")
                
                for keyword in text_keywords_for_country:
                    if not isinstance(keyword, str):
                        continue
                        
                    # 移除关键词前后空格
                    keyword = keyword.strip()
                    if not keyword:
                        continue
                        
                    # 对缩写使用单词边界匹配，对普通词使用包含匹配
                    is_abbr = (len(keyword) in [2, 3]) and keyword.isupper() and keyword.isalpha()
                    keyword_lower = keyword.lower()
                    
                    if is_abbr:
                        # 对于缩写，使用更灵活的匹配策略
                        try:
                            # 改进缩写匹配逻辑，提高准确性
                            # 检查是否为独立单词
                            pattern = r'\b' + re.escape(keyword) + r'\b'
                            if re.search(pattern, current_name_to_check_str, re.IGNORECASE):
                                match_found = True
                                logging.debug(f"国家'{country_name_key}' 匹配缩写: '{keyword}'")
                                break
                            # 检查是否为单独的国家代码部分
                            parts = re.split(r'[^a-zA-Z]', current_name_to_check_str.lower())
                            if keyword_lower in parts:
                                match_found = True
                                logging.debug(f"国家'{country_name_key}' 匹配分割后缩写: '{keyword}'")
                                break
                        except Exception as e:
                            # 添加异常日志但继续执行
                            logging.debug(f"正则匹配错误: {e}")
                    else:
                        # 优化关键词匹配逻辑
                        if not is_non_english_text(keyword):
                            # 英语关键词使用包含检查
                            if keyword_lower in current_name_lower:
                                match_found = True
                                logging.debug(f"国家'{country_name_key}' 匹配英语关键词: '{keyword}'")
                                break
                        else:
                            # 非英语关键词直接比较
                            if keyword in current_name_to_check_str or keyword_lower in current_name_lower:
                                match_found = True
                                logging.debug(f"国家'{country_name_key}' 匹配非英语关键词: '{keyword}'")
                                break
                
                if match_found:
                    final_configs_by_country[country_name_key].add(config)
                    logging.debug(f"配置已关联到国家: {country_name_key}")
                    # 继续循环，允许配置匹配多个国家

    # 统计信息日志
    logging.info(f"成功处理 {processed_pages}/{len(fetched_pages)} 个页面，找到 {found_configs} 个有效配置，过滤掉 {filtered_out_configs} 个无效配置")
    
    # 确保删除任何可能的旧国家计数数据，重新基于集合大小计算
    country_counts = {}
    
    # 国家计数将在保存文件时基于集合大小计算，此处删除重复代码
    
    # 准备输出目录结构
    output_dir_abs = os.path.abspath(OUTPUT_DIR)
    country_dir = os.path.join(output_dir_abs, COUNTRY_SUBDIR)
    protocol_dir = os.path.join(output_dir_abs, PROTOCOL_SUBDIR)
    
    if os.path.exists(output_dir_abs):
        try:
            shutil.rmtree(output_dir_abs)
            logging.info(f"已删除旧的输出目录: {output_dir_abs}")
        except (PermissionError, OSError) as e:
            logging.warning(f"无法删除旧输出目录: {e}，尝试使用新目录名")
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            backup_dir = f"{output_dir_abs}_backup_{timestamp}"
            try:
                shutil.move(output_dir_abs, backup_dir)
                logging.info(f"已将旧目录重命名为: {backup_dir}")
            except Exception as inner_e:
                logging.error(f"重命名旧目录失败: {inner_e}")
                # 继续执行，让os.makedirs处理可能的目录存在情况
    
    # 确保输出目录结构存在
    try:
        # 使用绝对路径确保目录位置正确
        output_dir_abs = os.path.abspath(OUTPUT_DIR)
        country_dir_abs = os.path.abspath(country_dir)
        protocol_dir_abs = os.path.abspath(protocol_dir)
        
        # 先创建主目录
        os.makedirs(output_dir_abs, exist_ok=True)
        logging.info(f"已创建主输出目录: {output_dir_abs}")
        
        # 再创建子目录
        os.makedirs(country_dir_abs, exist_ok=True)
        os.makedirs(protocol_dir_abs, exist_ok=True)
        logging.info(f"已创建子目录: {country_dir_abs} 和 {protocol_dir_abs}")
        
        logging.info(f"正在保存文件到目录: {output_dir_abs}")
        logging.info(f"国家配置将保存到: {country_dir_abs}")
        logging.info(f"协议配置将保存到: {protocol_dir_abs}")
        
        # 验证目录创建成功
        if os.path.exists(country_dir_abs) and os.path.exists(protocol_dir_abs):
            logging.info("输出目录创建成功")
        else:
            logging.warning("输出目录创建可能不成功，请检查路径和权限")
    except (PermissionError, OSError) as e:
        logging.critical(f"无法创建输出目录: {e}")
        # 尝试使用当前工作目录
        try:
            current_dir = os.getcwd()
            fallback_country_dir = os.path.join(current_dir, OUTPUT_DIR, COUNTRY_SUBDIR)
            fallback_protocol_dir = os.path.join(current_dir, OUTPUT_DIR, PROTOCOL_SUBDIR)
            os.makedirs(fallback_country_dir, exist_ok=True)
            os.makedirs(fallback_protocol_dir, exist_ok=True)
            country_dir = fallback_country_dir
            protocol_dir = fallback_protocol_dir
            logging.warning(f"已切换到备选目录: {current_dir}\{OUTPUT_DIR}")
        except Exception as fallback_e:
            logging.critical(f"备选目录创建也失败: {fallback_e}")
            return

    # 保存协议配置文件
    protocol_counts = {}
    protocols_saved = 0
    total_protocol_configs = 0  # 添加总配置计数变量
    
    if not final_all_protocols:
        logging.warning("没有协议配置需要保存，final_all_protocols为空")
    else:
        logging.info(f"准备保存 {len(final_all_protocols)} 个协议类别的配置")
        
    for category, items in final_all_protocols.items():
        if not items:
            logging.debug(f"跳过空集合的保存: {category}")
            continue
            
        # 确保使用集合的实际大小作为计数，保持与国家配置保存逻辑一致
        actual_count = len(items)
        logging.info(f"正在保存协议配置: {category}，包含 {actual_count} 个配置")
        saved, count = save_to_file(protocol_dir, category, items, error_stats)
        if saved:
            protocol_counts[category] = actual_count  # 使用实际计数
            protocols_saved += 1
            total_protocol_configs += actual_count  # 累加总配置数
            logging.info(f"已保存协议配置: {category}, 节点数量: {actual_count}")
        else:
            logging.warning(f"协议配置保存失败: {category}")
    
    logging.info(f"总共保存了 {protocols_saved} 个协议配置文件，包含 {total_protocol_configs} 个配置")
    
    # 保存国家配置文件并确保计数准确
    country_counts = {}
    countries_with_configs = 0
    total_country_configs = 0
    countries_saved = 0
    
    if not final_configs_by_country:
        logging.warning("没有国家配置需要保存，final_configs_by_country为空")
    else:
        logging.info(f"准备保存 {len(final_configs_by_country)} 个国家类别的配置")
    
    for category, items in final_configs_by_country.items():
        if not items:
            logging.debug(f"跳过空集合的保存: {category}")
            continue
            
        # 确保使用集合的实际大小作为计数
        actual_count = len(items)
        logging.info(f"正在保存国家配置: {category}，包含 {actual_count} 个配置")
        saved, count = save_to_file(country_dir, category, items, error_stats)
        if saved:
            country_counts[category] = actual_count
            countries_with_configs += 1
            total_country_configs += actual_count
            countries_saved += 1
            logging.info(f"已保存国家配置: {category}, 节点数量: {actual_count}")
        else:
            logging.warning(f"国家配置保存失败: {category}")
    
    logging.info(f"总共保存了 {countries_saved} 个国家配置文件，包含 {total_country_configs} 个配置")
    
    # 生成README文件
    try:
        generate_simple_readme(protocol_counts, country_counts, categories_data, use_local_paths=False)
    except Exception as e:
        logging.error(f"生成README文件时出错: {e}")
        # 继续执行，不中断程序
    
    # 计算统计信息 - 使用直接统计的总数更准确
    protocol_config_count = total_protocol_configs  # 使用直接统计的变量，而不是重新计算
    
    # 生成并保存更新日志
    try:
        tz = pytz.timezone('Asia/Shanghai')
        now = datetime.now(tz)
        log_timestamp = now.strftime("%Y-%m-%d %H:%M:%S %Z")
        
        # 获取README文件的修改时间作为其更新时间
        readme_update_time = "未知"
        if os.path.exists(README_FILE):
            try:
                # 使用与README生成相同的时区
                tz = pytz.timezone('Asia/Shanghai')
                readme_mtime = os.path.getmtime(README_FILE)
                readme_update_datetime = datetime.fromtimestamp(readme_mtime, tz)
                readme_update_time = readme_update_datetime.strftime("%Y-%m-%d %H:%M:%S %Z")
                logging.debug(f"README文件修改时间: {readme_update_time}")
            except Exception as e:
                logging.warning(f"获取README修改时间失败: {e}")
        
        # 增强的详细日志内容，记录完整执行流程
        # 计算平均响应时间和执行总时间
        avg_response_time = response_times_sum[0] / response_times_count[0] if response_times_count[0] > 0 else 0
        logging.debug(f"响应时间统计: 平均={avg_response_time:.2f}s, 最大={response_times['max']:.2f}s, 最小={response_times['min']:.2f}s, 样本数={response_times_count[0]}")
        
        # 计算执行总时间
        if execution_time.get('start'):
            execution_time['total'] = (datetime.now() - execution_time['start']).total_seconds()
        
        log_entry = f"""========== GitHub Action 执行日志 - {log_timestamp} ==========

[程序启动信息]
- 程序版本: V1.0
- 执行环境: Python {platform.python_version()}
- 操作系统: {platform.system()} {platform.release()}
- 执行路径: {os.getcwd()}
- 环境变量状态: {'GITHUB_ACTIONS变量存在' if 'GITHUB_ACTIONS' in os.environ else 'GITHUB_ACTIONS变量不存在'}

[配置加载情况]
- URL列表文件: {os.path.abspath('config/urls.txt') if os.path.exists('config/urls.txt') else 'urls.txt'}
- 国家关键词文件: {os.path.abspath('config/keywords.json') if os.path.exists('config/keywords.json') else 'keywords.json'}
- 初始URL总数: {len(urls)}

[网络请求详情]
- 成功获取的URL数: {success_count}/{len(urls)}
- 失败的URL数: {len(urls) - success_count}
- 平均响应时间: {f"{avg_response_time:.2f}秒" if avg_response_time > 0 else 'N/A'}
- 最长响应时间: {f"{response_times['max']:.2f}秒" if response_times['max'] > 0 else 'N/A'}
- 最短响应时间: {f"{response_times['min']:.2f}秒" if response_times['min'] < float('inf') else 'N/A'}
- 响应时间样本数: {response_times_count[0]}

[页面处理详情]
- 处理的页面总数: {processed_pages}
- 跳过的无效页面: {len(fetched_pages) - processed_pages}
- 找到的配置总数: {found_configs}
- 过滤掉的无效配置: {filtered_out_configs}
- 过滤配置占比: {f"{filtered_out_configs/found_configs:.1%}" if found_configs > 0 else 'N/A'}

[配置过滤统计]
- URL编码检查过滤: {filter_stats.get('url_encoding', 0)}
- 长度限制过滤: {filter_stats.get('length', 0)}
- 协议关键词过滤: {filter_stats.get('protocol', 0)}
- 格式验证过滤: {filter_stats.get('format', 0)}
- 过滤分类详情: {filter_stats}
- 总过滤数: {sum(filter_stats.values())}

[国家关联详情]
- 处理的国家关键词: {len(country_keywords_for_naming) if 'country_keywords_for_naming' in locals() else 'N/A'}
- 有配置的国家数量: {countries_with_configs}
- 国家相关配置总数: {total_country_configs}
- 平均每个国家配置数: {f"{total_country_configs/countries_with_configs:.1f}" if countries_with_configs > 0 else '0'}

[目录处理信息]
- 输出目录: {os.path.abspath(OUTPUT_DIR)}
- 国家配置目录: {os.path.abspath(country_dir)}
- 协议配置目录: {os.path.abspath(protocol_dir)}
- 目录创建状态: {'成功' if os.path.exists(OUTPUT_DIR) else '失败'}
- 目录权限检查: {'可写' if os.path.exists(OUTPUT_DIR) and os.access(OUTPUT_DIR, os.W_OK) else '不可写' if os.path.exists(OUTPUT_DIR) else '目录不存在'}

[文件保存详情]
- 保存的协议配置总数: {protocol_config_count}
- 保存的协议配置文件数: {protocols_saved}
- 保存的国家配置文件数: {countries_saved}
- 平均每个协议配置数: {f"{protocol_config_count/protocols_saved:.1f}" if protocols_saved > 0 else '0'}
- 保存状态: {'成功' if protocols_saved > 0 or countries_saved > 0 else '失败'}

[README生成]
- README文件路径: {os.path.abspath(README_FILE)}
- README更新时间: {readme_update_time}
- README文件大小: {os.path.getsize(README_FILE) if os.path.exists(README_FILE) else 'N/A'}字节

[错误和异常信息]
- URL请求错误: {error_stats.get('url_request', 0)}
- 配置解析错误: {error_stats.get('config_parse', 0)}
- 文件保存错误: {error_stats.get('file_save', 0)}
- 目录创建错误: {error_stats.get('dir_create', 0)}
- 错误统计详情: {error_stats}
- 总错误数: {sum(error_stats.values())}

[资源使用情况]
- 内存使用: {resource_stats.get('memory', 'N/A')}
- CPU使用率: {resource_stats.get('cpu', 'N/A')}
- 执行总时间: {execution_time.get('total', 'N/A')}秒
- 执行开始时间: {execution_time.get('start', 'N/A').strftime('%Y-%m-%d %H:%M:%S') if hasattr(execution_time.get('start', None), 'strftime') else 'N/A'}

[GitHub Actions运行信息]
- 运行编号: {os.environ.get('GITHUB_RUN_NUMBER', 'N/A')}
- 运行ID: {os.environ.get('GITHUB_RUN_ID', 'N/A')}
- 工作流名称: {os.environ.get('GITHUB_WORKFLOW', 'N/A')}
- 分支名称: {os.environ.get('GITHUB_REF', 'N/A')}
- 提交SHA: {os.environ.get('GITHUB_SHA', 'N/A')}
====================================================\n\n"""
        
        # 确保日志文件所在目录存在
        log_dir = os.path.dirname(UPDATE_LOG_FILE)
        if log_dir:
            os.makedirs(log_dir, exist_ok=True)
            logging.debug(f"确保日志目录存在: {log_dir}")
        
        # 更新output_configs文件夹及其所有内容的修改时间，确保在GitHub Actions中显示一致
        try:
            # 使用绝对路径确保正确更新文件夹时间
            output_dir_abs = os.path.abspath(OUTPUT_DIR)
            current_time = (time.time(), time.time())  # (access_time, modify_time)
            
            # 先更新子目录和文件时间戳
            for subdir in [PROTOCOL_SUBDIR, COUNTRY_SUBDIR]:
                subdir_path = os.path.join(output_dir_abs, subdir)
                if os.path.exists(subdir_path):
                    # 递归更新目录中所有文件的时间戳
                    for root, dirs, files in os.walk(subdir_path):
                        for file in files:
                            file_path = os.path.join(root, file)
                            try:
                                os.utime(file_path, current_time)
                            except Exception as file_e:
                                logging.debug(f"无法更新文件时间戳 {file_path}: {file_e}")
                    # 最后更新目录本身的时间戳
                    os.utime(subdir_path, current_time)
                    logging.info(f"已更新{subdir}子目录及其所有文件的修改时间: {subdir_path}")
            
            # 最后更新主目录时间戳，确保它是最后更新的
            if os.path.exists(output_dir_abs):
                os.utime(output_dir_abs, current_time)
                logging.info(f"已更新output_configs文件夹的修改时间: {output_dir_abs}")
                
        except Exception as e:
            logging.warning(f"更新output_configs文件夹时间失败: {e}")
        
        # 使用绝对路径确保文件写入正确位置
        update_log_abs_path = os.path.abspath(UPDATE_LOG_FILE)
        with open(update_log_abs_path, 'a', encoding='utf-8') as f:
            f.write(log_entry)
        logging.info(f"更新日志已写入: {update_log_abs_path}")
        
        # 简单的日志大小控制 - 只保留最近30条日志
        try:
            with open(update_log_abs_path, 'r', encoding='utf-8') as f:
                content = f.read()
            
            # 按分隔符分割日志条目
            entries = content.split("====================================================\n\n")
            # 过滤掉空条目
            entries = [e for e in entries if e.strip()]
            
            # 只保留最近30条
            if len(entries) > 30:
                with open(update_log_abs_path, 'w', encoding='utf-8') as f:
                    f.write("====================================================\n\n".join(entries[-30:]) + "====================================================\n\n")
        except Exception as inner_e:
            logging.warning(f"清理旧日志时出错: {inner_e}")
            
    except Exception as e:
        logging.error(f"写入更新日志时出错: {e}")
        # 添加更详细的错误信息
        import traceback
        logging.error(f"错误详情: {traceback.format_exc()}")
    
    # 输出完成信息，显示实际使用的目录路径
    logging.info(f"=== 抓取完成 ===")
    logging.info(f"找到并保存的协议配置: {protocol_config_count}")
    logging.info(f"有配置的国家数量: {countries_with_configs}")
    logging.info(f"国家相关配置总数: {total_country_configs}")
    logging.info(f"输出目录结构:")
    logging.info(f"- 协议配置: {os.path.abspath(protocol_dir)}")
    logging.info(f"- 国家配置: {os.path.abspath(country_dir)}")
    logging.info(f"README文件已更新: {os.path.abspath(README_FILE)}")
    logging.info(f"更新日志已生成: {os.path.abspath(UPDATE_LOG_FILE)}")

if __name__ == "__main__":
    try:
        logging.info("=== V2Ray配置抓取工具开始运行 ===")
        asyncio.run(main())
    except KeyboardInterrupt:
        logging.info("程序被用户中断")
    except Exception as e:
        logging.critical(f"程序执行出错: {e}")
    finally:
        logging.info("=== 程序结束 ===")
