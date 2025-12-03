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

# 获取当前脚本所在目录的绝对路径
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.abspath(os.path.join(SCRIPT_DIR, '..'))

# 使用绝对路径引用文件
URLS_FILE = os.path.join(SCRIPT_DIR, 'urls.txt')
KEYWORDS_FILE = os.path.join(SCRIPT_DIR, 'key.json')
PROTOCOL_OUTPUT_DIR = os.path.join(PROJECT_ROOT, 'configs/protocols')
COUNTRY_OUTPUT_DIR = os.path.join(PROJECT_ROOT, 'configs/countries')
README_FILE = os.path.join(PROJECT_ROOT, 'README.md')
REQUEST_TIMEOUT = 15
CONCURRENT_REQUESTS = 10
MAX_CONFIG_LENGTH = 1500
MIN_PERCENT25_COUNT = 15

logging.basicConfig(level=logging.INFO,
                    format='%(asctime)s - %(levelname)s - %(message)s')

PROTOCOL_CATEGORIES = [
    "Vmess", "Vless", "Trojan", "ShadowSocks", "ShadowSocksR",
    "Tuic", "Hysteria2", "WireGuard"
]

def is_persian_like(text):
    if not isinstance(text, str) or not text.strip():
        return False
    has_persian_char = False
    has_latin_char = False
    for char in text:
        if '\u0600' <= char <= '\u06FF' or char in ['\u200C', '\u200D']:
            has_persian_char = True
        elif 'a' <= char.lower() <= 'z':
            has_latin_char = True
    return has_persian_char and not has_latin_char

def decode_base64(data):
    try:
        data = data.replace('_', '/').replace('-', '+')
        missing_padding = len(data) % 4
        if missing_padding:
            data += '=' * (4 - missing_padding)
        return base64.b64decode(data).decode('utf-8')
    except Exception:
        return None

def get_vmess_name(vmess_link):
    if not vmess_link.startswith("vmess://"):
        return None
    try:
        b64_part = vmess_link[8:]
        decoded_str = decode_base64(b64_part)
        if decoded_str:
            vmess_json = json.loads(decoded_str)
            return vmess_json.get('ps')
    except Exception as e:
        logging.warning(f"Failed to parse Vmess name from {vmess_link[:30]}...: {e}")
    return None

def get_ssr_name(ssr_link):
    if not ssr_link.startswith("ssr://"):
        return None
    try:
        b64_part = ssr_link[6:]
        decoded_str = decode_base64(b64_part)
        if not decoded_str:
            return None
        parts = decoded_str.split('/?')
        if len(parts) < 2:
            return None
        params_str = parts[1]
        params = parse_qs(params_str)
        if 'remarks' in params and params['remarks']:
            remarks_b64 = params['remarks'][0]
            return decode_base64(remarks_b64)
    except Exception as e:
        logging.warning(f"Failed to parse SSR name from {ssr_link[:30]}...: {e}")
    return None

def get_vless_name(vless_link):
    if not vless_link.startswith("vless://"):
        return None
    try:
        # vless://uuid@host:port?encryption=none&security=tls&sni=example.com#name
        if '#' in vless_link:
            name_part = vless_link.split('#', 1)[1]
            return unquote(name_part).strip()
    except Exception as e:
        logging.warning(f"Failed to parse Vless name from {vless_link[:30]}...: {e}")
    return None

def get_trojan_name(trojan_link):
    if not trojan_link.startswith("trojan://"):
        return None
    try:
        # trojan://password@host:port#name
        if '#' in trojan_link:
            name_part = trojan_link.split('#', 1)[1]
            return unquote(name_part).strip()
    except Exception as e:
        logging.warning(f"Failed to parse Trojan name from {trojan_link[:30]}...: {e}")
    return None

def get_shadowsocks_name(ss_link):
    if not ss_link.startswith("ss://"):
        return None
    try:
        # ss://base64_encoded#name
        if '#' in ss_link:
            name_part = ss_link.split('#', 1)[1]
            return unquote(name_part).strip()
    except Exception as e:
        logging.warning(f"Failed to parse Shadowsocks name from {ss_link[:30]}...: {e}")
    return None

def get_hysteria2_name(hy2_link):
    if not hy2_link.startswith("hy2://"):
        return None
    try:
        # hy2://password@host:port#name
        if '#' in hy2_link:
            name_part = hy2_link.split('#', 1)[1]
            return unquote(name_part).strip()
    except Exception as e:
        logging.warning(f"Failed to parse Hysteria2 name from {hy2_link[:30]}...: {e}")
    return None

def get_wireguard_name(wg_link):
    if not (wg_link.startswith("wg://") or 'WireGuard' in wg_link):
        return None
    try:
        # WireGuard配置通常包含#name
        if '#' in wg_link:
            name_part = wg_link.split('#', 1)[1]
            return unquote(name_part).strip()
    except Exception as e:
        logging.warning(f"Failed to parse WireGuard name from {wg_link[:30]}...: {e}")
    return None

def should_filter_config(config):
    # 过滤包含广告或可疑内容的配置
    if 'i_love_' in config.lower():
        return True
    # 过滤URL编码异常（%25过多）的配置
    percent25_count = config.count('%25')
    if percent25_count >= MIN_PERCENT25_COUNT:
        return True
    # 过滤过长的配置
    if len(config) >= MAX_CONFIG_LENGTH:
        return True
    # 过滤双重URL编码（%2525）的配置
    if '%2525' in config:
        return True
    return False

async def fetch_url(session, url):
    retries = 3
    for attempt in range(retries):
        try:
            async with session.get(url, timeout=REQUEST_TIMEOUT) as response:
                response.raise_for_status()
                html = await response.text()
                soup = BeautifulSoup(html, 'html.parser')
                text_content = ""
                # 尝试从各种HTML元素中提取文本
                for element in soup.find_all(['pre', 'code', 'p', 'div', 'li', 'span', 'td']):
                    text_content += element.get_text(separator='\n', strip=True) + "\n"
                if not text_content:
                    # 如果没有找到特定元素，使用整个页面文本
                    text_content = soup.get_text(separator=' ', strip=True)
                logging.info(f"Successfully fetched: {url} (attempt {attempt+1}/{retries})")
                return url, text_content
        except Exception as e:
            if attempt < retries - 1:
                logging.warning(f"Failed to fetch or process {url} (attempt {attempt+1}/{retries}): {e}. Retrying...")
                await asyncio.sleep(1)  # 重试前等待1秒
            else:
                logging.error(f"Failed to fetch or process {url} after {retries} attempts: {e}")
                return url, None

def find_matches(text, categories_data):
    matches = {category: set() for category in categories_data}
    for category, patterns in categories_data.items():
        for pattern_str in patterns:
            if not isinstance(pattern_str, str):
                continue
            try:
                is_protocol_pattern = any(proto_prefix in pattern_str for proto_prefix in [p.lower() + "://" for p in PROTOCOL_CATEGORIES])
                if category in PROTOCOL_CATEGORIES or is_protocol_pattern:
                    pattern = re.compile(pattern_str, re.IGNORECASE | re.MULTILINE)
                    found = pattern.findall(text)
                    if found:
                        cleaned_found = {item.strip() for item in found if item.strip()}
                        matches[category].update(cleaned_found)
            except re.error as e:
                logging.error(f"Regex error for '{pattern_str}' in category '{category}': {e}")
    return {k: v for k, v in matches.items() if v}

def save_to_file(directory, category_name, items_set):
    if not items_set:
        return False, 0
    file_path = os.path.join(directory, f"{category_name}.txt")
    count = len(items_set)
    try:
        with open(file_path, 'w', encoding='utf-8') as f:
            for item in sorted(list(items_set)):
                f.write(f"{item}\n")
        logging.info(f"Saved {count} items to {file_path}")
        return True, count
    except Exception as e:
        logging.error(f"Failed to write file {file_path}: {e}")
        return False, 0

def generate_simple_readme(protocol_counts, country_counts, all_keywords_data, github_repo_path="Eleven1985/Scrape-By-Country", github_branch="main"):
    tz = pytz.timezone('Asia/Shanghai')
    now = datetime.now(tz)
    time_str = now.strftime("%H:%M")
    date_str = now.strftime("%Y-%m-%d")
    timestamp = f"最后更新: {time_str} {date_str}"

    raw_github_base_url_protocols = f"https://raw.githubusercontent.com/{github_repo_path}/refs/heads/{github_branch}/configs/protocols"
    raw_github_base_url_countries = f"https://raw.githubusercontent.com/{github_repo_path}/refs/heads/{github_branch}/configs/countries"

    total_configs = sum(protocol_counts.values())

    md_content = f"""# 🚀 Scrape-By-Country

<p align="center">
  <img src="https://img.shields.io/github/license/{github_repo_path}?style=flat-square&color=blue" alt="License" />
  <img src="https://img.shields.io/badge/python-3.9%2B-3776AB?style=flat-square&logo=python" alt="Python 3.9+" />
  <img src="https://img.shields.io/github/actions/workflow/status/{github_repo_path}/scraper.yml?style=flat-square" alt="GitHub Workflow Status" />
  <img src="https://img.shields.io/github/last-commit/{github_repo_path}?style=flat-square" alt="Last Commit" />
  <br>
  <img src="https://img.shields.io/github/issues/{github_repo_path}?style=flat-square" alt="GitHub Issues" />
  <img src="https://img.shields.io/badge/Configs-{total_configs}-blue?style=flat-square" alt="Total Configs" />
  <img src="https://img.shields.io/github/stars/{github_repo_path}?style=social" alt="GitHub Stars" />
  <img src="https://img.shields.io/badge/status-active-brightgreen?style=flat-square" alt="Project Status" />
  <img src="https://img.shields.io/badge/language-中文%20%26%20English-007EC6?style=flat-square" alt="Language" />
</p>

## {timestamp}

---

## 📖 关于项目
这个项目自动从各种来源收集和分类VPN配置（如V2Ray、Trojan和Shadowsocks等不同协议）。我们的目标是为用户提供最新且可靠的配置。



---

## 📁 协议配置
{f'目前有 {total_configs} 个配置可用。' if total_configs else '未找到任何协议配置。'}

<div align="center">

| 协议 | 数量 | 下载链接 |
|:-------:|:-----:|:------------:|
"""
    # 添加汇总行，显示AllProtocols.txt的信息
    all_protocols_link = f"{raw_github_base_url_protocols}/AllProtocols.txt"
    md_content += f"| **汇总** | **{total_configs}** | [`AllProtocols.txt`]({all_protocols_link}) |\n"
    
    if protocol_counts:
        for category_name, count in sorted(protocol_counts.items()):
            file_link = f"{raw_github_base_url_protocols}/{category_name}.txt"
            md_content += f"| {category_name} | {count} | [`{category_name}.txt`]({file_link}) |\n"
    else:
        md_content += "| - | - | - |\n"

    md_content += "</div>\n\n---\n\n"

    md_content += f"""
## 🌍 国家配置
{f'配置已按国家名称分类。' if country_counts else '未找到任何国家相关配置。'}

<div align="center">

| 国家 | 数量 | 下载链接 |
|:----:|:-----:|:------------:|
"""
    if country_counts:
        for country_category_name, count in sorted(country_counts.items()):
            flag_image_markdown = ""
            chinese_name_str = ""
            iso_code_original_case = ""

            if country_category_name in all_keywords_data:
                keywords_list = all_keywords_data[country_category_name]
                if keywords_list and isinstance(keywords_list, list):
                    iso_code_lowercase_for_url = ""
                    for item in keywords_list:
                        if isinstance(item, str) and len(item) == 2 and item.isupper() and item.isalpha():
                            iso_code_lowercase_for_url = item.lower()
                            iso_code_original_case = item
                            break
                    if iso_code_lowercase_for_url:
                        flag_image_url = f"https://flagcdn.com/w20/{iso_code_lowercase_for_url}.png"
                        flag_image_markdown = f'<img src="{flag_image_url}" width="20" alt="{country_category_name} flag"> '
                    for item in keywords_list:
                        if isinstance(item, str):
                            if iso_code_original_case and item == iso_code_original_case:
                                continue
                            if item.lower() == country_category_name.lower() and not is_persian_like(item):
                                continue
                            if len(item) in [2, 3] and item.isupper() and item.isalpha() and item != iso_code_original_case:
                                continue
                            # 检查是否为中文名称
                            if any('\u4e00' <= c <= '\u9fff' for c in item):
                                chinese_name_str = item
                                break
            display_parts = []
            if flag_image_markdown:
                display_parts.append(flag_image_markdown)
            display_parts.append(country_category_name)
            if chinese_name_str:
                display_parts.append(f"({chinese_name_str})")
            country_display_text = " ".join(display_parts)
            file_link = f"{raw_github_base_url_countries}/{country_category_name}.txt"
            md_content += f"| {country_display_text} | {count} | [`{country_category_name}.txt`]({file_link}) |\n"
    else:
        md_content += "| - | - | - |\n"

    md_content += "</div>\n\n---\n\n"

    md_content += """
## 🛠️ 使用方法
1. **下载配置**: 从上方表格中，下载您需要的文件（根据协议或国家）。
2. **推荐客户端**:
   - **V2Ray**: [v2rayNG](https://github.com/2dust/v2rayNG) (安卓)，[Hiddify](https://github.com/hiddify/hiddify-app/releases) (Mac)，[V2RayN](https://github.com/2dust/v2rayN/releases) (Windows)
   - **NekoRey_pro**: [NekoRey](https://github.com/Mahdi-zarei/nekoray/releases) (Mac)，[Karing](https://github.com/KaringX/karing/releases)
   - **sing-box**: [Sing-Box](https://github.com/SagerNet/sing-box/releases)
3. 将配置文件导入您的客户端并测试连接。

> **建议**: 为获得最佳性能，请定期检查和更新配置。

---

## 🤝 贡献
如果您想参与项目，可以：
- 推荐新的配置收集来源（`urls.txt`文件）。
- 添加新的协议或国家模式（`key.json`文件）。
- 通过在 [GitHub](https://github.com/Eleven1985/Scrape-By-Country) 上提交Pull Request或Issue来帮助改进项目。

---

## 📢 注意事项
- 本项目仅用于学习和研究目的。
- 请根据您所在国家的法律负责任地使用配置。
- 如遇问题或建议，请使用 [Issues](https://github.com/Eleven1985/Scrape-By-Country/issues) 部分。
"""


    try:
        with open(README_FILE, 'w', encoding='utf-8') as f:
            f.write(md_content)
        logging.info(f"Successfully generated {README_FILE}")
    except Exception as e:
        logging.error(f"Failed to write {README_FILE}: {e}")

async def main():
    if not os.path.exists(URLS_FILE) or not os.path.exists(KEYWORDS_FILE):
        logging.critical("Input files not found.")
        return

    with open(URLS_FILE, 'r', encoding='utf-8') as f:
        urls = [line.strip() for line in f if line.strip()]
    with open(KEYWORDS_FILE, 'r', encoding='utf-8') as f:
        categories_data = json.load(f)

    protocol_patterns_for_matching = {
        cat: patterns for cat, patterns in categories_data.items() if cat in PROTOCOL_CATEGORIES
    }
    country_keywords_for_naming = {
        cat: patterns for cat, patterns in categories_data.items() if cat not in PROTOCOL_CATEGORIES
    }
    country_category_names = list(country_keywords_for_naming.keys())

    logging.info(f"Loaded {len(urls)} URLs and "
                 f"{len(categories_data)} total categories from key.json.")

    tasks = []
    sem = asyncio.Semaphore(CONCURRENT_REQUESTS)
    async def fetch_with_sem(session, url_to_fetch):
        async with sem:
            return await fetch_url(session, url_to_fetch)
    async with aiohttp.ClientSession() as session:
        fetched_pages = await asyncio.gather(*[fetch_with_sem(session, u) for u in urls])

    final_configs_by_country = {cat: set() for cat in country_category_names}
    final_all_protocols = {cat: set() for cat in PROTOCOL_CATEGORIES}

    logging.info("Processing pages for config name association...")
    for url, text in fetched_pages:
        if not text:
            continue

        page_protocol_matches = find_matches(text, protocol_patterns_for_matching)
        all_page_configs_after_filter = set()
        for protocol_cat_name, configs_found in page_protocol_matches.items():
            if protocol_cat_name in PROTOCOL_CATEGORIES:
                for config in configs_found:
                    if should_filter_config(config):
                        continue
                    all_page_configs_after_filter.add(config)
                    final_all_protocols[protocol_cat_name].add(config)

        for config in all_page_configs_after_filter:
            name_to_check = None
            if '#' in config:
                try:
                    potential_name = config.split('#', 1)[1]
                    name_to_check = unquote(potential_name).strip()
                    if not name_to_check:
                        name_to_check = None
                except IndexError:
                    pass

            if not name_to_check:
                if config.startswith('ssr://'):
                    name_to_check = get_ssr_name(config)
                elif config.startswith('vmess://'):
                    name_to_check = get_vmess_name(config)
                elif config.startswith('vless://'):
                    name_to_check = get_vless_name(config)
                elif config.startswith('trojan://'):
                    name_to_check = get_trojan_name(config)
                elif config.startswith('ss://'):
                    name_to_check = get_shadowsocks_name(config)
                elif config.startswith('hy2://'):
                    name_to_check = get_hysteria2_name(config)
                elif config.startswith('wg://') or 'WireGuard' in config:
                    name_to_check = get_wireguard_name(config)

            if not name_to_check:
                continue

            current_name_to_check_str = name_to_check if isinstance(name_to_check, str) else ""

            for country_name_key, keywords_for_country_list in country_keywords_for_naming.items():
                if not isinstance(keywords_for_country_list, list):
                    continue
                    
                # 提取所有有效的国家关键字（排除emoji但保留国家代码和名称）
                text_keywords_for_country = []
                for kw in keywords_for_country_list:
                    if not isinstance(kw, str):
                        continue
                        
                    # 保留国家代码（2-3个大写字母）
                    if 2 <= len(kw) <= 3 and kw.isupper() and kw.isalpha():
                        text_keywords_for_country.append(kw)
                        continue
                        
                    # 保留完整的国家名称（非emoji）
                    if not (1 <= len(kw) <= 7 and not kw.isalnum()):  # 排除可能是emoji的字符串
                        # 即使是波斯语，如果与国家名称匹配也保留
                        if not is_persian_like(kw) or kw.lower() == country_name_key.lower():
                            text_keywords_for_country.append(kw)
                
                # 检查配置名称是否包含国家关键字
                for keyword in text_keywords_for_country:
                    if not isinstance(keyword, str):
                        continue
                        
                    # 对于国家代码，使用单词边界匹配
                    if 2 <= len(keyword) <= 3 and keyword.isupper() and keyword.isalpha():
                        pattern = r'\b' + re.escape(keyword) + r'\b'
                        if re.search(pattern, current_name_to_check_str, re.IGNORECASE):
                            final_configs_by_country[country_name_key].add(config)
                            break
                    # 对于国家名称，使用包含匹配
                    elif keyword.lower() in current_name_to_check_str.lower():
                        final_configs_by_country[country_name_key].add(config)
                        break
                else:
                    continue  # 未找到匹配，继续下一个国家
                break  # 找到匹配，跳出循环

    if os.path.exists('configs'):
        shutil.rmtree('configs')
    os.makedirs(PROTOCOL_OUTPUT_DIR, exist_ok=True)
    os.makedirs(COUNTRY_OUTPUT_DIR, exist_ok=True)
    logging.info(f"Saving protocol files to directory: {PROTOCOL_OUTPUT_DIR}")
    logging.info(f"Saving country files to directory: {COUNTRY_OUTPUT_DIR}")

    protocol_counts = {}
    country_counts = {}

    for category, items in final_all_protocols.items():
        saved, count = save_to_file(PROTOCOL_OUTPUT_DIR, category, items)
        if saved:
            protocol_counts[category] = count
    
    # Merge all protocols into one file (保持与其他协议文件命名一致)
    all_protocols_combined = set()
    for category, items in final_all_protocols.items():
        all_protocols_combined.update(items)
    save_to_file(PROTOCOL_OUTPUT_DIR, "AllProtocols", all_protocols_combined)
    
    for category, items in final_configs_by_country.items():
        saved, count = save_to_file(COUNTRY_OUTPUT_DIR, category, items)
        if saved:
            country_counts[category] = count

    generate_simple_readme(protocol_counts, country_counts, categories_data,
                          github_repo_path="Eleven1985/Scrape-By-Country",
                          github_branch="main")

    logging.info("--- Script Finished ---")

if __name__ == "__main__":
    asyncio.run(main())
