import requests
import base64
import os
from datetime import datetime, timezone

GFW_URL = "https://raw.githubusercontent.com/gfwlist/gfwlist/master/gfwlist.txt"
OUTPUT_FILE = "list/gfw.list"
POLICY = "PROXY"
SCRIPT_NAME = "generate_gfw.py"


def fetch_and_decode():
    print("正在下载 GFWList...")
    try:
        resp = requests.get(GFW_URL, timeout=30)
        resp.raise_for_status()
        decoded_content = base64.b64decode(resp.content).decode('utf-8')
        return decoded_content.splitlines()
    except Exception as e:
        print(f"GFWList 下载或解码失败: {e}")
        return []


def clean_domain(domain_str):
    """
    清洗域名函数：
    1. 去除路径（/及其后面的内容）
    2. 去除端口（:及其后面的内容，虽然少见但为了保险）
    3. 验证是否是有效域名格式
    """
    # 【关键修复】 去除路径，例如 example.com/foo -> example.com
    if '/' in domain_str:
        domain_str = domain_str.split('/')[0]

    # 去除端口号（可选，视情况而定，一般 host-suffix 不带端口）
    if ':' in domain_str:
        domain_str = domain_str.split(':')[0]

    domain_str = domain_str.strip()

    # 简单验证：必须包含点，且不能包含空格或通配符
    if '.' in domain_str and ' ' not in domain_str and '*' not in domain_str:
        return domain_str
    return None


def read_old_rules(filepath):
    try:
        with open(filepath, 'r', encoding='utf-8') as f:
            lines = f.readlines()
        body_start = 0
        for i, line in enumerate(lines):
            if line.startswith('#') or line.strip() == '':
                body_start = i + 1
            else:
                break
        return ''.join(lines[body_start:])
    except FileNotFoundError:
        return None


def write_rules(domains):
    now_utc = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")

    # 构建规则体用于对比
    rule_lines = []
    for domain in sorted(domains):
        if len(domain) > 3:
            rule_lines.append(f"host-suffix, {domain}")
    new_body = "\n".join(rule_lines) + ("\n" if rule_lines else "")

    old_body = read_old_rules(OUTPUT_FILE)
    if old_body is not None and old_body == new_body:
        status = "No Changes"
    else:
        status = "Updated"

    header = [
        f"# GFWList (Auto-Generated)",
        f"# Maintained by: scripts/{SCRIPT_NAME}",
        f"# Last Updated: {now_utc}",
        f"# Source: gfwlist/gfwlist",
        f"# Total Rules: {len(domains)}",
        f"# Status: {status}",
        "",
    ]

    output_lines = header + rule_lines

    os.makedirs(os.path.dirname(OUTPUT_FILE), exist_ok=True)
    with open(OUTPUT_FILE, 'w', encoding='utf-8') as f:
        f.write('\n'.join(output_lines))

    print(f"✅ GFWList 生成完毕: {OUTPUT_FILE}, 共 {len(domains)} 条规则 (Status: {status})")


def main():
    lines = fetch_and_decode()
    domains = set()

    print(f"正在解析 {len(lines)} 行规则...")

    for line in lines:
        line = line.strip()
        # 跳过空行、注释、正则表达式、白名单
        if not line or line.startswith('!') or line.startswith('[') or line.startswith('/') or line.startswith('@@'):
            continue

        raw_domain = ""

        # 1. 处理 ||example.com
        if line.startswith('||'):
            raw_domain = line[2:]
        # 2. 处理 .example.com
        elif line.startswith('.'):
            raw_domain = line[1:]
        # 3. 处理 |http://example.com (这种通常带协议头)
        elif line.startswith('|'):
            # 这种格式比较乱，且数量少，为了规则纯净度，建议跳过，或者尝试提取
            continue
        else:
            # 普通行，假设是域名
            raw_domain = line

        # 调用清洗函数
        final_domain = clean_domain(raw_domain)
        if final_domain:
            domains.add(final_domain)

    write_rules(domains)


if __name__ == "__main__":
    main()
