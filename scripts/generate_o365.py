import requests
import json
import os
from datetime import datetime, timezone, timedelta

# 微软官方 Office 365 中国版接口
URL = "https://endpoints.office.com/endpoints/China?clientrequestid=b10c5ed1-bad1-445f-b386-b919946339a7"
OUTPUT_FILE = "list/Auto_o365_cn.list"
SCRIPT_NAME = "generate_o365.py"


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
        body = ''.join(lines[body_start:])
        if body.endswith('\n'):
            body = body[:-1]
        return body
    except FileNotFoundError:
        return None


def build_rule_body(domains, ipv4_list):
    """构建规则体（不含 header），用于写入和对比"""
    lines = []
    lines.append("; --- Domains (host-suffix) ---")
    for domain in sorted(domains):
        lines.append(f"host-suffix, {domain}")
    lines.append("")
    lines.append("; --- IPv4 Ranges (ip-cidr) ---")
    for ip in sorted(ipv4_list, key=lambda x: [int(o) for o in x.replace('/', '.').split('.')[:4]]):
        lines.append(f"ip-cidr, {ip}")
    return "\n".join(lines)


def write_rules(domains, ipv4_list):
    now_cst = datetime.now(timezone(timedelta(hours=8))).strftime("%Y-%m-%d %H:%M CST")

    rule_body = build_rule_body(domains, ipv4_list)
    old_body = read_old_rules(OUTPUT_FILE)
    if old_body is not None and old_body == rule_body:
        status = "No Changes"
    else:
        status = "Updated"

    header = [
        f"# Office 365 China (21Vianet) (Auto-Generated)",
        f"# Maintained by: scripts/{SCRIPT_NAME}",
        f"# Last Updated: {now_cst}",
        f"# Source: Microsoft Official Endpoint",
        f"# Total Domains: {len(domains)}",
        f"# Total IPv4: {len(ipv4_list)}",
        f"# Status: {status}",
        "",
    ]

    final_lines = header + [rule_body]

    os.makedirs(os.path.dirname(OUTPUT_FILE), exist_ok=True)
    with open(OUTPUT_FILE, 'w', encoding='utf-8') as f:
        f.write('\n'.join(final_lines))

    print(f"✅ 生成规则文件: {OUTPUT_FILE} (Status: {status})")


def main():
    print("正在获取数据...")
    try:
        response = requests.get(URL, timeout=30)
        response.raise_for_status()
        data = response.json()
    except Exception as e:
        print(f"获取数据失败: {e}")
        exit(1)

    domains = set()
    ipv4_list = set()
    ipv6_list = set()

    print("正在解析数据...")
    for item in data:
        # 提取域名
        if 'urls' in item:
            for url in item['urls']:
                # 移除通配符 *. 和开头 . 以适配 host-suffix
                clean_url = url.lstrip('*').lstrip('.')
                if clean_url:
                    domains.add(clean_url)

        # 提取 IP
        if 'ips' in item:
            for ip in item['ips']:
                if ':' in ip:
                    ipv6_list.add(ip)
                else:
                    ipv4_list.add(ip)

    write_rules(domains, ipv4_list)


if __name__ == "__main__":
    main()
