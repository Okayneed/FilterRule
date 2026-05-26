import requests
import json
import os
from datetime import datetime, timezone, timedelta

URL = "https://endpoints.office.com/endpoints/China?clientrequestid=b10c5ed1-bad1-445f-b386-b919946339a7"
SCRIPT_NAME = "generate_o365.py"

OUTPUTS = [
    {"file": "list/Auto_o365_cn.list",      "fmt": "qx"},
    {"file": "loon-rule/Auto_o365_cn.list", "fmt": "loon"},
]


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


def build_rule_body(domains, ipv4_list, fmt):
    """构建规则体"""
    suffix_label = "DOMAIN-SUFFIX" if fmt == "loon" else "host-suffix"
    cidr_label = "IP-CIDR" if fmt == "loon" else "ip-cidr"
    sep = "," if fmt == "loon" else ", "

    lines = [f"; --- Domains ({suffix_label}) ---"]
    for domain in sorted(domains):
        lines.append(f"{suffix_label}{sep}{domain}")
    lines.append("")
    lines.append(f"; --- IPv4 Ranges ({cidr_label}) ---")
    for ip in sorted(ipv4_list, key=lambda x: [int(o) for o in x.replace('/', '.').split('.')[:4]]):
        lines.append(f"{cidr_label}{sep}{ip}")
    return "\n".join(lines)


def write_rules(domains, ipv4_list):
    now_cst = datetime.now(timezone(timedelta(hours=8))).strftime("%Y-%m-%d %H:%M CST")

    for output in OUTPUTS:
        rule_body = build_rule_body(domains, ipv4_list, output["fmt"])
        old_body = read_old_rules(output["file"])
        status = "No Changes" if (old_body is not None and old_body == rule_body) else "Updated"

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

        os.makedirs(os.path.dirname(output["file"]), exist_ok=True)
        with open(output["file"], 'w', encoding='utf-8') as f:
            f.write('\n'.join(header + [rule_body]))

        print(f"✅ {output['file']}  ({status})")


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
        if 'urls' in item:
            for url in item['urls']:
                clean_url = url.lstrip('*').lstrip('.')
                if clean_url:
                    domains.add(clean_url)
        if 'ips' in item:
            for ip in item['ips']:
                if ':' in ip:
                    ipv6_list.add(ip)
                else:
                    ipv4_list.add(ip)

    write_rules(domains, ipv4_list)


if __name__ == "__main__":
    main()
