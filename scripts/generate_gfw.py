import requests
import base64
import os
from datetime import datetime, timezone, timedelta

GFW_URL = "https://raw.githubusercontent.com/gfwlist/gfwlist/master/gfwlist.txt"
POLICY = "PROXY"
SCRIPT_NAME = "generate_gfw.py"

OUTPUTS = [
    {"file": "list/Auto_gfw.list",      "fmt": "qx"},
    {"file": "loon-rule/Auto_gfw.list", "fmt": "loon"},
]

def fmt_rule(domain, fmt):
    if fmt == "loon":
        return f"DOMAIN-SUFFIX,{domain}"
    return f"host-suffix, {domain}"


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
    if '/' in domain_str:
        domain_str = domain_str.split('/')[0]
    if ':' in domain_str:
        domain_str = domain_str.split(':')[0]
    domain_str = domain_str.strip()
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
        body = ''.join(lines[body_start:])
        if body.endswith('\n'):
            body = body[:-1]
        return body
    except FileNotFoundError:
        return None


def write_rules(domains):
    now_cst = datetime.now(timezone(timedelta(hours=8))).strftime("%Y-%m-%d %H:%M CST")

    for output in OUTPUTS:
        rule_lines = [fmt_rule(d, output["fmt"]) for d in sorted(domains) if len(d) > 3]
        new_body = "\n".join(rule_lines)

        old_body = read_old_rules(output["file"])
        status = "No Changes" if (old_body is not None and old_body == new_body) else "Updated"

        header = [
            f"# GFWList (Auto-Generated)",
            f"# Maintained by: scripts/{SCRIPT_NAME}",
            f"# Last Updated: {now_cst}",
            f"# Source: gfwlist/gfwlist",
            f"# Total Rules: {len(domains)}",
            f"# Status: {status}",
            "",
        ]

        output_lines = header + rule_lines
        os.makedirs(os.path.dirname(output["file"]), exist_ok=True)
        with open(output["file"], 'w', encoding='utf-8') as f:
            f.write('\n'.join(output_lines))

        print(f"✅ {output['file']}  ({status})")


def main():
    lines = fetch_and_decode()
    domains = set()
    print(f"正在解析 {len(lines)} 行规则...")

    for line in lines:
        line = line.strip()
        if not line or line.startswith('!') or line.startswith('[') or line.startswith('/') or line.startswith('@@'):
            continue
        raw_domain = ""
        if line.startswith('||'):
            raw_domain = line[2:]
        elif line.startswith('.'):
            raw_domain = line[1:]
        elif line.startswith('|'):
            continue
        else:
            raw_domain = line
        final_domain = clean_domain(raw_domain)
        if final_domain:
            domains.add(final_domain)

    write_rules(domains)


if __name__ == "__main__":
    main()
