import requests
import re
import os
from datetime import datetime, timezone, timedelta

OUTPUT = "list/Auto_claude.list"
SOURCE_URL = "https://ip.net.coffee/claude/site.html"
SCRIPT_NAME = "fetch_claude.py"

# Clash 类型 → Quantumult X 类型 映射
TYPE_MAP = {
    "DOMAIN": "host",
    "DOMAIN-SUFFIX": "host-suffix",
    "DOMAIN-KEYWORD": "host-keyword",
    "IP-CIDR": "ip-cidr",
    "IP-CIDR6": "ip6-cidr",
    "IP-ASN": "ip-asn",
}


def fetch_page(url: str) -> str:
    try:
        resp = requests.get(url, timeout=15)
        resp.raise_for_status()
        return resp.text
    except Exception as e:
        print(f"❌ 下载失败 {url}: {e}")
        raise


def extract_rules(text: str):
    rules = []
    seen = set()

    for line in text.splitlines():
        line = line.strip()

        if not line or line.startswith("#") or line.startswith("//"):
            continue

        match = re.match(r"^(DOMAIN|DOMAIN-SUFFIX|DOMAIN-KEYWORD|IP-CIDR6?|IP-ASN),(.+)$", line)
        if not match:
            continue

        clash_type = match.group(1)
        rest = match.group(2)
        value = rest.split(",")[0].strip()

        qx_type = TYPE_MAP.get(clash_type)
        if not qx_type:
            continue

        key = f"{qx_type},{value}"
        if key in seen:
            continue
        seen.add(key)

        rules.append(f"{qx_type}, {value}")

    def sort_key(rule):
        type_order = {
            "host": 0,
            "host-suffix": 1,
            "host-keyword": 2,
            "ip-cidr": 3,
            "ip6-cidr": 4,
            "ip-asn": 5,
        }
        qx_type, _, val = rule.partition(",")
        return (type_order.get(qx_type.strip(), 99), val.strip())

    return sorted(rules, key=sort_key)


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


def write_rules(rules):
    now_cst = datetime.now(timezone(timedelta(hours=8))).strftime("%Y-%m-%d %H:%M CST")

    new_body = "\n".join(rules)
    old_body = read_old_rules(OUTPUT)
    if old_body is not None and old_body == new_body:
        status = "No Changes"
    else:
        status = "Updated"

    header = [
        f"# Claude Rules (Auto-Generated)",
        f"# Maintained by: scripts/{SCRIPT_NAME}",
        f"# Last Updated: {now_cst}",
        f"# Source: {SOURCE_URL}",
        f"# Total Rules: {len(rules)}",
        f"# Status: {status}",
        "",
    ]

    lines = header + rules

    os.makedirs(os.path.dirname(OUTPUT), exist_ok=True)
    with open(OUTPUT, 'w', encoding='utf-8') as f:
        f.write("\n".join(lines) + "\n")

    print(f"✅ 生成 {OUTPUT} 成功（共 {len(rules)} 条规则, Status: {status})")


def main():
    print(f"🌐 从 {SOURCE_URL} 获取 Claude 规则...")
    page = fetch_page(SOURCE_URL)
    rules = extract_rules(page)

    if not rules:
        print("⚠️ 未提取到任何规则，跳过更新")
        return

    write_rules(rules)


if __name__ == "__main__":
    main()
