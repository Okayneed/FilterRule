import requests
import re
import os
from datetime import datetime, timezone, timedelta

SOURCE_URL = "https://ip.net.coffee/claude/site.html"
SCRIPT_NAME = "fetch_claude.py"

OUTPUTS = [
    {"file": "list/Auto_claude.list",      "fmt": "qx"},
    {"file": "loon-rule/Auto_claude.list", "fmt": "loon"},
]

# Clash type → QX type mapping (Loon uses same as Clash, no mapping needed)
QX_MAP = {
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
    """返回结构化规则列表: [(clash_type, value), ...]"""
    rules = []
    seen = set()

    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#") or line.startswith("//"):
            continue

        match = re.match(r"^(DOMAIN|DOMAIN-SUFFIX|DOMAIN-KEYWORD|IP-CIDR6?|IP-ASN),(.+)$", line)
        if not match:
            continue

        rule_type = match.group(1)
        rest = match.group(2)
        value = rest.split(",")[0].strip()

        key = (rule_type, value)
        if key in seen:
            continue
        seen.add(key)
        rules.append(key)

    type_order = {"DOMAIN": 0, "DOMAIN-SUFFIX": 1, "DOMAIN-KEYWORD": 2,
                  "IP-CIDR": 3, "IP-CIDR6": 4, "IP-ASN": 5}
    rules.sort(key=lambda r: (type_order.get(r[0], 99), r[1]))
    return rules


def fmt_qx(rule):
    typ, val = rule
    qx_type = QX_MAP.get(typ, typ.lower())
    return f"{qx_type}, {val}"


def fmt_loon(rule):
    typ, val = rule
    return f"{typ},{val}"


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

    for output in OUTPUTS:
        fmt_func = fmt_qx if output["fmt"] == "qx" else fmt_loon
        rule_lines = [fmt_func(r) for r in rules]
        new_body = "\n".join(rule_lines)

        old_body = read_old_rules(output["file"])
        status = "No Changes" if (old_body is not None and old_body == new_body) else "Updated"

        header = [
            f"# Claude Rules (Auto-Generated)",
            f"# Maintained by: scripts/{SCRIPT_NAME}",
            f"# Last Updated: {now_cst}",
            f"# Source: {SOURCE_URL}",
            f"# Total Rules: {len(rules)}",
            f"# Status: {status}",
            "",
        ]

        os.makedirs(os.path.dirname(output["file"]), exist_ok=True)
        with open(output["file"], 'w', encoding='utf-8') as f:
            f.write("\n".join(header + rule_lines) + "\n")

        print(f"✅ {output['file']}  ({status})")


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
