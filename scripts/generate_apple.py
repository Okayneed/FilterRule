import requests
import os
from datetime import datetime, timezone, timedelta

SOURCES = [
    "https://raw.githubusercontent.com/v2fly/domain-list-community/master/data/apple",
    "https://raw.githubusercontent.com/v2fly/domain-list-community/master/data/icloud",
    "https://raw.githubusercontent.com/v2fly/domain-list-community/master/data/apple-cn"
]

SCRIPT_NAME = "generate_apple.py"

OUTPUTS = [
    {"file": "list/Auto_apple_cn.list",      "fmt": "qx"},
    {"file": "loon-rule/Auto_apple_cn.list", "fmt": "loon"},
]


def get_data(url):
    try:
        resp = requests.get(url, timeout=10)
        resp.raise_for_status()
        return resp.text.splitlines()
    except Exception as e:
        print(f"Error fetching {url}: {e}")
        return []


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


def fmt_rule(typ, val, fmt):
    """typ: 'domain' | 'suffix'"""
    if typ == 'domain':
        return f"DOMAIN,{val}" if fmt == "loon" else f"host, {val}"
    return f"DOMAIN-SUFFIX,{val}" if fmt == "loon" else f"host-suffix, {val}"


def write_rules(rules):
    """rules: list of (type, value) tuples"""
    now_cst = datetime.now(timezone(timedelta(hours=8))).strftime("%Y-%m-%d %H:%M CST")

    for output in OUTPUTS:
        rule_lines = [fmt_rule(typ, val, output["fmt"]) for typ, val in sorted(rules)]
        new_body = "\n".join(rule_lines)

        old_body = read_old_rules(output["file"])
        status = "No Changes" if (old_body is not None and old_body == new_body) else "Updated"

        header = [
            f"# Apple & iCloud China (Auto-Generated)",
            f"# Maintained by: scripts/{SCRIPT_NAME}",
            f"# Last Updated: {now_cst}",
            f"# Source: v2fly/domain-list-community",
            f"# Total Rules: {len(rules)}",
            f"# Status: {status}",
            "",
        ]

        os.makedirs(os.path.dirname(output["file"]), exist_ok=True)
        with open(output["file"], 'w', encoding='utf-8') as f:
            f.write('\n'.join(header + rule_lines))

        print(f"✅ {output['file']}  ({status})")


def main():
    rules = set()  # (type, value) tuples

    print("正在拉取 Apple/iCloud 社区规则...")

    for url in SOURCES:
        lines = get_data(url)
        for line in lines:
            line = line.strip()
            if not line or line.startswith('#'):
                continue

            parts = line.split()
            domain_raw = parts[0]

            if domain_raw.startswith('include:'):
                continue

            if ':' in domain_raw:
                type_tag, value = domain_raw.split(':', 1)
                if type_tag == 'full':
                    rules.add(('domain', value))
            else:
                rules.add(('suffix', domain_raw))

    write_rules(rules)


if __name__ == "__main__":
    main()
