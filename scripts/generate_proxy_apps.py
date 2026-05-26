import requests
import os
from datetime import datetime, timezone, timedelta

# 定义源和目标
TASKS = [
    {
        "name": "Google",
        "url": "https://raw.githubusercontent.com/v2fly/domain-list-community/master/data/google",
        "output_qx": "list/Auto_google.list",
        "output_loon": "loon-rule/Auto_google.list",
    }
]

SCRIPT_NAME = "generate_proxy_apps.py"


def parse_v2fly(url):
    """返回结构化规则列表: [(type, value), ...] type: 'domain'|'suffix'|'cidr'"""
    try:
        resp = requests.get(url, timeout=15)
        resp.raise_for_status()
        lines = resp.text.splitlines()
    except Exception as e:
        print(f"下载失败 {url}: {e}")
        return []

    rules = []
    seen = set()

    for line in lines:
        line = line.strip()
        if not line or line.startswith('#'):
            continue

        parts = line.split()
        clean_content = parts[0]

        if clean_content.startswith('include:'):
            continue

        if clean_content.startswith('ip-cidr'):
            ip_parts = line.replace(',', ' ').replace(':', ' ').split()
            if len(ip_parts) >= 2:
                key = ('cidr', ip_parts[1])
                if key not in seen:
                    seen.add(key)
                    rules.append(key)
            continue

        if ':' in clean_content:
            type_tag, value = clean_content.split(':', 1)
            if type_tag == 'full':
                key = ('domain', value)
                if key not in seen:
                    seen.add(key)
                    rules.append(key)
        else:
            key = ('suffix', clean_content)
            if key not in seen:
                seen.add(key)
                rules.append(key)

    return rules


def fmt_qx(rule):
    typ, val = rule
    if typ == 'domain':
        return f"host, {val}"
    elif typ == 'cidr':
        return f"ip-cidr, {val}"
    return f"host-suffix, {val}"


def fmt_loon(rule):
    typ, val = rule
    if typ == 'domain':
        return f"DOMAIN,{val}"
    elif typ == 'cidr':
        return f"IP-CIDR,{val}"
    return f"DOMAIN-SUFFIX,{val}"


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


def write_dual(task, rules):
    now_cst = datetime.now(timezone(timedelta(hours=8))).strftime("%Y-%m-%d %H:%M CST")

    outputs = [
        (task['output_qx'], fmt_qx, "QX"),
        (task['output_loon'], fmt_loon, "Loon"),
    ]

    for filepath, fmt_func, label in outputs:
        rule_lines = [fmt_func(r) for r in sorted(rules)]
        new_body = "\n".join(rule_lines)

        old_body = read_old_rules(filepath)
        status = "No Changes" if (old_body is not None and old_body == new_body) else "Updated"

        header = [
            f"# {task['name']} Rules (Auto-Generated)",
            f"# Maintained by: scripts/{SCRIPT_NAME}",
            f"# Last Updated: {now_cst}",
            f"# Source: v2fly/domain-list-community",
            f"# Total Rules: {len(rules)}",
            f"# Status: {status}",
            "",
        ]

        os.makedirs(os.path.dirname(filepath), exist_ok=True)
        with open(filepath, 'w', encoding='utf-8') as f:
            f.write('\n'.join(header + rule_lines))

        print(f"✅ [{label}] {filepath}  ({status})")


def main():
    for task in TASKS:
        print(f"正在处理 {task['name']} ...")
        rules = parse_v2fly(task['url'])
        write_dual(task, rules)


if __name__ == "__main__":
    main()
