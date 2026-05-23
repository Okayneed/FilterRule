import requests
import os
from datetime import datetime, timezone

# v2fly 社区维护的权威列表
SOURCES = [
    "https://raw.githubusercontent.com/v2fly/domain-list-community/master/data/apple",
    "https://raw.githubusercontent.com/v2fly/domain-list-community/master/data/icloud",
    # 如果您特别介意云上贵州，可以加上 apple-cn，但其实上面的 apple 已经包含了大部分
    "https://raw.githubusercontent.com/v2fly/domain-list-community/master/data/apple-cn"
]

OUTPUT_FILE = "list/apple_cn.list"
SCRIPT_NAME = "generate_apple.py"


def get_data(url):
    try:
        resp = requests.get(url, timeout=10)
        resp.raise_for_status()
        return resp.text.splitlines()
    except Exception as e:
        print(f"Error fetching {url}: {e}")
        return []


def read_old_rules(filepath):
    """读取旧文件的规则体（跳过所有 # 开头的头注释行），用于对比是否更新"""
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


def write_rules(rules):
    now_utc = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")

    new_body = "\n".join(rules) + ("\n" if rules else "")
    old_body = read_old_rules(OUTPUT_FILE)
    if old_body is not None and old_body == new_body:
        status = "No Changes"
    else:
        status = "Updated"

    header = [
        f"# Apple & iCloud China (Auto-Generated)",
        f"# Maintained by: scripts/{SCRIPT_NAME}",
        f"# Last Updated: {now_utc}",
        f"# Source: v2fly/domain-list-community",
        f"# Total Rules: {len(rules)}",
        f"# Status: {status}",
        "",
    ]

    lines = header + [r for r in rules]

    os.makedirs(os.path.dirname(OUTPUT_FILE), exist_ok=True)
    with open(OUTPUT_FILE, 'w', encoding='utf-8') as f:
        f.write('\n'.join(lines))

    print(f"✅ Apple 规则生成完毕: {OUTPUT_FILE} (Status: {status})")


def main():
    domains = set()

    print("正在拉取 Apple/iCloud 社区规则...")

    for url in SOURCES:
        lines = get_data(url)
        for line in lines:
            line = line.strip()
            # 忽略注释和空行
            if not line or line.startswith('#'):
                continue

            # v2fly 的格式比较复杂，包含 include: 和 @cn 等属性
            # 我们只需要提取纯域名
            parts = line.split()
            domain_raw = parts[0]

            # 忽略 include 指令 (引用其他文件)
            if domain_raw.startswith('include:'):
                continue

            # 提取域名：v2fly 有时写 full:google.com 或 regexp:
            # 针对 Apple 列表，绝大多数是纯域名
            if ':' in domain_raw:
                type_tag, value = domain_raw.split(':', 1)
                if type_tag == 'full':
                    # full 对应 host
                    domains.add(f"host, {value}")
                # 忽略 regexp (QX 不好直接转)
            else:
                # 默认为 domain-suffix
                domains.add(f"host-suffix, {domain_raw}")

    write_rules(sorted(domains))


if __name__ == "__main__":
    main()
