import requests
import os
from datetime import datetime, timezone, timedelta

# 定义源和目标
TASKS = [
    {
        "name": "Google",
        "url": "https://raw.githubusercontent.com/v2fly/domain-list-community/master/data/google",
        "output": "list/Auto_google.list",
        "policy": "PROXY"
    }
]

SCRIPT_NAME = "generate_proxy_apps.py"


def parse_v2fly(url, policy):
    try:
        resp = requests.get(url, timeout=15)
        resp.raise_for_status()
        lines = resp.text.splitlines()
    except Exception as e:
        print(f"下载失败 {url}: {e}")
        return []

    rules = []

    for line in lines:
        # 1. 基础清洗：去空格，去注释
        line = line.strip()
        if not line or line.startswith('#'):
            continue

        # 2. 【关键修复】 去除行内属性 (例如 @cn) 和行内注释
        # v2fly 格式通常是 "domain.com @cn" 或 "domain.com # comment"
        # 我们只取空格前的第一部分
        parts = line.split()
        clean_content = parts[0]

        # 3. 跳过 include 指令
        if clean_content.startswith('include:'):
            continue

        # 4. 处理 IP-CIDR
        if clean_content.startswith('ip-cidr'):
            # 格式可能是 ip-cidr,1.2.3.4/24 或 ip-cidr:1.2.3.4/24
            # 无论哪种，我们只需要提取 IP 部分
            # 重新分割一下原始行以确保提取正确
            ip_parts = line.replace(',', ' ').replace(':', ' ').split()
            if len(ip_parts) >= 2:
                ip = ip_parts[1]
                rules.append(f"ip-cidr, {ip}")
            continue

        # 5. 处理域名
        # 格式可能为: "google.com" 或 "full:www.google.com"
        if ':' in clean_content:
            type_tag, value = clean_content.split(':', 1)
            if type_tag == 'full':
                rules.append(f"host, {value}")
            # 忽略 regexp 和其他类型
        else:
            # 默认为域名后缀
            rules.append(f"host-suffix, {clean_content}")

    return sorted(list(set(rules)))


def read_old_rules(filepath):
    """读取旧文件的规则体（跳过所有 # 开头的头注释行），用于对比是否更新"""
    try:
        with open(filepath, 'r', encoding='utf-8') as f:
            lines = f.readlines()
        # 跳过开头的注释行（#开头）和空行
        body_start = 0
        for i, line in enumerate(lines):
            if line.startswith('#') or line.strip() == '':
                body_start = i + 1
            else:
                break
        body = ''.join(lines[body_start:])
        # 去掉尾部换行，确保与新生成规则体格式一致
        if body.endswith('\n'):
            body = body[:-1]
        return body
    except FileNotFoundError:
        return None


def write_rules_with_header(task, rules):
    """写入规则文件，带统一标识头"""
    now_cst = datetime.now(timezone(timedelta(hours=8))).strftime("%Y-%m-%d %H:%M CST")

    # 生成新的规则体（用于对比，不含 header）
    new_body = "\n".join(rules)

    # 对比旧文件的规则体，判断是否真的有更新
    old_body = read_old_rules(task['output'])
    if old_body is not None and old_body == new_body:
        status = "No Changes"
    else:
        status = "Updated"

    header = [
        f"# {task['name']} Rules (Auto-Generated)",
        f"# Maintained by: scripts/{SCRIPT_NAME}",
        f"# Last Updated: {now_cst}",
        f"# Source: v2fly/domain-list-community",
        f"# Total Rules: {len(rules)}",
        f"# Status: {status}",
        "",
    ]

    final_content = "\n".join(header + rules)

    os.makedirs(os.path.dirname(task['output']), exist_ok=True)
    with open(task['output'], 'w', encoding='utf-8') as f:
        f.write(final_content)

    print(f"✅ 生成 {task['output']} 成功 (Status: {status})")


def main():
    for task in TASKS:
        print(f"正在处理 {task['name']} ...")
        rules = parse_v2fly(task['url'], task['policy'])
        write_rules_with_header(task, rules)


if __name__ == "__main__":
    main()
