##Google,telegram
import requests
import os

# 定义源和目标
TASKS = [
    {
        "name": "Google",
        "url": "https://raw.githubusercontent.com/v2fly/domain-list-community/master/data/google",
        "output": "list/google.list",
        "policy": "PROXY" # 通常走代理
    },
    {
        "name": "Telegram",
        "url": "https://raw.githubusercontent.com/v2fly/domain-list-community/master/data/telegram",
        "output": "list/telegram.list",
        "policy": "PROXY"
    }
]

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
        line = line.strip()
        if not line or line.startswith('#'):
            continue
        
        # 处理 include (简单跳过，防止递归过于复杂)
        if line.startswith('include:'):
            continue

        # 处理 IP-CIDR (Telegram 特别重要)
        # v2fly 格式: ip-cidr, 1.2.3.4/24
        if line.startswith('ip-cidr'):
            # 清洗一下格式，有些可能是 "ip-cidr, 1.1.1.1/24"
            parts = line.replace(',', ' ').split()
            if len(parts) >= 2:
                ip = parts[1]
                rules.append(f"ip-cidr, {ip}")
            continue

        # 处理域名
        # 格式可能为: "google.com" 或 "full:www.google.com" 或 "regexp:..."
        if ':' in line:
            type_tag, value = line.split(':', 1)
            if type_tag == 'full':
                rules.append(f"host, {value}")
            # 忽略 regexp，QX 转换容易出错
        else:
            # 默认为域名后缀
            rules.append(f"host-suffix, {line}")

    return sorted(list(set(rules))) # 去重并排序

def main():
    for task in TASKS:
        print(f"正在处理 {task['name']} ...")
        rules = parse_v2fly(task['url'], task['policy'])
        
        # 写入文件
        header = [
            f"# {task['name']} Rules (Auto-Generated)",
            f"# Source: v2fly/domain-list-community",
            f"# Total Rules: {len(rules)}",
            ""
        ]
        
        content = "\n".join(header + rules)
        
        os.makedirs(os.path.dirname(task['output']), exist_ok=True)
        with open(task['output'], 'w', encoding='utf-8') as f:
            f.write(content)
        
        print(f"✅ 生成 {task['output']} 成功")

if __name__ == "__main__":
    main()
