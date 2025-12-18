import requests
import os

# v2fly 社区维护的权威列表
SOURCES = [
    "https://raw.githubusercontent.com/v2fly/domain-list-community/master/data/apple",
    "https://raw.githubusercontent.com/v2fly/domain-list-community/master/data/icloud",
    # 如果您特别介意云上贵州，可以加上 apple-cn，但其实上面的 apple 已经包含了大部分
    "https://raw.githubusercontent.com/v2fly/domain-list-community/master/data/apple-cn"
]

OUTPUT_FILE = "list/apple_cn.list"

def get_data(url):
    try:
        resp = requests.get(url, timeout=10)
        resp.raise_for_status()
        return resp.text.splitlines()
    except Exception as e:
        print(f"Error fetching {url}: {e}")
        return []

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
                    domains.add(f"host, {value}, DIRECT")
                # 忽略 regexp (QX 不好直接转)
            else:
                # 默认为 domain-suffix
                domains.add(f"host-suffix, {domain_raw}, DIRECT")

    # 写入文件
    lines = []
    lines.append("# Apple & iCloud China (Auto-Generated)")
    lines.append("# Source: v2fly/domain-list-community")
    lines.append(f"# Total Rules: {len(domains)}\n")
    
    # 排序输出
    for rule in sorted(domains):
        lines.append(rule)

    os.makedirs(os.path.dirname(OUTPUT_FILE), exist_ok=True)
    with open(OUTPUT_FILE, 'w', encoding='utf-8') as f:
        f.write('\n'.join(lines))

    print(f"✅ Apple 规则生成完毕: {OUTPUT_FILE}")

if __name__ == "__main__":
    main()
