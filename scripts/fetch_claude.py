import requests
import re
import os

OUTPUT = "list/claude.list"
SOURCE_URL = "https://ip.net.coffee/claude/site.html"

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
    """
    从页面内容中提取 Clash 格式的规则行（如 DOMAIN-SUFFIX,xxx），
    转换为 Quantumult X 格式。
    """
    rules = []
    seen = set()

    for line in text.splitlines():
        line = line.strip()

        # 跳过空行和注释
        if not line or line.startswith("#") or line.startswith("//"):
            continue

        # 匹配 Clash 规则行: DOMAIN-SUFFIX,xxx 或 IP-CIDR,xxx,no-resolve 等
        # 格式: TYPE,value[,optional_args]
        match = re.match(r"^(DOMAIN|DOMAIN-SUFFIX|DOMAIN-KEYWORD|IP-CIDR6?|IP-ASN),(.+)$", line)
        if not match:
            continue

        clash_type = match.group(1)
        rest = match.group(2)

        # 提取主值（去掉 no-resolve 等附加参数）
        value = rest.split(",")[0].strip()

        # 转换类型
        qx_type = TYPE_MAP.get(clash_type)
        if not qx_type:
            continue

        # 去重
        key = f"{qx_type},{value}"
        if key in seen:
            continue
        seen.add(key)

        rules.append(f"{qx_type}, {value}")

    # 自定义排序：先按类型分组，同类型内按值排序
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


def main():
    print(f"🌐 从 {SOURCE_URL} 获取 Claude 规则...")
    page = fetch_page(SOURCE_URL)
    rules = extract_rules(page)

    if not rules:
        print("⚠️ 未提取到任何规则，跳过更新")
        return

    header = [
        f"# Claude Rules (Auto-Generated)",
        f"# Source: {SOURCE_URL}",
        f"# Update Time: Automated Daily",
        f"# Total Rules: {len(rules)}",
        "",
    ]

    content = "\n".join(header + rules) + "\n"

    os.makedirs(os.path.dirname(OUTPUT), exist_ok=True)
    with open(OUTPUT, "w", encoding="utf-8") as f:
        f.write(content)

    print(f"✅ 生成 {OUTPUT} 成功（共 {len(rules)} 条规则）")


if __name__ == "__main__":
    main()
