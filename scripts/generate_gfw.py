import requests
import base64
import os

GFW_URL = "https://raw.githubusercontent.com/gfwlist/gfwlist/master/gfwlist.txt"
OUTPUT_FILE = "list/gfw.list"
POLICY = "PROXY"

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
    """
    清洗域名函数：
    1. 去除路径（/及其后面的内容）
    2. 去除端口（:及其后面的内容，虽然少见但为了保险）
    3. 验证是否是有效域名格式
    """
    # 【关键修复】 去除路径，例如 example.com/foo -> example.com
    if '/' in domain_str:
        domain_str = domain_str.split('/')[0]
    
    # 去除端口号（可选，视情况而定，一般 host-suffix 不带端口）
    if ':' in domain_str:
        domain_str = domain_str.split(':')[0]

    domain_str = domain_str.strip()
    
    # 简单验证：必须包含点，且不能包含空格或通配符
    if '.' in domain_str and ' ' not in domain_str and '*' not in domain_str:
        return domain_str
    return None

def main():
    lines = fetch_and_decode()
    domains = set()

    print(f"正在解析 {len(lines)} 行规则...")

    for line in lines:
        line = line.strip()
        # 跳过空行、注释、正则表达式、白名单
        if not line or line.startswith('!') or line.startswith('[') or line.startswith('/') or line.startswith('@@'):
            continue

        raw_domain = ""

        # 1. 处理 ||example.com
        if line.startswith('||'):
            raw_domain = line[2:]
        # 2. 处理 .example.com
        elif line.startswith('.'):
            raw_domain = line[1:]
        # 3. 处理 |http://example.com (这种通常带协议头)
        elif line.startswith('|'):
            # 这种格式比较乱，且数量少，为了规则纯净度，建议跳过，或者尝试提取
            continue 
        else:
            # 普通行，假设是域名
            raw_domain = line

        # 调用清洗函数
        final_domain = clean_domain(raw_domain)
        if final_domain:
            domains.add(final_domain)

    # 生成文件
    output_lines = []
    output_lines.append(f"# GFWList (Auto-Converted)")
    output_lines.append(f"# Source: gfwlist/gfwlist")
    output_lines.append(f"# Total Rules: {len(domains)}\n")

    for domain in sorted(domains):
        # 过滤掉过短的错误提取（如 "com", "cn"）
        if len(domain) > 3: 
            output_lines.append(f"host-suffix, {domain}, {POLICY}")

    os.makedirs(os.path.dirname(OUTPUT_FILE), exist_ok=True)
    with open(OUTPUT_FILE, 'w', encoding='utf-8') as f:
        f.write('\n'.join(output_lines))

    print(f"✅ GFWList 生成完毕: {OUTPUT_FILE}, 共 {len(domains)} 条规则")

if __name__ == "__main__":
    main()
