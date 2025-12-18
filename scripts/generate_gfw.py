import requests
import base64
import os

# GFWList 官方镜像源 (GitHub Raw)
GFW_URL = "https://raw.githubusercontent.com/gfwlist/gfwlist/master/gfwlist.txt"
OUTPUT_FILE = "list/gfw.list"
POLICY = "PROXY"

def fetch_and_decode():
    print("正在下载 GFWList...")
    try:
        resp = requests.get(GFW_URL, timeout=30)
        resp.raise_for_status()
        # GFWList 是 Base64 编码的
        decoded_content = base64.b64decode(resp.content).decode('utf-8')
        return decoded_content.splitlines()
    except Exception as e:
        print(f"GFWList 下载或解码失败: {e}")
        return []

def main():
    lines = fetch_and_decode()
    domains = set()

    print(f"正在解析 {len(lines)} 行规则...")

    for line in lines:
        line = line.strip()
        # 跳过空行、注释、正则表达式(/.../)、以及 @@ 开头的白名单
        if not line or line.startswith('!') or line.startswith('[') or line.startswith('/') or line.startswith('@@'):
            continue

        # 处理 AdBlock 语法
        # 1. ||example.com -> host-suffix
        if line.startswith('||'):
            domain = line[2:]
            domains.add(domain)
        # 2. .example.com -> host-suffix
        elif line.startswith('.'):
            domain = line[1:]
            domains.add(domain)
        # 3. |http://example.com -> 这种很难转为纯域名规则，跳过或尝试提取
        # 为了规则纯净度，我们只提取明确的域名后缀
        else:
            # 简单的域名行
            if '.' in line and ' ' not in line and '*' not in line:
                domains.add(line)

    # 生成文件内容
    output_lines = []
    output_lines.append(f"# GFWList (Auto-Converted)")
    output_lines.append(f"# Source: gfwlist/gfwlist")
    output_lines.append(f"# Total Rules: {len(domains)}\n")

    for domain in sorted(domains):
        # 过滤掉一些明显的杂质
        if len(domain) > 3: 
            output_lines.append(f"host-suffix, {domain}, {POLICY}")

    os.makedirs(os.path.dirname(OUTPUT_FILE), exist_ok=True)
    with open(OUTPUT_FILE, 'w', encoding='utf-8') as f:
        f.write('\n'.join(output_lines))

    print(f"✅ GFWList 生成完毕: {OUTPUT_FILE}, 共 {len(domains)} 条规则")

if __name__ == "__main__":
    main()
