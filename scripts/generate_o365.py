import requests
import json
import os

# 微软官方 Office 365 中国版接口
URL = "https://endpoints.office.com/endpoints/China?clientrequestid=b10c5ed1-bad1-445f-b386-b919946339a7"
# 输出文件名
OUTPUT_FILE = "list/o365_cn.list"

def main():
    print("正在获取数据...")
    try:
        response = requests.get(URL, timeout=30)
        response.raise_for_status()
        data = response.json()
    except Exception as e:
        print(f"获取数据失败: {e}")
        exit(1)

    domains = set()
    ipv4_list = set()
    ipv6_list = set()

    print("正在解析数据...")
    for item in data:
        # 提取域名
        if 'urls' in item:
            for url in item['urls']:
                # 移除通配符 *. 和开头 . 以适配 host-suffix
                clean_url = url.lstrip('*').lstrip('.')
                if clean_url:
                    domains.add(clean_url)
        
        # 提取 IP
        if 'ips' in item:
            for ip in item['ips']:
                if ':' in ip:
                    ipv6_list.add(ip)
                else:
                    ipv4_list.add(ip)

    # 准备写入内容
    lines = []
    lines.append("# Office 365 China (21Vianet) Auto-Generated Rules")
    lines.append("# Source: Microsoft Official Endpoint")
    lines.append(f"# Total Domains: {len(domains)}")
    lines.append(f"# Total IPv4: {len(ipv4_list)}")
    lines.append("")

    lines.append("; --- Domains (host-suffix) ---")
    for domain in sorted(domains):
        lines.append(f"host-suffix, {domain}")

    lines.append("")
    lines.append("; --- IPv4 Ranges (ip-cidr) ---")
    # 简单的 IP 排序
    for ip in sorted(ipv4_list, key=lambda x: int(x.split('.')[0])):
        lines.append(f"ip-cidr, {ip}")

    # 如果需要 IPv6，取消下面注释
    # lines.append("")
    # lines.append("; --- IPv6 Ranges (ip6-cidr) ---")
    # for ip in sorted(ipv6_list):
    #     lines.append(f"ip6-cidr, {ip}")

    # 确保输出目录存在
    os.makedirs(os.path.dirname(OUTPUT_FILE), exist_ok=True)

    # 写入文件
    with open(OUTPUT_FILE, 'w', encoding='utf-8') as f:
        f.write('\n'.join(lines))
    
    print(f"成功生成规则文件: {OUTPUT_FILE}")

if __name__ == "__main__":
    main()
