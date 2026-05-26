#!/usr/bin/env python3
"""Convert QX format .list files to Loon format."""

import os
import re

LOON_RULE_DIR = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'loon-rule')

# QX type → Loon type mapping
TYPE_MAP = {
    'host': 'DOMAIN',
    'host-suffix': 'DOMAIN-SUFFIX',
    'host-keyword': 'DOMAIN-KEYWORD',
    'ip-cidr': 'IP-CIDR',
    'ip6-cidr': 'IP-CIDR6',
    'ip-asn': 'IP-ASN',
    'domain': 'DOMAIN',
    'domain-suffix': 'DOMAIN-SUFFIX',
    'domain-keyword': 'DOMAIN-KEYWORD',
}

# Policy normalization
POLICY_MAP = {
    'direct': 'DIRECT',
    'reject': 'REJECT',
    'proxy': 'PROXY',
}

def convert_line(line):
    """Convert a single QX rule line to Loon format."""
    stripped = line.strip()
    
    # Keep empty lines, comments, and section markers
    if not stripped:
        return line  # preserve original formatting
    if stripped.startswith('#') or stripped.startswith(';'):
        return line
    
    # Parse: rule_type, target[, policy]
    # Split on first two commas max
    parts = line.split(',', maxsplit=2)
    if len(parts) < 2:
        return line  # malformed, leave as-is
    
    rule_type = parts[0].strip().lower()
    target = parts[1].strip()
    policy = parts[2].strip() if len(parts) >= 3 else None
    
    # geoip is not supported in Loon
    if rule_type == 'geoip':
        return f"# [REMOVED] Loon不支持geoip规则: {stripped}"
    
    # Map rule type
    new_type = TYPE_MAP.get(rule_type)
    if new_type is None:
        return f"# [UNKNOWN TYPE] {stripped}"
    
    # Map policy if present
    if policy:
        policy_lower = policy.lower()
        new_policy = POLICY_MAP.get(policy_lower, policy)  # keep as-is for custom policy names
        
        # Preserve original line's comment indentation style
        return f"{new_type},{target},{new_policy}"
    else:
        return f"{new_type},{target}"


def convert_file(filepath):
    """Convert a .list file from QX to Loon format."""
    with open(filepath, 'r', encoding='utf-8') as f:
        lines = f.readlines()
    
    new_lines = []
    for line in lines:
        # preserve trailing newline
        had_newline = line.endswith('\n')
        converted = convert_line(line.rstrip('\n'))
        if had_newline:
            converted += '\n'
        new_lines.append(converted)
    
    with open(filepath, 'w', encoding='utf-8') as f:
        f.writelines(new_lines)
    
    print(f"  ✅ {os.path.basename(filepath)}")


def main():
    print("🔄 转换 QX .list → Loon .list ...\n")
    
    for fn in sorted(os.listdir(LOON_RULE_DIR)):
        if fn.endswith('.list'):
            filepath = os.path.join(LOON_RULE_DIR, fn)
            convert_file(filepath)
    
    print(f"\n✅ 全部转换完成！目录: {LOON_RULE_DIR}")


if __name__ == '__main__':
    main()
