#!/usr/bin/env python3
"""
Audit all rule list files for duplicates and conflicts.
"""
import os
import re
from collections import defaultdict

LIST_DIR = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'loon-rule')

def parse_rules(filepath):
    """Parse a list file and return (rules, errors)."""
    rules = []  # [(line_raw, rule_type, target, policy, file_line)]
    errors = []
    with open(filepath, 'r', encoding='utf-8') as f:
        for line_no, line in enumerate(f, 1):
            line = line.strip()
            if not line or line.startswith('#') or line.startswith(';'):
                continue
            # Normalize case: HOST-SUFFIX → host-suffix, etc.
            # Split on first comma
            parts = line.split(',', maxsplit=2)
            if len(parts) < 2:
                errors.append((line_no, line, 'Malformed: less than 2 fields'))
                continue
            
            rule_type = parts[0].strip().lower()
            target = parts[1].strip()
            policy = parts[2].strip() if len(parts) >= 3 else None
            
            rules.append((line, rule_type, target, policy, line_no))
    
    return rules, errors

def normalize_asn(asn_str):
    """Normalize ASN string (e.g., '399358' or 'AS399358' → '399358')."""
    return asn_str.lstrip('as').strip()

def normalize_cidr4(cidr):
    """Normalize IPv4 CIDR for comparison."""
    return cidr.strip()

def normalize_cidr6(cidr):
    """Normalize IPv6 CIDR for comparison."""
    return cidr.strip().lower()

def audits():
    """Run full audit."""
    filenames = sorted(f for f in os.listdir(LIST_DIR) if f.endswith('.list'))
    
    all_rules = {}  # filename -> [(raw, type, target, policy, line)]
    all_errors = {}
    total_rules = 0
    
    for fn in filenames:
        filepath = os.path.join(LIST_DIR, fn)
        rules, errors = parse_rules(filepath)
        all_rules[fn] = rules
        all_errors[fn] = errors
        total_rules += len(rules)
        
        # Dump for debug
        # print(f"{fn}: {len(rules)} rules")
    
    # ── 1. DUPLICATES ──
    print("=" * 60)
    print("1. 重复规则检查 (文件内)")
    print("=" * 60)
    
    intra_dup_total = 0
    for fn in filenames:
        seen = defaultdict(list)  # (raw_line) → [line_nos]
        for raw, rt, tgt, pol, ln in all_rules[fn]:
            seen_key = raw
            seen[seen_key].append(ln)
        
        file_dups = 0
        for raw, lines in sorted(seen.items()):
            if len(lines) > 1:
                if file_dups == 0:
                    print(f"\n  📁 {fn}:")
                print(f"    Line {lines}: {raw}")
                file_dups += 1
                intra_dup_total += 1
        
        if file_dups == 0:
            print(f"  ✅ {fn}: 无重复")
    
    print(f"\n  ▶ 总计文件内重复: {intra_dup_total}")
    
    # ── 2. CROSS-FILE DUPLICATES ──
    print("\n" + "=" * 60)
    print("2. 跨文件重复规则检查")
    print("=" * 60)
    
    # Group by (rule_type, target) ignoring policy
    cross_index = defaultdict(list)  # (type, target) → [(fn, policy, line)]
    for fn in filenames:
        for raw, rt, tgt, pol, ln in all_rules[fn]:
            cross_index[(rt, tgt)].append((fn, pol, ln))
    
    cross_dup_total = 0
    for (rt, tgt), occurrences in sorted(cross_index.items()):
        if len(occurrences) > 1:
            # Check if it's the same file or different files
            file_set = set(o[0] for o in occurrences)
            if len(file_set) > 1:
                cross_dup_total += 1
                policies = ', '.join(f"{fn}(L{ln}, pol={pol or 'none'})" for fn, pol, ln in occurrences)
                print(f"  {rt}, {tgt}")
                print(f"    → {policies}")
    
    if cross_dup_total == 0:
        print("  ✅ 无跨文件重复")
    else:
        print(f"\n  ▶ 总计跨文件重复: {cross_dup_total}")
    
    # ── 3. CONFLICT CHECK ──
    print("\n" + "=" * 60)
    print("3. 冲突规则检查")
    print("=" * 60)
    print("   (相同域名在不同文件中策略不同，如 proxy vs Direct)")
    print()
    
    # Collect all host-type rules with their policy
    # For Auto files → implicit policy = "Proxy" (no explicit policy)
    # For Manual files → explicit policy (e.g., Direct, Only_US, Fast_All, Only_JP, Not_HK)
    AUTO_FILES = {'Auto_google.list', 'Auto_gfw.list', 'Auto_o365_cn.list', 
                  'Auto_apple_cn.list', 'Auto_claude.list'}
    
    domain_policy = defaultdict(list)  # domain → [(fn, policy, type)]
    
    for fn in filenames:
        for raw, rt, tgt, pol, ln in all_rules[fn]:
            # Only check domain-type rules
            if rt not in ('domain', 'domain-suffix', 'domain-keyword'):
                continue
            
            # Determine policy
            # Auto files → Proxy (implicit)
            # Manual files → explicit policy from rule
            if fn in AUTO_FILES:
                effective_policy = 'Proxy'
                explicit_policy = None
            else:
                if pol:
                    effective_policy = pol
                    explicit_policy = pol
                else:
                    # Manual file rule without policy → use filename as hint
                    effective_policy = fn.replace('Manual_', '').replace('.list', '')
                    explicit_policy = None
            
            domain_policy[(rt, tgt)].append((fn, effective_policy, explicit_policy, ln))
    
    # Now check for conflicts
    conflict_total = 0
    conflict_domains = defaultdict(list)  # (rt, tgt) → [(fn, pol, line)]
    
    for (rt, tgt), occurrences in sorted(domain_policy.items()):
        policies = set(o[1] for o in occurrences)
        files = set(o[0] for o in occurrences)
        
        # Only flag if in different files AND policies differ
        if len(files) > 1 and len(policies) > 1:
            # Special: some policies are subset relationships, not conflicts
            # e.g., "Fast_All" vs "Only_US" — Only_US is a stricter subset
            # We still flag them for manual review
            conflict_total += 1
            details = ', '.join(f"{fn}({pol}{' explicit' if exp else ' implicit'} L{ln})" 
                              for fn, pol, exp, ln in occurrences)
            print(f"  [{rt}] {tgt}")
            print(f"    → {details}")
    
    if conflict_total == 0:
        print("  ✅ 无冲突")
    else:
        print(f"\n  ▶ 总计冲突: {conflict_total}")
    
    # ── 4. CIDR OVERLAP CHECK (IP subnet overlaps) ──
    print("\n" + "=" * 60)
    print("4. IP CIDR 重叠检查 (文件内)")
    print("=" * 60)
    
    cidr_intra_total = 0
    for fn in filenames:
        seen_cidr = defaultdict(list)
        for raw, rt, tgt, pol, ln in all_rules[fn]:
            if rt in ('ip-cidr', 'ip6-cidr'):
                seen_cidr[(rt, tgt)].append(ln)
        
        cidr_dups = 0
        for (rt, cidr), lines in sorted(seen_cidr.items()):
            if len(lines) > 1:
                if cidr_dups == 0:
                    print(f"  📁 {fn}:")
                print(f"    Line {lines}: {rt}, {cidr}")
                cidr_dups += 1
        
        cidr_intra_total += cidr_dups
        if cidr_dups == 0:
            print(f"  ✅ {fn}: 无重复 CIDR")
    
    # ── 5. CROSS-FILE CIDR OVERLAP ──
    print("\n" + "=" * 60)
    print("5. IP CIDR 跨文件重叠检查")
    print("=" * 60)
    
    all_cidrs = defaultdict(list)  # (rt, cidr) → [(fn, line)]
    for fn in filenames:
        for raw, rt, tgt, pol, ln in all_rules[fn]:
            if rt in ('ip-cidr', 'ip6-cidr'):
                all_cidrs[(rt, tgt)].append((fn, ln))
    
    cidr_cross = 0
    for (rt, cidr), occurrences in sorted(all_cidrs.items()):
        file_set = set(o[0] for o in occurrences)
        if len(file_set) > 1:
            cidr_cross += 1
            locs = ', '.join(f"{fn}(L{ln})" for fn, ln in occurrences)
            print(f"  {rt}, {cidr}")
            print(f"    → {locs}")
    
    if cidr_cross == 0:
        print("  ✅ 无跨文件 CIDR 重叠")
    else:
        print(f"\n  ▶ 总计跨文件 CIDR 重叠: {cidr_cross}")
    
    # ── 6. ASN OVERLAP ──
    print("\n" + "=" * 60)
    print("6. ASN 跨文件重叠检查")
    print("=" * 60)
    
    all_asns = defaultdict(list)
    for fn in filenames:
        for raw, rt, tgt, pol, ln in all_rules[fn]:
            if rt == 'ip-asn':
                normalized = normalize_asn(tgt)
                all_asns[normalized].append((fn, ln, raw))
    
    asn_cross = 0
    for asn, occurrences in sorted(all_asns.items()):
        file_set = set(o[0] for o in occurrences)
        if len(file_set) > 1:
            asn_cross += 1
            locs = ', '.join(f"{fn}(L{ln}: {raw})" for fn, ln, raw in occurrences)
            print(f"  ASN {asn}")
            print(f"    → {locs}")
    
    if asn_cross == 0:
        print("  ✅ 无跨文件 ASN 重叠")
    else:
        print(f"\n  ▶ 总计跨文件 ASN 重叠: {asn_cross}")
    
    # ── SUMMARY ──
    print("\n" + "=" * 60)
    print("📊 检查概览")
    print("=" * 60)
    print(f"  文件数: {len(filenames)}")
    print(f"  总规则数: {total_rules}")
    print(f"  文件内重复: {intra_dup_total}")
    print(f"  跨文件重复: {cross_dup_total}")
    print(f"  策略冲突: {conflict_total}")
    print(f"  文件内 CIDR 重复: {cidr_intra_total}")
    print(f"  跨文件 CIDR 重叠: {cidr_cross}")
    print(f"  跨文件 ASN 重叠: {asn_cross}")
    print("=" * 60)


if __name__ == '__main__':
    audits()
