#!/usr/bin/env python3
"""
sync_loon.py — 双目录一致性校验与对齐（QX 为唯一真源，Loon 为其镜像）

背景
----
仓库同时维护两套规则：`list/`（Quantumult X 语法）与 `loon-rule/`（Loon 语法）。
自动文件由生成脚本双写两目录，天然对齐；**手动文件靠人手双写，必然漂移**。
历史上多次出现「改了 QX 忘了 Loon」，导致 Loon 用户拿不到规则（或反之）。

本脚本把「对齐」从人工约定变成机器强制：
  - 按 QX 文件的结构与顺序重建 Loon 文件，使两侧**规则集与顺序**完全一致
  - Loon 平台专属规则（AND / OR / NOT 等 QX 无等价语法）原样保留
  - QX 平台专属规则（geoip）在 Loon 侧转为注释说明

模式
----
  python scripts/sync_loon.py            # 对齐（重建有差异的文件）
  python scripts/sync_loon.py --check    # 只校验，有差异退出码 1（供 CI 拦截）
  python scripts/sync_loon.py --quiet    # 只输出汇总
"""

import argparse
import os
import re
import sys

BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
QX_DIR = os.path.join(BASE, 'list')
LOON_DIR = os.path.join(BASE, 'loon-rule')

# ── QX 规则类型 → Loon 规则类型 ──
TYPE_MAP = {
    'host': 'DOMAIN',
    'host-suffix': 'DOMAIN-SUFFIX',
    'host-keyword': 'DOMAIN-KEYWORD',
    'domain': 'DOMAIN',
    'domain-suffix': 'DOMAIN-SUFFIX',
    'domain-keyword': 'DOMAIN-KEYWORD',
    'ip-cidr': 'IP-CIDR',
    'ip6-cidr': 'IP-CIDR6',
    'ip-asn': 'IP-ASN',
    'user-agent': 'USER-AGENT',
    'url-regex': 'URL-REGEX',
}

# ── 平台专属类型：单侧存在属预期行为 ──
QX_ONLY_TYPES = {'geoip'}                                  # Loon 无此语法
LOON_ONLY_TYPES = {'and', 'or', 'not', 'rule-set', 'final'}  # QX 无此语法

# ── 已声明的合法不对称：文件名 → {规则 key}，双向都不视为漂移 ──
# 仅用于「因平台能力差异而故意只在单侧存在」的规则，需逐条说明理由。
ALLOWED_ASYMMETRIC = {
    'Manual_ManualSetting.list': {
        # Loon 侧用 AND((DOMAIN,nat.qq.pw),(DEST-PORT,25560)) 精确匹配端口，
        # 刻意以窄规则替代 QX 侧的宽匹配 host-suffix qq.pw（QX 不支持 DEST-PORT）。
        # 来源：commit ef378da "添加 nat.qq.pw:25560 精确端口分流规则 (Loon)"
        ('domain-suffix', 'qq.pw'),
        ('and', '((domain,nat.qq.pw),(dest-port,25560))'),
    },
}


def is_rule_line(line):
    """是否为规则行（非空、非注释）。"""
    s = line.strip()
    return bool(s) and not s.startswith('#') and not s.startswith(';')


def parse_line(line, side):
    """解析一行规则，返回 dict 或 None。

    side='qx' 时把 QX 类型映射为 Loon 类型，使两侧 key 可直接比对。
    """
    if not is_rule_line(line):
        return None

    s = line.strip()

    # 复杂规则（AND/OR/NOT）的 target 内含逗号，单独解析
    m = re.match(r'^([A-Za-z][A-Za-z0-9-]*)\s*,(\(.*\))\s*(?:,\s*(.+))?$', s)
    if m and m.group(1).lower() in ('and', 'or', 'not'):
        return {
            'key': (m.group(1).lower(), m.group(2).strip().lower()),
            'type_raw': m.group(1),
            'target_raw': m.group(2).strip(),
            'policy_raw': (m.group(3) or '').strip(),
            'raw': s,
        }

    parts = [p.strip() for p in s.split(',')]
    if len(parts) < 2:
        return None

    rtype_raw, target_raw = parts[0], parts[1]
    policy_raw = parts[2] if len(parts) >= 3 else ''

    if side == 'qx':
        rtype_norm = TYPE_MAP.get(rtype_raw.lower(), rtype_raw.lower()).lower()
    else:
        rtype_norm = rtype_raw.lower()

    return {
        'key': (rtype_norm, target_raw.lower()),
        'type_raw': rtype_raw,
        'target_raw': target_raw,
        'policy_raw': policy_raw,
        'raw': s,
    }


def read_lines(path):
    with open(path, encoding='utf-8') as f:
        return f.read().split('\n')


def read_rules(path, side):
    """读取 .list 文件，返回带行号的规则列表。"""
    rules = []
    for lineno, line in enumerate(read_lines(path), 1):
        p = parse_line(line, side)
        if p:
            p['lineno'] = lineno
            rules.append(p)
    return rules


def to_loon_line(rule):
    """QX 规则 → Loon 语法行（逗号后无空格，类型大写）。"""
    loon_type = TYPE_MAP.get(rule['type_raw'].lower(), rule['type_raw'].upper())
    parts = [loon_type, rule['target_raw']]
    if rule['policy_raw']:
        parts.append(rule['policy_raw'])
    return ','.join(parts)


# ── Loon 合法规则类型（含平台专属） ──
LOON_VALID_TYPES = {
    'DOMAIN', 'DOMAIN-SUFFIX', 'DOMAIN-KEYWORD', 'DOMAIN-WILDCARD',
    'IP-CIDR', 'IP-CIDR6', 'IP-ASN', 'GEOIP',
    'USER-AGENT', 'URL-REGEX', 'PROTOCOL',
    'AND', 'OR', 'NOT', 'RULE-SET', 'FINAL', 'DEST-PORT',
}


def validate_loon():
    """校验 loon-rule/ 下所有文件的 Loon 语法，返回问题列表。

    独立于一致性比对，专门拦截语法层面的错误：
      - 残留 QX 类型（host / host-suffix / ip6-cidr ...）
      - 逗号后带空格（Loon 要求无空格）
      - 无法识别的规则类型
      - 字段数不足
    """
    issues = []
    for fn in sorted(os.listdir(LOON_DIR)):
        if not fn.endswith('.list'):
            continue
        path = os.path.join(LOON_DIR, fn)
        for lineno, line in enumerate(read_lines(path), 1):
            if not is_rule_line(line):
                continue
            s = line.strip()
            rtype = s.split(',', 1)[0].strip()

            # 逗号后带空格
            if re.search(r',\s', s):
                issues.append(f'  ❌ {fn} L{lineno}: 逗号后含空格 → {s}')

            # 残留 QX 类型
            if rtype.lower() in TYPE_MAP and rtype != rtype.upper():
                issues.append(f'  ❌ {fn} L{lineno}: 残留 QX 类型 `{rtype}` → {s}')
                continue

            # 类型合法性（复杂规则形如 AND,((...),(...)),Policy）
            if not re.match(r'^[A-Z][A-Z0-9-]*$', rtype):
                issues.append(f'  ❌ {fn} L{lineno}: 类型格式非法 `{rtype}` → {s}')
                continue
            if rtype not in LOON_VALID_TYPES:
                issues.append(f'  ❌ {fn} L{lineno}: 未知 Loon 类型 `{rtype}` → {s}')

    return issues


def diff_file(fn):
    """比对单个文件，返回 (missing, orphan)。missing=QX 有 Loon 无；orphan=反之。"""
    qx_rules = read_rules(os.path.join(QX_DIR, fn), 'qx')
    loon_rules = read_rules(os.path.join(LOON_DIR, fn), 'loon')

    allowed = ALLOWED_ASYMMETRIC.get(fn, set())

    qx_cmp = [r for r in qx_rules
              if r['key'][0] not in QX_ONLY_TYPES and r['key'] not in allowed]
    loon_cmp = [r for r in loon_rules
                if r['key'][0] not in LOON_ONLY_TYPES and r['key'] not in allowed]

    loon_keys = {r['key'] for r in loon_cmp}
    qx_keys = {r['key'] for r in qx_cmp}

    missing = [r for r in qx_cmp if r['key'] not in loon_keys]
    orphan = [r for r in loon_cmp if r['key'] not in qx_keys]
    return missing, orphan


def rebuild_loon(fn):
    """以 QX 文件为模板重建 Loon 文件：同结构、同顺序、语法转换。

    - 注释与空行按 QX 原样保留
    - 规则行按 QX 顺序转为 Loon 语法
    - QX 专属类型（geoip）转为注释
    - 已声明的合法不对称规则跳过（如 qq.pw，Loon 侧用精确端口规则替代）
    - Loon 专属规则（AND 等）追加在末尾，保持不丢失
    - # Total Rules 头重新计算
    """
    qx_lines = read_lines(os.path.join(QX_DIR, fn))
    loon_path = os.path.join(LOON_DIR, fn)
    loon_rules = read_rules(loon_path, 'loon')

    allowed = ALLOWED_ASYMMETRIC.get(fn, set())

    # Loon 平台专属规则需原样保留
    loon_exclusive = [r for r in loon_rules if r['key'][0] in LOON_ONLY_TYPES]

    out = []
    total = 0

    for line in qx_lines:
        if not line.strip():
            out.append('')
            continue
        if line.strip().startswith(('#', ';')):
            out.append(line)
            continue

        p = parse_line(line, 'qx')
        if p is None:
            out.append(line)
            continue

        if p['key'][0] in QX_ONLY_TYPES:
            out.append(f"# [REMOVED] Loon不支持{p['type_raw']}规则: {p['raw']}")
            continue

        # 合法不对称：该规则刻意不在 Loon 侧存在
        if p['key'] in allowed:
            continue

        out.append(to_loon_line(p))
        total += 1

    # 追加 Loon 专属规则
    for r in loon_exclusive:
        out.append(r['raw'])
        total += 1

    # 去掉尾部空行
    while out and not out[-1].strip():
        out.pop()

    # 刷新 # Total Rules
    out = [re.sub(r'^#\s*Total Rules:\s*\d+', f'# Total Rules: {total}', l) for l in out]

    with open(loon_path, 'w', encoding='utf-8') as f:
        f.write('\n'.join(out) + '\n')

    return total


def main():
    ap = argparse.ArgumentParser(description='校验并对齐 QX / Loon 双目录规则')
    ap.add_argument('--check', action='store_true', help='只校验不写入，有差异退出码 1')
    ap.add_argument('--quiet', action='store_true', help='只输出汇总')
    args = ap.parse_args()

    files = sorted(f for f in os.listdir(QX_DIR) if f.endswith('.list'))

    if not args.quiet:
        print('=' * 62)
        print('双目录一致性校验（真源: list/  →  镜像: loon-rule/）')
        print('=' * 62)

    total_missing = total_orphan = 0
    problems = []
    dirty = []

    for fn in files:
        if not os.path.exists(os.path.join(LOON_DIR, fn)):
            problems.append(f'  ❌ loon-rule/{fn} 不存在')
            continue

        missing, orphan = diff_file(fn)
        total_missing += len(missing)
        total_orphan += len(orphan)

        if not missing and not orphan:
            if not args.quiet:
                print(f'  ✅ {fn}')
            continue

        dirty.append(fn)
        if missing:
            problems.append(f'  ⚠️  {fn}: Loon 侧缺 {len(missing)} 条')
            for r in missing[:8]:
                problems.append(f'        QX L{r["lineno"]}: {r["raw"]}')
            if len(missing) > 8:
                problems.append(f'        … 另有 {len(missing) - 8} 条')
        if orphan:
            problems.append(f'  ⚠️  {fn}: Loon 侧孤儿 {len(orphan)} 条（QX 已无）')
            for r in orphan[:8]:
                problems.append(f'        Loon L{r["lineno"]}: {r["raw"]}')
            if len(orphan) > 8:
                problems.append(f'        … 另有 {len(orphan) - 8} 条')

    if problems and not args.quiet:
        print()
        print('\n'.join(problems))

    # ── Loon 语法校验（独立于一致性比对）──
    syntax_issues = validate_loon()
    if syntax_issues:
        print()
        print('=' * 62)
        print(f'Loon 语法校验：发现 {len(syntax_issues)} 处问题')
        print('=' * 62)
        print('\n'.join(syntax_issues))

    print()
    print('=' * 62)
    print(f'  Loon 侧缺失: {total_missing} 条')
    print(f'  Loon 侧孤儿: {total_orphan} 条')
    print(f'  Loon 语法问题: {len(syntax_issues)} 处')
    print('=' * 62)

    if args.check:
        if syntax_issues:
            print('❌ Loon 语法校验未通过')
            return 1
        if total_missing or total_orphan:
            print('❌ 双目录不一致，请运行 python scripts/sync_loon.py 对齐')
            return 1
        print('✅ 双目录一致，语法校验通过')
        return 0

    if not dirty:
        print('✅ 双目录已一致，无需改动')
        return 0

    for fn in dirty:
        n = rebuild_loon(fn)
        print(f'  🔧 已重建 loon-rule/{fn}（{n} 条规则）')
    print('✅ 对齐完成')

    # 重建后再校验一次，确保幂等收敛
    remain_m = remain_o = 0
    for fn in files:
        m, o = diff_file(fn)
        remain_m += len(m)
        remain_o += len(o)
    if remain_m or remain_o:
        print(f'❌ 对齐后仍存在差异：缺失 {remain_m} / 孤儿 {remain_o}（脚本异常）')
        return 1
    print('✅ 复校验通过')
    return 0


if __name__ == '__main__':
    sys.exit(main())
