"""拆分 ManualSetting: Only_US → goUS, Only_JP → goJP，去重并移出"""
import sys, os

def normalize(line):
    """标准化一行用于去重比较: 小写, 去空格"""
    return line.strip().lower().replace(' ', '')

def read_lines(path):
    if not os.path.exists(path): return [], []
    with open(path) as f:
        raw = f.readlines()
    lines = [l.rstrip('\n') for l in raw]
    return lines, raw  # lines (no \n), raw (with \n)

def get_type_and_domain(qx_line):
    """从 QX 格式行提取 type 和 domain: HOST-SUFFIX, domain 或 host-suffix, domain, policy"""
    parts = [p.strip() for p in qx_line.split(',')]
    if len(parts) >= 2:
        return parts[0], parts[1]
    return None, None

def extract_rules(manual_lines, policy):
    """从 ManualSetting 提取指定 policy 的规则，返回 (迁移规则列表, 剩余规则列表)"""
    to_move = []
    remaining = []
    for line in manual_lines:
        stripped = line.strip()
        if not stripped or stripped.startswith('#'):
            remaining.append(line)
            continue
        parts = [p.strip() for p in line.split(',')]
        if len(parts) >= 3 and parts[-1] == policy:
            to_move.append(line)
        else:
            remaining.append(line)
    return to_move, remaining

def convert_qx_to_qx_target(line, policy):
    """QX ManualSetting rule → QX goUS/goJP target format"""
    parts = [p.strip() for p in line.split(',')]
    if len(parts) < 2:
        return line
    typ, domain = parts[0], parts[1]
    # 统一大写类型
    typ_map = {
        'host-suffix': 'DOMAIN-SUFFIX',
        'host-keyword': 'DOMAIN-KEYWORD',
        'host': 'DOMAIN',
        'host-suffix': 'DOMAIN-SUFFIX',
    }
    typ = typ_map.get(typ.lower(), typ.upper())
    return f"{typ},{domain}"

def convert_loon_to_loon_target(line, policy):
    """LOON ManualSetting rule → LOON goUS/goJP target format (strip policy)"""
    parts = [p.strip() for p in line.split(',')]
    if len(parts) < 2:
        return line
    # LOON 格式已是 DOMAIN-SUFFIX,domain,policy，去掉 policy
    typ, domain = parts[0], parts[1]
    return f"{typ},{domain}"

def process(manual_path, target_path, policy, convert_func):
    """处理一个 ManualSetting → target 的迁移"""
    print(f"\n--- {manual_path} -> {target_path} (policy={policy}) ---")
    
    manual_lines, _ = read_lines(manual_path)
    target_lines, _ = read_lines(target_path)
    
    to_move, remaining = extract_rules(manual_lines, policy)
    
    if not to_move:
        print("  无规则需迁移")
        return False
    
    # 去重：检查目标文件已有规则
    existing_set = set()
    for line in target_lines:
        s = line.strip()
        if s and not s.startswith('#'):
            existing_set.add(normalize(s))
    
    new_added = []
    skipped = []
    for line in to_move:
        converted = convert_func(line, policy)
        if normalize(converted) in existing_set:
            skipped.append((line, converted))
        else:
            new_added.append(converted)
            existing_set.add(normalize(converted))
    
    print(f"  迁移 {len(to_move)} 条: 新增 {len(new_added)} 条, 已存在 {len(skipped)} 条")
    for l, c in skipped:
        print(f"    跳过(已存在): {c}")
    
    if new_added:
        # 更新目标文件
        new_target = target_lines + new_added
        with open(target_path, 'w') as f:
            f.write('\n'.join(new_target) + '\n')
        print(f"  写入 {target_path}: {len(target_lines)} -> {len(new_target)} 行")
    
    # 更新 ManualSetting
    with open(manual_path, 'w') as f:
        f.write('\n'.join(remaining) + '\n')
    print(f"  更新 {manual_path}: {len(manual_lines)} -> {len(remaining)} 行")
    
    return True

# ===== QX =====
qx_base = '/Users/humengqi/clacky_workspace/FilterRule'

process(
    f'{qx_base}/list/Manual_ManualSetting.list',
    f'{qx_base}/list/Manual_goUS.list',
    'Only_US',
    convert_qx_to_qx_target,
)
process(
    f'{qx_base}/list/Manual_ManualSetting.list',
    f'{qx_base}/list/Manual_goJP.list',
    'Only_JP',
    convert_qx_to_qx_target,
)

# ===== LOON =====
process(
    f'{qx_base}/loon-rule/Manual_ManualSetting.list',
    f'{qx_base}/loon-rule/Manual_goUS.list',
    'Only_US',
    convert_loon_to_loon_target,
)
process(
    f'{qx_base}/loon-rule/Manual_ManualSetting.list',
    f'{qx_base}/loon-rule/Manual_goJP.list',
    'Only_JP',
    convert_loon_to_loon_target,
)

print("\n===== 完成 =====")
