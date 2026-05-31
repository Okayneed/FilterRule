"""从 ManualSetting 剪切 Not_HK 规则 → Manual_NotHK.list (QX+Loon)"""
import os, re

BASE = '/Users/humengqi/clacky_workspace/FilterRule'

def process(ms_path, nothk_path, dir_label):
    with open(ms_path) as f:
        lines = [l.rstrip('\n') for l in f]
    
    nothk_rules = []
    remaining = []
    for line in lines:
        s = line.strip()
        if not s or s.startswith('#'):
            remaining.append(line)
        elif re.search(r',\s*Not_HK\s*$', s):
            # strip policy, keep TYPE,domain
            parts = [p.strip() for p in line.strip().split(',')]
            rule = ','.join(parts[:2])  # TYPE,domain
            nothk_rules.append(rule)
        else:
            remaining.append(line)
    
    if not nothk_rules:
        print(f"{dir_label}: 无 Not_HK 规则")
        return
    
    header = f"# Not HK Rules (Manually Maintained)\n# Maintained by: manual editing (no auto-script)\n"
    with open(nothk_path, 'w') as f:
        f.write(header)
        f.write('\n'.join(nothk_rules) + '\n')
    
    with open(ms_path, 'w') as f:
        f.write('\n'.join(remaining) + '\n')
    
    print(f"{dir_label}: 移出 {len(nothk_rules)} 条 → {os.path.basename(nothk_path)}, ManualSetting {len(lines)}→{len(remaining)} 行")

process(f'{BASE}/list/Manual_ManualSetting.list', f'{BASE}/list/Manual_NotHK.list', 'QX')
process(f'{BASE}/loon-rule/Manual_ManualSetting.list', f'{BASE}/loon-rule/Manual_NotHK.list', 'LOON')
print("完成")
