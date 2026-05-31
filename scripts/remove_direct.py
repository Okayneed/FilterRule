"""删除 ManualSetting 中的 Direct/DIRECT 规则和关联注释 (QX+Loon)"""
import re, os

BASE = '/Users/humengqi/clacky_workspace/FilterRule'
files = [
    f'{BASE}/list/Manual_ManualSetting.list',
    f'{BASE}/loon-rule/Manual_ManualSetting.list',
]

for fpath in files:
    with open(fpath) as f:
        lines = [l.rstrip('\n') for l in f]
    
    new_lines = []
    skip_next_comment = False
    for i, line in enumerate(lines):
        s = line.strip()
        # 跳过多行标记（同花顺终端）
        if s.startswith('#') and ('同花顺' in s or '---' in s):
            continue
        # 跳过 Direct 规则
        if re.search(r',\s*(Direct|DIRECT)\s*$', s):
            continue
        new_lines.append(line)
    
    removed = len(lines) - len(new_lines)
    with open(fpath, 'w') as f:
        f.write('\n'.join(new_lines) + '\n')
    print(f"{os.path.basename(fpath)}: 删除 {removed} 行 → {len(new_lines)} 行")

print("完成")
