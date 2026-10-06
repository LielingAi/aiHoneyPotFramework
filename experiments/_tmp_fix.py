# -*- coding: utf-8 -*-
p = 'static/js/views.js'
lines = open(p, encoding='utf-8').read().split('\n')
out = []
i = 0
BS = chr(92)
while i < len(lines):
    ln = lines[i]
    if 'urls.join("' in ln and ln.rstrip().endswith('"'):
        out.append('    hooks.value = urls.join("' + BS + 'n");')
        if i + 1 < len(lines) and lines[i + 1].strip() == '");':
            i += 2
            continue
        i += 1
        continue
    if 'hooks.value.split("' in ln and '.map(' not in ln:
        # 多行 split 同样规整
        out.append('            const list = hooks.value.split("' + BS + 'n")'
                   '.map((x) => x.trim()).filter(Boolean);')
        if i + 1 < len(lines) and lines[i + 1].strip() == '")':
            i += 2
            continue
        i += 1
        continue
    out.append(ln)
    i += 1
open(p, 'w', encoding='utf-8').write('\n'.join(out))
print('done')
