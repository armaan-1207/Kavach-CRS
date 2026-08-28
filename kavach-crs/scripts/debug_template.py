import re, sys
sys.stdout.reconfigure(encoding='utf-8', errors='replace')

line = '    result = subprocess.check_output(f"ping -n 1 {host}", shell=True, text=True)'
print("LINE:", line)

fstr_re = re.compile(r"""f["']([^"']+)["']""")
m = fstr_re.search(line)
print("fstr_re match:", m.group(1) if m else "NONE")

fstr_re2 = re.compile(r'f"([^"]*)"')
m2 = fstr_re2.search(line)
print("fstr_re2 match:", m2.group(1) if m2 else "NONE")

import sys
sys.path.insert(0, '.')
from reason.templates import patch_cmdinj
lines = open('target_app/app.py', encoding='utf-8', errors='replace').readlines()
finding = {'line': 49, 'cwe': 'CWE-78', 'id': 'F001'}
result = patch_cmdinj(lines, finding)
print("Template result:", result)
