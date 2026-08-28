import sys
sys.stdout.reconfigure(encoding='utf-8', errors='replace')
lines = open('target_app/app.py', encoding='utf-8', errors='replace').readlines()
keywords = ['ADMIN_SECRET', 'shell=True', 'base_dir +', 'SELECT']
for i, l in enumerate(lines, 1):
    ls = l.strip()
    if any(x in ls for x in keywords):
        print(f'line {i}: {ls}')
