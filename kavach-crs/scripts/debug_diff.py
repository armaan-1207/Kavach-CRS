import sys, os
sys.stdout.reconfigure(encoding='utf-8', errors='replace')
sys.path.insert(0, '.')

from prove.differential import _call_flask_route, _load_corpus, run_differential
from patch.patcher import apply_patch
from detect.sast import run_detection
from detect.triage import run_triage

# Find backups
import glob
backups = sorted(glob.glob('run_output/backups/app_F002_*.py'))
print("CWE-22 backup:", backups)

if backups:
    backup = backups[0]
    current = 'target_app/app.py'
    # Run safe_01 case
    print("\n--- safe_01 /file?name=readme.txt ---")
    print("orig:", _call_flask_route(backup, '/file', {'name': 'readme.txt'})[0])
    print("patched:", _call_flask_route(current, '/file', {'name': 'readme.txt'})[0])
    print("\n--- safe_02 /file?name=readme.txt (second call) ---")
    print("orig:", _call_flask_route(backup, '/file', {'name': 'readme.txt'})[0])
    print("patched:", _call_flask_route(current, '/file', {'name': 'readme.txt'})[0])
else:
    print("No backup found - need to run pipeline first")
