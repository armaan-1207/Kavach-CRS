import os
import re
from pathlib import Path

def remove_em_dash_and_oxford():
    for root, _, files in os.walk('.'):
        if '.git' in root or '__pycache__' in root or 'run_output' in root:
            continue
        for file in files:
            if not (file.endswith('.py') or file == 'README.md' or file.endswith('.yaml')):
                continue
            
            path = Path(root) / file
            try:
                content = path.read_text(encoding='utf-8')
                original = content
                
                # 1. Em dashes and equivalents
                content = content.replace('-', '-') # replace em dash with standard hyphen
                content = content.replace('-', '-')  # replace en dash with standard hyphen
                content = content.replace(' - ', ' - ') # replace double hyphen spacing
                
                # Specifically fix the README weird character seen in Get-Content if it's there
                # We'll just regex for anything that looks like an Oxford comma
                # 2. Oxford Comma (" and " -> " and ", " or " -> " or ")
                # We use regex to only target word boundaries or spaces to avoid breaking code logic like `, and_var`
                content = re.sub(r',\s+and\s+', ' and ', content)
                content = re.sub(r',\s+or\s+', ' or ', content)
                
                if content != original:
                    path.write_text(content, encoding='utf-8')
                    print(f"Fixed {path}")
            except Exception as e:
                pass

if __name__ == '__main__':
    remove_em_dash_and_oxford()
