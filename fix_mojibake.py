import os
from pathlib import Path

bad_chars = ['-\u201d', '-\u201c', '-\u2014', '-\u009d', '-\u0093', '-\u0094', '-\"', ' - ']

def fix():
    for root, _, files in os.walk('.'):
        for file in files:
            if not file.endswith('.py'): continue
            path = Path(root) / file
            try:
                content = path.read_text(encoding='utf-8')
                original = content
                for b in bad_chars:
                    content = content.replace(b, ' - ')
                # special case for "- -  that might have been " - 
                content = content.replace('-\ufffd??', ' - ')
                content = content.replace('-\ufffd', ' - ')
                content = content.replace(' - ', ' - ')
                
                # Also, fix the specific ones we know:
                content = content.replace(' - ', ' - ')
                
                if content != original:
                    path.write_text(content, encoding='utf-8')
                    print(f"Fixed {path}")
            except Exception as e:
                pass

if __name__ == '__main__':
    fix()
