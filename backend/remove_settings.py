import re

with open('app/main.py', 'r', encoding='utf-8') as f:
    content = f.read()

# Remove get_settings function
pattern = re.compile(r'\n\n@app\.get\("/api/settings".*?return \{.*?\}\n', re.DOTALL)
content = pattern.sub('', content)

with open('app/main.py', 'w', encoding='utf-8') as f:
    f.write(content)
