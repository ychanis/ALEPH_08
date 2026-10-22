"""Create a deterministic public source snapshot from an explicit non-secret whitelist."""
from pathlib import Path
import json, zipfile, shutil
root=Path(__file__).resolve().parent.parent
paths=[]
for directory in ['app','lib','db','drizzle','docs','tests','public/original','build','scripts']:
    for p in (root/directory).rglob('*'):
        if p.is_file() and p.suffix in ['.ts','.tsx','.js','.mjs','.css','.html','.md','.json','.sql','.py','.sh','.cjs'] and not any(x in p.parts for x in ['node_modules','.sites-runtime','.wrangler']):paths.append(p)
for name in ['README.md','package.json','pnpm-lock.yaml','pnpm-workspace.yaml','vite.config.ts','tsconfig.json','cloudflare-env.d.ts','drizzle.config.ts','.openai/hosting.json','.gitignore']:
    p=root/name
    if p.is_file():paths.append(p)
paths=sorted(set(paths))
files=[{'path':str(p.relative_to(root)),'content':p.read_text()} for p in paths]
(root/'public/source-files.json').write_text(json.dumps(files,ensure_ascii=False,indent=2)+'\n')
with zipfile.ZipFile(root/'public/ALEPH_08-source.zip','w',zipfile.ZIP_DEFLATED) as z:
    for p in paths:z.write(p,'ALEPH_08/'+str(p.relative_to(root)))
    z.write(root/'public/source-files.json','ALEPH_08/public/source-files.json')
    for name in ['automated-evidence.json','DEVICE-CHECK.md']:
        shutil.copyfile(root/'docs'/name,root/'public'/name)
        z.write(root/'docs'/name,'ALEPH_08/public/'+name)
print(f'Public source: {len(files)} files; secrets/runtime data excluded')
