#!/usr/bin/env python3
"""Inventory and index project documents; only explicit archives are mutated."""
import argparse,hashlib,json,os,re
from pathlib import Path
from datetime import datetime,timezone
ROOT=Path(__file__).resolve().parents[3]
def read(path):return path.read_text(encoding='utf-8-sig')
def sha(path):return hashlib.sha256(path.read_bytes()).hexdigest()
def category(name):
 if re.search(r'CHARG|CHARGE|POWER|BATTERY|LD9040|IDLE',name):return '充电与省电'
 if re.search(r'EMMC|VOLUME|STORAGE|SD-ROOT',name):return '存储'
 if re.search(r'AUDIO|MEDIA|CMSSESSION|COMMCENTER|MFC',name):return '媒体与音频'
 if re.search(r'HAPTIC|SENSOR|CAMERA|BCM|BLUETOOTH|WIRELESS|SDIO|MALI|GPU|PERIPHERAL',name):return '外设'
 if re.search(r'HID|TOUCH|DENSITY|METRICS|DISPLAY|SETUP|UI|FROZEN',name):return '界面与输入'
 if re.search(r'AUTOMATION|USB|PANIC|BOOT|ROOT|PMAP|SLAB|COPYPV|COREDATA|RENDER|MACHPORT',name):return '启动与内核'
 if re.search(r'LS-|LSD|TCC|MDNS|SANDBOX|AMFI|AKS|SPRINGBOARD|XPC|LAUNCHD',name):return '用户态与兼容'
 return '项目与交接'
def inventory():
 rows=[]
 for scope in ('research','xnu-S2I9100/docs','uniloader-S2I9100/docs'):
  base=ROOT/scope
  if not base.exists():continue
  for parent,dirs,files in os.walk(base):
   dirs[:]=[n for n in dirs if n not in ('.git','out','BUILD','build','__pycache__','node_modules') and not Path(parent,n).is_symlink()]
   if scope=='research':dirs[:]=[n for n in dirs if not n.startswith(('ref-','ref_','vendor','upstream'))]
   for name in files:
    p=Path(parent,name)
    if p.suffix.lower()!='.md' or p.is_symlink():continue
    text=read(p)
    if name.startswith('AGENTS') or p == ROOT/'research/DOCUMENT-INDEX.md':continue
    archive='archive' in p.relative_to(ROOT).parts
    title=next((line[2:].strip() for line in text.splitlines() if line.startswith('# ')),p.name)
    rows.append(dict(path=p.relative_to(ROOT).as_posix(),title=title,bytes=p.stat().st_size,sha256=sha(p),archive=archive,category='上游工程报告' if scope!='research' else category(name)))
 return rows
def rewrite_index(out):
 rows=inventory();(out/'document-inventory-after.json').write_text(json.dumps(dict(schema=1,created=datetime.now(timezone.utc).isoformat(),documents=rows),ensure_ascii=False,indent=2)+'\n',encoding='utf8')
 lines=['# 项目文档总目录','','本目录列出研究文档、归档记录和两仓已有工程报告。当前部署与下一步以 [NOTES.md](../NOTES.md) 为准；历史文档中的命令和镜像不能直接重跑。','']
 for group in ('充电与省电','存储','媒体与音频','外设','界面与输入','启动与内核','用户态与兼容','项目与交接','上游工程报告','历史归档'):
  selected=[r for r in rows if (r['archive'] if group=='历史归档' else not r['archive'] and r['category']==group)]
  if not selected:continue
  lines+=['## '+group,'','| 文档 | 位置 |','|---|---|']
  for row in sorted(selected,key=lambda r:r['path']):
   p=ROOT/row['path'];target=os.path.relpath(p,ROOT/'research').replace('\\','/')
   label=row['title'].replace('|','／');lines.append('| ['+label+']('+target+') | '+row['path'].replace('|','／')+' |')
  lines+=['']
 (ROOT/'research/DOCUMENT-INDEX.md').write_text('\n'.join(lines)+'\n',encoding='utf8')
 broken=[]
 for row in rows:
  p=ROOT/row['path'];text=read(p)
  for match in re.finditer(r'\[[^\]\n]*\]\(([^)\n]+)\)',text):
   target=match[1].strip().strip('<>').split('#',1)[0]
   if not target or re.match(r'^(https?|app|plugin|codex|mailto):',target):continue
   if target.startswith(('/root/','/mnt/','D:','C:','/D:/','/C:/')):continue
   target=re.sub(r':[0-9]+$','',target)
   resolved=p.parent/target
   if not resolved.exists():broken.append(dict(document=row['path'],target=target,archive=row['archive']))
 (out/'document-link-audit.json').write_text(json.dumps(dict(broken=broken,scope='Local explicit Markdown links only; code paths and historical runtime aliases are separate'),ensure_ascii=False,indent=2)+'\n',encoding='utf8')
 return len(rows),broken
def main():
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('--output',type=Path,required=True);p.add_argument('--archive',nargs='*',default=[]);p.add_argument('--apply',action='store_true');a=p.parse_args()
 out=a.output.resolve();assert out.is_relative_to(ROOT/'research/archive') and out.exists()
 if a.apply:
  result=[]
  for name in a.archive:
   assert re.fullmatch(r'[A-Z0-9_-]+\.md',name)
   source=ROOT/'research'/name;target=ROOT/'research/archive/weekly-20261121'/name
   assert source.is_file() and not source.is_symlink() and not target.exists()
   before=sha(source);target.parent.mkdir(exist_ok=True);source.rename(target);assert sha(target)==before
   text=read(target)
   # Move relative Markdown document links to the correct new depth. Exact
   # embedded code/evidence strings are left in the retained original text.
   original=out/'original-documents'/name;original.parent.mkdir(exist_ok=True);original.write_bytes(target.read_bytes())
   def move_link(m):
    targetname=m[1]
    if targetname.startswith(('#','http:','https:','/','D:','C:','../','archive/')):prefix='../../' if targetname.startswith(('../','archive/')) else ''
    else:prefix='../../'
    return ']('+prefix+targetname+')'
   updated=re.sub(r'\]\(([^)\n]+)\)',move_link,text)
   target.write_text(updated,encoding='utf8')
   source.write_text('# 已归档：'+name+'\n\n本周整理将旧阶段继续点归档，完整原文保留于 ['+name+'](archive/weekly-20261121/'+name+')。\n\n当前部署、未完成项和构建入口先读 [NOTES.md](../NOTES.md) 与 [研究入口](README.md)；历史计划不可直接重新执行。\n',encoding='utf8')
   result.append(dict(source=source.relative_to(ROOT).as_posix(),archive=target.relative_to(ROOT).as_posix(),original_sha256=before,retained_original_sha256=sha(original),link_rebased_archive_sha256=sha(target)))
  (out/'archived-document-manifest.json').write_text(json.dumps(result,ensure_ascii=False,indent=2)+'\n',encoding='utf8')
 total,broken=rewrite_index(out);print(json.dumps(dict(result='indexed',documents=total,broken=len(broken),active_broken=sum(not r['archive'] for r in broken)),ensure_ascii=False))
if __name__=='__main__':main()
