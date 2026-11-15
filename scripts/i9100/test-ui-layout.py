#!/usr/bin/env python3
"""Compare recovered ARM flag offsets with original getters and real objects."""
import os,sys
if os.environ.get('I9100_CPU_CAPPED')!='1':
    os.execvpe('taskset',['taskset','-c','0-13','nice','-n10','ionice','-c2','-n7',sys.executable,'-B',__file__,*sys.argv[1:]],dict(os.environ,I9100_CPU_CAPPED='1'))
import argparse,importlib.util,json,mmap,struct,subprocess,re
from pathlib import Path
here=Path(__file__).resolve().parent
s=importlib.util.spec_from_file_location('ui_original',here/'research-ios6-ui.py')
r=importlib.util.module_from_spec(s);s.loader.exec_module(r)
p=argparse.ArgumentParser(description=__doc__);p.add_argument('--layout',type=Path,required=True)
p.add_argument('--hierarchy',type=Path,required=True);p.add_argument('--output',type=Path,required=True);a=p.parse_args()
j=json.loads(a.layout.read_text());e=json.loads(a.hierarchy.read_text());out=a.output.resolve()
assert out.is_relative_to(r.root/'research') and not out.exists();out.mkdir()
table=next(o for o in e['objects'].values() if o['class_name']=='UITableView')
raw=(a.hierarchy.parent/('object-'+table['address'][2:]+'.bin')).read_bytes()
field=next(x for x in j['classes']['UITableView']['ivars'] if x['name']=='_tableFlags')
fields=r.flag_fields(field['type']);bits=int.from_bytes(raw[field['offset']:field['offset']+field['size']],'little')
values={x['name']:(bits>>x['bit'])&((1<<x['width'])-1) for x in fields}
offsets={x['name']:x['bit'] for x in fields}
assert offsets['style']==107 and offsets['allowsSelection']==133 and offsets['allowsMultipleSelection']==135
assert values['style']==1 and values['allowsSelection']==1 and values['ignoreTouchSelect']==0 and values['delegateDidSelectRow']==1
# Confirm the interleaved ordinary integers with an ARM C record layout.
decl=[]
for x in re.finditer(r'"([^"]+)"(b[0-9]+|I)',field['type']):
    decl.append('unsigned int '+x[1]+(':'+x[2][1:] if x[2].startswith('b') else '')+';')
source='struct TableFlags {\n'+'\n'.join(decl)+'\n};\nstruct TableFlags flags;\nint selected(void){return flags.allowsSelection;}\n'
(out/'layout.c').write_text(source)
result=subprocess.run(['clang','-target','armv7-apple-darwin','-Xclang','-fdump-record-layouts','-c',out/'layout.c','-o',out/'layout.o'],capture_output=True,text=True,check=True)
(out/'compiler.txt').write_text(result.stdout+result.stderr)
for name in ('style','allowsSelection','allowsMultipleSelection','ignoreTouchSelect','delegateDidSelectRow'):
    match=re.search(r'([0-9]+):([0-9]+)-[0-9]+\s*\|\s*unsigned int '+name+r'\b',result.stdout)
    assert match and int(match[1])*8+int(match[2])==offsets[name],name
try:r.flag_fields('{?="a"b1"bad"[4I]}')
except ValueError:pass
else:raise AssertionError('Unsupported composite silently interpreted')
# Pure bitfield state retains its previous ARM offsets.
for name,ivar in (('UIApplication','_applicationFlags'),('UIView','_viewFlags'),('UIScrollView','_scrollViewFlags'),('UIGestureRecognizer','_gestureFlags')):
    obj=next(x for x in j['classes'][name]['ivars'] if x['name']==ivar)
    parsed=r.flag_fields(obj['type']);assert parsed==j['classes'][name]['bitfields'][ivar]
summary=dict(result='PASS',arm_compiler_layout=True,original_getter_offsets=offsets,
             real_table={k:values[k] for k in ('style','allowsSelection','allowsMultipleSelection','ignoreTouchSelect','delegateDidSelectRow')},
             scope='read-only flags, no GUI state repair')
(out/'result.json').write_text(json.dumps(summary,indent=2)+'\n')
print('PASS ARM compiler/original getter offsets, real selectable language table, unsupported shape rejection and unchanged pure-bitfield flags')
