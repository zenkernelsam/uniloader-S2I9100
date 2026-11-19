#!/usr/bin/env python3
"""Read original BTServer function starts/imports and UART transport call sites."""
import argparse
import bisect
import hashlib
import json
import os
from pathlib import Path
import re
import struct
import sys
if os.environ.get('I9100_CPU_CAPPED')!='1':
    os.execvpe('taskset',['taskset','-c','0-13','nice','-n10','ionice','-c2','-n7',sys.executable,'-B',__file__,*sys.argv[1:]],dict(os.environ,I9100_CPU_CAPPED='1'))
ROOT=Path(__file__).resolve().parents[3]
sys.path.insert(0,str(ROOT/'assets/py-native-hid'))
from capstone import Cs,CS_ARCH_ARM,CS_MODE_THUMB,CS_MODE_ARM
from capstone.arm import ARM_OP_REG,ARM_OP_IMM,ARM_OP_MEM,ARM_REG_PC


def relevant_string(value):
    return value in ('bluetooth','BaudRate','Transport','H4','H4DS','H4BC','H5','BCSP','USB') or bool(re.search(
        r'/dev/|UART|transport-speed|transport-encoding|BT_HCI_TRANSPORT|HCI Transport|HCI Driver|com\.apple\.uart',value,re.I))


class MachO:
    def __init__(self,path):
        self.raw=path.read_bytes();b=self.raw
        if len(b)<28 or struct.unpack_from('<II',b)[0:2]!=(0xfeedface,12):raise ValueError('Expected original ARM32 Mach-O')
        self.segments=[];self.sections=[];self.sym=None;self.dy=None;self.uuid=None;self.functions=[];self.function_modes={};self.function_entries=[];self.entries={}
        pos=28;number,total=struct.unpack_from('<II',b,16);starts=None
        if number>256 or pos+total>len(b):raise ValueError('Unbounded/truncated Mach-O command table')
        for _ in range(number):
            cmd,length=struct.unpack_from('<II',b,pos)
            if length<8 or pos+length>28+total:raise ValueError('Invalid Mach-O command')
            if cmd==1:
                if length<56:raise ValueError('Truncated ARM32 segment')
                name=b[pos+8:pos+24].rstrip(b'\0').decode();vm,size,fo,fs=struct.unpack_from('<4I',b,pos+24)
                self.segments.append(dict(name=name,vm=vm,size=size,offset=fo,file_bytes=fs))
                if fo+fs>len(b) or fs>size:raise ValueError('Segment file range escaped image')
                for n in range(struct.unpack_from('<I',b,pos+48)[0]):
                    at=pos+56+n*68
                    if at+68>pos+length:raise ValueError('Section escaped load command')
                    label=b[at:at+16].rstrip(b'\0').decode();addr,size,off=struct.unpack_from('<III',b,at+32)
                    flags,r1,r2=struct.unpack_from('<III',b,at+56)
                    self.sections.append(dict(name=label,segment=name,address=addr,bytes=size,offset=off,flags=flags,reserved1=r1,reserved2=r2))
            if cmd==2:
                if length<24:raise ValueError('Truncated symbol command')
                self.sym=struct.unpack_from('<4I',b,pos+8)
            if cmd==11:
                if length<80:raise ValueError('Truncated indirect symbol command')
                self.dy=struct.unpack_from('<18I',b,pos+8)
            if cmd==27:
                if length<24:raise ValueError('Truncated UUID command')
                self.uuid=b[pos+8:pos+24].hex()
            if cmd==0x26:
                if length<16:raise ValueError('Truncated function-start command')
                starts=struct.unpack_from('<II',b,pos+8)
            pos+=length
        if not self.sym or not self.dy or not starts:raise ValueError('Require symbols, indirect table and function starts')
        base=next(s['vm'] for s in self.segments if s['name']=='__TEXT')
        offset,n=starts;end=offset+n;address=base
        if end>len(b):raise ValueError('Function table outside file')
        while offset<end:
            value=0;shift=0
            while True:
                if offset>=end or shift>28:raise ValueError('Truncated/unbounded function ULEB')
                byte=b[offset];offset+=1;value|=(byte&127)<<shift;shift+=7
                if not byte&128:break
            if not value:break
            address+=value
            code_address=address&~1
            self.function_entries.append(address)
            self.functions.append(code_address)
            self.function_modes[code_address]='thumb' if address&1 else 'arm'
            self.entries[code_address]=address
        text=next(s for s in self.sections if s['name']=='__text')
        if len(self.functions)>65536 or any(a<text['address'] or a>=text['address']+text['bytes'] for a in self.functions) or any(a>=b for a,b in zip(self.functions,self.functions[1:])):
            raise ValueError('Function start outside original text')
        if pos!=28+total:raise ValueError('Command count/bytes disagree')
        if self.sym[0]+12*self.sym[1]>len(b) or self.sym[2]+self.sym[3]>len(b) or self.dy[12]+4*self.dy[13]>len(b):
            raise ValueError('Symbol or string table escaped image')
        self.stubs={};self.pointers={}
        for section in self.sections:
            kind=section['flags']&255
            if kind not in (6,7,8):continue
            size=section['reserved2'] if kind==8 else 4
            if size<4 or section['bytes']%size:raise ValueError('Unknown original stub/pointer width')
            if section['reserved1']+section['bytes']//size>self.dy[13]:raise ValueError('Stub/pointer index escaped indirect table')
            for n in range(section['bytes']//size):
                entry=struct.unpack_from('<I',b,self.dy[12]+(section['reserved1']+n)*4)[0]
                if entry&0xc0000000:continue
                if entry>=self.sym[1]:raise ValueError('Indirect symbol outside table')
                strindex=struct.unpack_from('<I',b,self.sym[0]+entry*12)[0]
                if strindex>=self.sym[3]:raise ValueError('Imported string index escaped table')
                start=self.sym[2]+strindex;end=b.find(b'\0',start,self.sym[2]+self.sym[3])
                if end<start:raise ValueError('Unterminated imported symbol')
                table=self.stubs if kind==8 else self.pointers
                table[section['address']+n*size]=b[start:end].decode()
        self.strings={};self.all_strings={};self.cfstrings={}
        for s in self.sections:
            if s['name']!='__cstring':continue
            at=0
            for raw in b[s['offset']:s['offset']+s['bytes']].split(b'\0'):
                text=raw.decode('utf-8','replace')
                if text:self.all_strings[s['address']+at]=text
                if relevant_string(text):
                    self.strings[s['address']+at]=text
                at+=len(raw)+1
        for s in self.sections:
            if s['name']!='__cfstring':continue
            if s['bytes']%16:raise ValueError('Unaligned ARM32 constant CFString table')
            for at in range(0,s['bytes'],16):
                address,length=struct.unpack_from('<II',b,s['offset']+at+8)
                if address in self.all_strings and length==len(self.all_strings[address].encode('utf-8')):
                    self.cfstrings[s['address']+at]=self.all_strings[address]

    def offset(self,address,bytes=1):
        if bytes<0 or address<0 or address+bytes>0x100000000:raise ValueError('Invalid ARM32 byte range')
        for s in self.segments:
            if s['vm']<=address and address+bytes<=s['vm']+s['file_bytes']:
                return s['offset']+address-s['vm']
        raise ValueError(f'Address outside original bytes: {address:08x}')

    def word(self,address):
        try:return struct.unpack_from('<I',self.raw,self.offset(address,4))[0]
        except ValueError:return None

    def string(self,address):
        return self.all_strings.get(address,self.cfstrings.get(address))

    def function(self,address):
        n=bisect.bisect_right(self.functions,address&~1)-1
        if n<0:return None
        return self.functions[n]


def analyze(m,lo,hi):
    cs=Cs(CS_ARCH_ARM,CS_MODE_THUMB if m.function_modes[lo]=='thumb' else CS_MODE_ARM);cs.detail=True;regs={};refs=[];calls=[];lines=[]
    raw=m.raw[m.offset(lo,hi-lo):m.offset(lo,hi-lo)+hi-lo]
    instructions=list(cs.disasm(raw,lo));undecoded=lo+len(raw)-(instructions[-1].address+instructions[-1].size) if instructions else len(raw)
    for i in instructions:
        ops=i.operands;note='';mn=i.mnemonic
        target=(ops[0].imm&0xffffffff)&~1 if ops and ops[0].type==ARM_OP_IMM else None
        if mn in ('bl','blx') and target is not None:
            symbol=m.stubs.get(target,'')
            calls.append(dict(at=i.address,target=target,symbol=symbol,arguments={i.reg_name(r):dict(value=v,string=m.string(v)) for r,v in regs.items() if i.reg_name(r) in ('r0','r1','r2','r3')}))
            note=symbol
        written=None
        if ops and ops[0].type==ARM_OP_REG:
            reg=ops[0].reg
            if mn in ('mov','movs','movw') and len(ops)>1:
                written=ops[1].imm&0xffffffff if ops[1].type==ARM_OP_IMM else regs.get(ops[1].reg)
            elif mn=='movt' and len(ops)>1:
                written=((regs.get(reg,0)&65535)|(ops[1].imm<<16))&0xffffffff
            elif mn=='adr' and len(ops)>1:written=ops[1].imm&0xffffffff
            elif mn in ('add','adds','sub','subs','orr','orrs') and len(ops)>1:
                left=regs.get(ops[1].reg) if len(ops)>2 and ops[1].type==ARM_OP_REG else regs.get(reg)
                if len(ops)>2 and ops[1].reg==ARM_REG_PC:left=(i.address+4)&0xffffffff
                rhs=ops[-1]
                right=rhs.imm if rhs.type==ARM_OP_IMM else (i.address+4 if rhs.reg==ARM_REG_PC else regs.get(rhs.reg))
                if left is not None and right is not None:
                    written=(left-right if mn.startswith('sub') else left|right if mn.startswith('orr') else left+right)&0xffffffff
            elif mn.startswith('ldr') and len(ops)>1 and ops[1].type==ARM_OP_MEM:
                mem=ops[1].mem;base=(i.address+4)&~3 if mem.base==ARM_REG_PC else regs.get(mem.base)
                if base is not None and not mem.index:written=m.word((base+mem.disp)&0xffffffff)
            if written is not None:
                regs[reg]=written
                value=m.string(written)
                if value is not None:
                    refs.append(dict(at=i.address,address=written,value=value));note=value.replace('\n','\\n')
            elif not mn.startswith(('str','cmp','tst','push','vstr')):
                regs.pop(reg,None)
        if mn in ('bl','blx'):
            for reg in list(regs):
                if i.reg_name(reg) in ('r0','r1','r2','r3','ip','lr'):regs.pop(reg,None)
        lines.append(f'{i.address:08x} {i.bytes.hex():12s} {mn:10s} {i.op_str}'+(' ; '+note if note else ''))
    return dict(start=lo,end=hi,entry=m.entries[lo],mode=m.function_modes[lo],undecoded_tail_bytes=undecoded,sha256=hashlib.sha256(raw).hexdigest(),refs=refs,calls=calls),lines


def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--image',type=Path,required=True)
    p.add_argument('--output',type=Path,required=True);p.add_argument('--functions',type=lambda s:int(s,0),action='append',default=[])
    p.add_argument('--only-functions',action='store_true',help='Analyze only explicitly requested native functions')
    p.add_argument('--table',nargs=2,action='append',default=[],metavar=('ADDRESS','WORDS'))
    a=p.parse_args();image=a.image.resolve();out=a.output.resolve()
    if not image.is_relative_to(ROOT) or not out.is_relative_to(ROOT/'research') or out.exists():p.error('Existing project image and fresh research output required')
    m=MachO(image);text=next(s for s in m.sections if s['name']=='__text');ends=m.functions[1:]+[text['address']+text['bytes']]
    candidates=[];detail=[]
    selected_functions={v&~1 for v in a.functions}
    if a.only_functions and not selected_functions:p.error('--only-functions requires --functions')
    if selected_functions-set(m.functions):p.error('Requested address is not an original function start')
    for lo,hi in zip(m.functions,ends):
        if a.only_functions and lo not in selected_functions:continue
        record,lines=analyze(m,lo,hi)
        if any(relevant_string(r['value']) for r in record['refs']) or lo in selected_functions or any(c['symbol'] in ('_open','_ioctl','_tcgetattr','_tcsetattr','_cfmakeraw','_cfsetspeed','_read','_write','_IOServiceNameMatching') for c in record['calls']):
            candidates.append(record);detail.extend(['\nFUNCTION '+hex(lo),*lines])
    tables=[]
    for address,count in a.table:
        address,count=int(address,0),int(count,0)
        if address%4 or not 1<=count<=256:p.error('Aligned tables of 1..256 words only')
        m.offset(address,count*4)
        tables.append(dict(address=address,words=[dict(at=address+n*4,value=m.word(address+n*4),string=m.string(m.word(address+n*4))) for n in range(count)]))
    out.mkdir(parents=True)
    report=dict(source=str(image.relative_to(ROOT)),sha256=hashlib.sha256(m.raw).hexdigest(),uuid=m.uuid,
        function_starts=len(m.functions),thumb_function_starts=sum(v&1 for v in m.function_entries),strings={hex(k):v for k,v in m.strings.items()},stubs={hex(k):v for k,v in m.stubs.items()},pointers={hex(k):v for k,v in m.pointers.items()},candidates=candidates,tables=tables,
        scope='Original Thumb call sites and linear constant propagation candidates; verify branch/register paths before interpreting runtime effects',device_contacted=False)
    (out/'catalog.json').write_text(json.dumps(report,indent=2)+'\n');(out/'native.txt').write_text('\n'.join(detail)+'\n')
    (out/'source.json').write_text(json.dumps(dict(image_sha256=report['sha256'],image_uuid=m.uuid,analyzer_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),device_contacted=False),indent=2)+'\n')
    print('EVIDENCE',out,'UUID',m.uuid,'functions',len(m.functions),'selected',len(candidates))
    for r in candidates:
        print(hex(r['start']),[s['value'] for s in r['refs'] if relevant_string(s['value'])],[(hex(c['at']),c['symbol']) for c in r['calls'] if c['symbol'] in ('_open','_ioctl','_tcgetattr','_tcsetattr','_write','_read','_IOServiceNameMatching')])


if __name__=='__main__':main()
