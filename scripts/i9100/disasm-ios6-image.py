#!/usr/bin/env python3
"""Read-only Thumb disassembly with the original Mach-O import names."""
import argparse,struct
from pathlib import Path
from capstone import Cs,CS_ARCH_ARM,CS_MODE_THUMB
def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--image',type=Path,required=True)
    p.add_argument('--start',type=lambda s:int(s,16),required=True)
    p.add_argument('--size',type=lambda s:int(s,16),required=True)
    p.add_argument('--output',type=Path,required=True)
    a=p.parse_args();root=Path(__file__).resolve().parents[3]
    if not a.image.resolve().is_relative_to(root/'assets') or not a.output.resolve().is_relative_to(root/'research'):
        p.error('Read the existing asset and write research only')
    b=a.image.read_bytes();pos=28;segments=[];sections=[];sym=dy=None
    if struct.unpack_from('<I',b)[0]!=0xfeedface:p.error('Expected ARM32 Mach-O')
    for _ in range(struct.unpack_from('<I',b,16)[0]):
        cmd,size=struct.unpack_from('<2I',b,pos)
        if cmd==1:
            segments.append(struct.unpack_from('<4I',b,pos+24))
            for n in range(struct.unpack_from('<I',b,pos+48)[0]):
                sections.append(struct.unpack_from('<9I',b,pos+56+n*68+32))
        if cmd==2:sym=struct.unpack_from('<4I',b,pos+8)
        if cmd==11:dy=struct.unpack_from('<18I',b,pos+8)
        pos+=size
    def stub(address):
        for at,size,_,_,_,_,flags,r1,r2 in sections:
            if flags&255==8 and at<=address<at+size:
                ni=struct.unpack_from('<I',b,dy[12]+((address-at)//r2+r1)*4)[0]
                so,_,st,_=sym;si=struct.unpack_from('<I',b,so+12*ni)[0]
                return b[st+si:b.find(b'\0',st+si)].decode()
        return ''
    off=next(fo+a.start-vm for vm,_,fo,fs in segments if vm<=a.start<vm+fs)
    lines=[]
    for i in Cs(CS_ARCH_ARM,CS_MODE_THUMB).disasm(b[off:off+a.size],a.start):
        annotation=stub(int(i.op_str[1:],16)) if i.mnemonic=='blx' and i.op_str.startswith('#') else ''
        lines.append(f'{i.address:08x} {i.mnemonic:10} {i.op_str} {annotation}')
    a.output.write_text('\n'.join(lines)+'\n');print(a.output)
if __name__=='__main__':main()
