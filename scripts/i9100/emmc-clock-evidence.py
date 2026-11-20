#!/usr/bin/env python3
"""Decode actual read-only4210 clock snapshots; no hardware or register writes."""
import argparse
from datetime import datetime,timezone
import hashlib
import json
from pathlib import Path
import struct
import zlib

ROOT=Path(__file__).resolve().parents[3];REPO=ROOT/'uniloader-S2I9100'
FIELDS=('chip_id','cmu_ip_gate','cmu_source_gate','source_mux','source_divider','divider_status',
 'source_top0','source_top1','source_cpu','mpll_con0','mpll_con1','epll_con0','epll_con1','vpll_con0','vpll_con1',
 'gpk0_mux','gpk0_data','gpk0_pull','gpk0_drive','gpk1_mux','gpk1_pull','gpk1_drive','gic_enable',
 'host_control','host_power','host_clkdiv','host_clksrc','host_clkena','host_ctype','host_intmask','host_command','host_status','host_rint',
 'host_version','host_hcon','host_uhs','host_bmod','host_idsts','host_idinten','clksel')
OFFSETS=(0,0xc940,0xc340,0xc240,0xc54c,0xc64c,0xc210,0xc214,0x14200,0x14108,0x1410c,0xc110,0xc114,0xc120,0xc124,
 0x40,0x44,0x48,0x4c,0x60,0x68,0x6c,0x10c,0,4,8,12,16,24,36,44,72,68,108,112,116,128,140,144,156)
REGIONS=(4,1,1,1,1,1,1,1,1,1,1,1,1,1,1,2,2,2,2,2,2,2,3,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0)

def pll(reference,con0,con1,kind):
    if con0==0xffffffff or con1==0xffffffff or con0&0xa0000000!=0xa0000000:raise ValueError('PLL is absent, disabled or not locked')
    m=(con0>>16)&(1023 if kind==0 else 511);p=(con0>>8)&63;s=con0&7
    if not m or not p or kind==0 and not s:raise ValueError('Invalid PLL divisor')
    if kind==0:rate=reference*m//(p<<(s-1))
    else:
        fraction=16 if kind==1 else 10;k=con1&(65535 if kind==1 else 4095)
        rate=(reference*((m<<fraction)+k)//(p<<s))>>fraction
    if not 10000000<=rate<=1600000000:raise ValueError('PLL rate outside reviewed4210 range')
    return rate

def decode(raw,require_admitted=False):
    if len(raw)!=512 or raw[:4]!=b'I9EC' or struct.unpack_from('<III',raw,4)!=(1,512,40) or struct.unpack_from('<I',raw,16)[0]&~1 or any(raw[28:32]) or any(raw[48:64]) or any(raw[384:508]) or zlib.crc32(raw[:508])!=struct.unpack_from('<I',raw,508)[0]:
        raise ValueError('Wrong/truncated/CRC-invalid clock record')
    flags,xxti,usb=struct.unpack_from('<III',raw,16);began,ended=struct.unpack_from('<QQ',raw,32)
    first=dict(zip(FIELDS,struct.unpack_from('<40I',raw,64)));second=dict(zip(FIELDS,struct.unpack_from('<40I',raw,224)))
    result=dict(model_fixture=bool(flags),xxti_hz=xxti,xusbxti_hz=usb,began_ns=began,ended_ns=ended,
      first=first,registers=second,host_physical=0x12550000,clock_arithmetic_valid=False,clock_and_pins_reviewed=False,
      admissible=False,electrical_measurement_verified=False,reasons=[])
    if ended<began or ended-began>100000000:result['reasons'].append('Clock capture interval invalid')
    if xxti!=24000000 or usb!=24000000:result['reasons'].append('Unreviewed board oscillator frequency')
    v=second;source=(v['source_mux']>>16)&15;result['selected_source']=source
    if v['chip_id']==0xffffffff or v['chip_id']&0xfffe0000!=0x43210000&0xfffe0000:result['reasons'].append('Different ChipID')
    if any(v[key]==0xffffffff for key in ('cmu_ip_gate','cmu_source_gate','source_mux','source_divider','divider_status','source_top0','source_top1','source_cpu')):
        result['reasons'].append('Clock register unmapped')
    if not v['cmu_ip_gate']&(1<<9) or not v['cmu_source_gate']&(1<<16) or v['divider_status']:
        result['reasons'].append('Clock gated or divider transition active')
    parent=None
    try:
        if source==0:parent=xxti
        elif source==1:parent=usb
        elif source==6:parent=pll(xxti,v['mpll_con0'],v['mpll_con1'],0) if v['source_cpu']&(1<<8) else xxti
        elif source==7:parent=pll(xxti,v['epll_con0'],v['epll_con1'],1) if v['source_top0']&(1<<4) else xxti
        elif source==8:
            if v['source_top1']&1:raise ValueError('VPLL externalHDMI reference requires separate evidence')
            parent=pll(xxti,v['vpll_con0'],v['vpll_con1'],2) if v['source_top0']&(1<<8) else xxti
        else:raise ValueError('Unsupported external clock parent')
    except ValueError as error:result['reasons'].append(str(error))
    if parent is not None:
        div=(v['source_divider']&15)+1;pre=((v['source_divider']>>8)&255)+1;fsys=parent//div//pre;ciu=fsys//2
        hostdiv=(v['host_clkdiv']>>(8*(v['host_clksrc']&3)))&255
        card=(ciu//(2*hostdiv)if hostdiv else ciu)if v['host_clkena']!=0xffffffff and v['host_clkena']&1 else 0
        result.update(parent_hz=parent,fsys_hz=fsys,ciu_clock_hz=ciu,card_clock_hz=card,
          card_clock_enabled=v['host_clkena']!=0xffffffff and bool(v['host_clkena']&1),cmu_div=div,cmu_pre=pre,host_div=hostdiv)
        if not 400000<=ciu<=200000000:result['reasons'].append('CIU is outside native rate range')
    masks={'cmu_ip_gate':1<<9,'cmu_source_gate':1<<16,'source_mux':15<<16,'source_divider':0xff0f,'divider_status':0xffffffff,
      'source_top0':(1<<4 if source==7 else 1<<8 if source==8 else 0),'source_top1':(1 if source==8 else 0),
      'source_cpu':(1<<8 if source==6 else 0),'mpll_con0':(0xa3ff3f07 if source==6 else 0),'mpll_con1':0,
      'epll_con0':(0xa1ff3f07 if source==7 else 0),'epll_con1':(65535 if source==7 else 0),
      'vpll_con0':(0xa1ff3f07 if source==8 else 0),'vpll_con1':(4095 if source==8 else 0),
      'gpk0_mux':65535,'gpk0_data':4,'gpk0_pull':255,'gpk0_drive':255,'gpk1_mux':0,'gpk1_pull':0,'gpk1_drive':0,
      'gic_enable':1<<13,'host_rint':0,'host_idsts':0}
    drift=[key for key in FIELDS if (first[key]^v[key])&masks.get(key,0xffffffff)]
    if drift:result['reasons'].append('Clock/pin/host drift: '+','.join(drift))
    host_keys=[key for key in FIELDS if key.startswith('host_')and key not in ('host_rint','host_idsts')]+['clksel','gic_enable']
    if any(v[key]==0xffffffff for key in host_keys):result['reasons'].append('Host/GIC register inaccessible')
    if not 0x2000<=v['host_version']&65535<0x240a or (v['host_hcon']>>7)&7!=1:result['reasons'].append('Different controller/FIFO generation')
    if not v['host_power']&1:result['reasons'].append('eMMC power was not enabled')
    busy=v['host_control']&(7|(1<<5)|(1<<25))or v['host_command']&(1<<31)or v['host_status']&((15<<4)|(1<<9)|(1<<10)|(0x1fff<<17)|(1<<30)|(1<<31))or v['host_bmod']&(1<<7)or v['host_intmask']or v['host_idinten']or v['gic_enable']&(1<<13)
    if busy:result['reasons'].append('Native exclusivePIO host is not idle')
    if v['gpk0_mux']==0xffffffff or v['gpk0_data']==0xffffffff or v['gpk0_pull']==0xffffffff or v['gpk0_drive']==0xffffffff or v['gpk0_mux']&65535!=0x3133 or not v['gpk0_data']&4:
        result['reasons'].append('Inherited legacy pins/power are unsuitable')
    result['clock_arithmetic_valid']=parent is not None and 'ciu_clock_hz'in result
    result['admissible']=not result['reasons']
    if require_admitted and not result['admissible']:raise ValueError('; '.join(result['reasons']))
    return result

def controller(record,reviewed=False,note=''):
    result=decode(record,require_admitted=True)
    if reviewed and result['model_fixture']:raise ValueError('Model clock snapshot cannot become reviewed hardware')
    if not note.strip():raise ValueError('Describe actual pre-probe host/session/root clock evidence')
    return dict(schema=2,model_fixture=result['model_fixture'],ciu_clock_hz=result['ciu_clock_hz'],clock_and_pins_reviewed=reviewed,
      host_physical=0x12550000,registers={name:result['registers'][name]for name in FIELDS},measurement_note=note,
      clock_record_hex=record.hex(),clock_decoder_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest())
def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('record',type=Path);p.add_argument('--controller-note');p.add_argument('--output',type=Path);a=p.parse_args()
    path=a.record.resolve()
    if not path.is_relative_to(ROOT)or path.stat().st_size!=512:raise ValueError('Require a512B record within project')
    raw=path.read_bytes();result=controller(raw,False,a.controller_note)if a.controller_note else decode(raw)
    if a.output:
        target=a.output.resolve()
        if not target.is_relative_to(REPO/'out')or target.exists():raise ValueError('Use a new file in retained loaderout')
        target.parent.mkdir(parents=True,exist_ok=True);target.write_text(json.dumps(result,indent=2)+'\n')
    print(json.dumps(result,indent=2))
if __name__=='__main__':main()
