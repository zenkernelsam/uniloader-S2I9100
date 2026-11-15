#!/usr/bin/env python3
"""Read observed Setup delegate entry bytes on one bounded native handle."""
import argparse,importlib.util,json,re,struct
from datetime import datetime,timezone
from pathlib import Path
here=Path(__file__).resolve().parent
s=importlib.util.spec_from_file_location('entry_boot',here/'capture-boot-snapshot.py')
b=importlib.util.module_from_spec(s);s.loader.exec_module(b)

def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--kernel',type=Path,required=True)
    p.add_argument('--evidence',type=Path,required=True);p.add_argument('--output',type=Path,required=True);a=p.parse_args()
    sy=b.m.Symbols(a.kernel);e=json.loads(a.evidence.read_text());b.o.require(e['tag']==sy.tag,'Observed BUILD differs')
    methods=[m for c in e['classes'].values() if c['name']=='BuddyLanguageController' for m in c['methods']
             if m['selector']=='tableView:didSelectRowAtIndexPath:']
    b.o.require(len(methods)==1,'Exact observed language delegate absent')
    out=b.o.confined(a.output,b.f.REPO/'out');b.o.require(not out.exists(),'Fresh evidence required')
    profile=json.loads((b.o.OUT/'inventory-20261106-211114-download-profile.json').read_text())
    with b.o.host_lock():
        dev=b.o.cdc(b.o.Host().inventory());b.o.require(dev and b.o.normalize_location(dev['location'])==profile['location'],'Approved CDC absent')
        out.mkdir(parents=True)
        with (out/'events.jsonl').open('x',encoding='utf-8') as events:
            def record(phase,**kw):
                v=dict(time=datetime.now(timezone.utc).isoformat(),phase=phase,**kw);events.write(json.dumps(v)+'\n');events.flush()
                if phase in ('OPEN_OK','DTR_OK','CLOSED','DONE','STOP'):print(json.dumps(v),flush=True)
            try:
                with b.open_session(dev,sy.tag,out,record,120) as session:
                    k=b.m.Kernel(session,sy);d=struct.unpack('<32I',k.read(sy['_i9100_ui_execution_diag'],128))
                    b.o.require((d[2],d[3],d[12])==(e['pid'],int(e['task'],16),e['idversion']),'Observed Setup replaced')
                    user=k.user_pmap(k.u32(k.u32(d[3]+0x18)+0x2c));mh=user.read(d[4],4096);(out/'image-header.bin').write_bytes(mh)
                    header=struct.unpack_from('<7I',mh);b.o.require(header[0]==0xfeedface and header[1]==12 and header[3]==2,'Observed image not ARM executable')
                    at=28;uuid=None
                    for _ in range(header[4]):
                        cmd,n=struct.unpack_from('<2I',mh,at);b.o.require(n>=8 and at+n<=len(mh),'Unbounded executable commands')
                        if cmd==27:
                            uuid=mh[at+8:at+24].hex();break
                        at+=n
                    b.o.require(uuid=='580dfd1edbd53d33844bca6635c0b3cd','Original Setup UUID differs')
                    rows=[]
                    for m in methods:
                        address=int(m['address'],16)&~1;b.o.require(d[4]<=address<d[4]+0x200000,'Delegate outside observed executable')
                        raw=user.read(address,64);(out/(m['selector'].replace(':','_')+'.bin')).write_bytes(raw)
                        rows.append(dict(selector=m['selector'],address=hex(address),executable_offset=hex(address-d[4]),bytes=raw.hex()))
                    current=struct.unpack('<32I',k.read(sy['_i9100_ui_execution_diag'],128))
                    b.o.require((current[2],current[3],current[12])==(d[2],d[3],d[12]),'Setup identity changed')
                    result=dict(tag=sy.tag,pid=d[2],task=hex(d[3]),header=hex(d[4]),uuid=uuid,sites=rows)
                    (out/'result.json').write_text(json.dumps(result,indent=2)+'\n');print(json.dumps(result),flush=True)
                record('DONE')
            except BaseException as error:record('STOP',error=str(error),retry=False);raise
if __name__=='__main__':main()
