#!/usr/bin/env python3
"""Bind the latest observed GS window send to its actual receive task."""
import argparse,importlib.util,json,re,struct
from datetime import datetime,timezone
from pathlib import Path
here=Path(__file__).resolve().parent
s=importlib.util.spec_from_file_location('window_boot',here/'capture-boot-snapshot.py')
b=importlib.util.module_from_spec(s);s.loader.exec_module(b)
def identity(raw):
    m=re.search(rb'proc\s+(\d+)\s+\S+.*?task=(0x[0-9a-f]+)',raw)
    b.o.require(m is not None,'Process absent')
    return int(m[1]),int(m[2],16)
def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--kernel',type=Path,required=True);p.add_argument('--output',type=Path,required=True)
    p.add_argument('--receiver',default='Setup');a=p.parse_args()
    b.f.validate_command('ports '+a.receiver)
    sy=b.m.Symbols(b.o.confined(a.kernel,b.f.REPO/'out'));out=b.o.confined(a.output,b.f.REPO/'out')
    b.o.require(not out.exists(),'Fresh output required')
    profile=json.loads((b.o.OUT/'inventory-20261106-211114-download-profile.json').read_text())
    with b.o.host_lock():
        dev=b.o.cdc(b.o.Host().inventory())
        b.o.require(dev and b.o.normalize_location(dev['location'])==profile['location'],'Approved CDC absent')
        out.mkdir(parents=True)
        with (out/'events.jsonl').open('x',encoding='utf-8') as events:
            def record(phase,**kw):
                row=dict(time=datetime.now(timezone.utc).isoformat(),phase=phase,**kw)
                events.write(json.dumps(row)+'\n');events.flush()
                if phase in ('OPEN_OK','DTR_OK','CLOSED','DONE','STOP'):print(json.dumps(row),flush=True)
            try:
                with b.open_session(dev,sy.tag,out,record,180) as session:
                    k=b.m.Kernel(session,sy);raw=k.read(sy['_i9100_hid_execution_diag'],128)
                    d=struct.unpack('<32I',raw);(out/'hid-diag.bin').write_bytes(raw)
                    b.o.require(d[0]==2 and d[1]==2 and d[10]>0 and d[24]==d[10],'Actual observer absent')
                    raw=k.read(sy['_i9100_hid_execution_rows'],(4+32*64)*4);(out/'hid-rows.bin').write_bytes(raw)
                    seq,version,capacity,stride=struct.unpack_from('<4I',raw)
                    b.o.require((version,capacity,stride)==(2,32,64),'Unknown execution ring')
                    rows=[struct.unpack_from('<64I',raw,(4+n*64)*4) for n in range(32)]
                    rows=[r for r in rows if max(1,seq-31)<=r[0]<=seq and r[4]==3 and (r[1],r[2],r[3])==(d[2],d[12],d[3]) and r[5]==d[5]+2*64+22]
                    b.o.require(rows,'No current GS send in retained ring')
                    r=max(rows,key=lambda x:x[0]);name=r[9]
                    b.o.require(name and not r[10],'Latest record is not a window send')
                    result=dict(tag=sy.tag,gs_sequence=r[0],sender_pid=r[1],sender_task=hex(r[3]),window_name=hex(name),sequential=True)
                    _,ports=session.command('ports backboardd');(out/'backboard-ports.txt').write_bytes(ports)
                    b.o.require(identity(ports)==(d[2],d[3]),'Backboard changed')
                    line=next((x for x in ports.splitlines() if re.search(rb'pn='+format(name,'x').encode()+rb'\b',x)),None)
                    b.o.require(line is not None,'Observed window send right is no longer present')
                    m=re.search(rb'obj=(0x[0-9a-f]+)',line);b.o.require(m is not None,'Port object missing')
                    obj=int(m[1],16);raw=k.read(obj,140);(out/'window-port.bin').write_bytes(raw);w=struct.unpack('<35I',raw)
                    result.update(port_line=line.decode(),port=dict(object=hex(obj),bits=hex(w[0]),active=bool(w[0]&0x80000000),count=w[17],limit=w[18],receiver_name=hex(w[20]),receiver_space=hex(w[22]),words=[hex(x) for x in w]))
                    b.o.require(result['port']['active'] and 0x80000000<=w[22]<0xf0000000,'Inactive receive space')
                    task=k.u32(w[22]+0x34);result['port']['receiver_task']=hex(task)
                    _,receiver=session.command('ports '+a.receiver);(out/'receiver-ports.txt').write_bytes(receiver)
                    pid,actual=identity(receiver);result['receiver']=dict(name=a.receiver,pid=pid,task=hex(actual),matches=actual==task,
                        port_lines=[x.decode() for x in receiver.splitlines() if format(obj,'x').encode() in x and b'rt=recv' in x])
                    _,after=session.command('ports backboardd');(out/'backboard-after.txt').write_bytes(after)
                    b.o.require(identity(after)==(d[2],d[3]),'Backboard replaced')
                    current=next((x for x in after.splitlines() if re.search(rb'pn='+format(name,'x').encode()+rb'\b',x)),None)
                    b.o.require(current is not None and format(obj,'x').encode() in current,'Window right replaced')
                    (out/'result.json').write_text(json.dumps(result,indent=2)+'\n');print(json.dumps(result,indent=2),flush=True)
                record('DONE')
            except BaseException as e:record('STOP',error=str(e),retry=False);raise
if __name__=='__main__':main()
