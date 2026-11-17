#!/usr/bin/env python3
"""Keep one verified CDC owner for bounded UI tasks and uninterrupted logs.

Requests are immutable JSON files, published by atomic rename inside out.
No flash, driver changes, opener retry or command resend. Errors close the
original handle; queued work never starts after a failed/uncertain request.
"""
import argparse,importlib.util,json,os,re,struct,time
from datetime import datetime,timezone
from pathlib import Path
HERE=Path(__file__).resolve().parent
s=importlib.util.spec_from_file_location('ui_owner_boot',HERE/'capture-boot-snapshot.py')
b=importlib.util.module_from_spec(s);s.loader.exec_module(b)

def validate(task):
    if not isinstance(task,dict) or set(task)-{'id','action','xy','ms','frame','process','thread_limit'}:raise ValueError('Unknown task fields')
    if not re.fullmatch(r'[0-9]{4}',str(task.get('id',''))):raise ValueError('Four-digit task id required')
    action=task.get('action')
    if action not in ('status','charge','frame','tap','swipe','home','setup','app','stacks','close','reboot-download'):raise ValueError('Unknown task action')
    if 'frame' in task and type(task['frame']) is not bool:raise ValueError('frame must be boolean')
    if action in ('tap','swipe','home'):
        xy=task.get('xy',[]);size=2 if action=='tap' else 4 if action=='swipe' else 0
        if not isinstance(xy,list) or len(xy)!=size or any(type(x) is not int or not 0<=x<(480 if n%2==0 else 800) for n,x in enumerate(xy)):raise ValueError('Physical 480x800 coordinates required')
        ms=task.get('ms',200 if action=='home' else 300 if action=='tap' else 800)
        if type(ms) is not int or not 80<=ms<=1500:raise ValueError('Input duration outside bounded range')
    elif 'xy' in task or 'ms' in task:raise ValueError('Coordinates/duration require input')
    if task.get('process','Setup') not in ('Setup','SpringBoard','backboardd'):raise ValueError('Only original UI owners supported')
    if type(task.get('thread_limit',1)) is not int or not 1<=task.get('thread_limit',1)<=12:raise ValueError('Thread limit outside scope')
    return task

class OwnerSession(b.f.Session):
    def __init__(self,*args,seconds,**kw):
        super().__init__(*args,**kw);self.deadline=time.monotonic()+seconds;self.commands=0
    def command(self,verb):
        if time.monotonic()>=self.deadline or self.commands>=4096:raise TimeoutError('Owner budget exhausted before next write')
        self.commands+=1;return super().command(verb)

def status(session,kernel,symbols):
    answer,_=session.command('panic-status');active,remaining=b.panic.countdown(answer)
    if active:raise RuntimeError('Panic active; subsequent UI work canceled')
    root,_=session.command('root-status');power={}
    for key in ('valid','percent','mv','connected','charging','temp','reason','revision_value'):
        power[key]=struct.unpack('<i' if key in ('temp','reason') else '<I',kernel.read(symbols['_i9100_power_'+key],4))[0]
    hid=struct.unpack('<32I',kernel.read(symbols['_i9100_hid_execution_diag'],128))
    return dict(root=root,panic=active,power=power,hid=dict(pid=hid[2],state=hid[1],installed=hid[10],callback=hid[16],digitizer=hid[17],gs=hid[18]))

def input_task(session,kernel,symbols,task):
    home=task['action']=='home';xy=task.get('xy',[]);points=[0,0,0,0] if home else xy+xy if task['action']=='tap' else xy
    ms=task.get('ms',200 if home else 300 if task['action']=='tap' else 800)
    probe=struct.unpack('<32I',kernel.read(symbols['_i9100_hid_execution_diag'],128))
    b.o.require(probe[0]==2 and probe[1]==2 and probe[10]>0 and probe[24]==probe[10] and probe[26]>=1,'Actual HID self-test missing; input not sent')
    address=symbols['_i9100_input_test'];before=struct.unpack('<16I',kernel.read(address,64))
    b.o.require(before[0]==1 and before[14 if home else 12]==1 and before[1] in (1,4,5),'Input mailbox unavailable')
    verb='hid-home '+format(ms,'x') if home else 'hid-swipe '+' '.join(format(v,'x') for v in [*points,ms])
    reply,_=session.command(verb);b.o.require(reply=='OK input-queued','Input not accepted')
    deadline=time.monotonic()+5
    while True:
        state=struct.unpack('<16I',kernel.read(address,64))
        b.o.require(list(state[3:8])==[*points,ms] and state[2]==before[2]+1 and state[13]==int(home),'Input ownership changed')
        if state[1]==4:break
        b.o.require(state[1]!=5,'Input canceled by physical input/closed reader')
        b.o.require(time.monotonic()<deadline,'Input completion uncertain; no resend');time.sleep(.1)
    if home:time.sleep(.5)
    return dict(command=verb,sequence=state[2],enqueued=state[8],queue_completed=True,ui_acceptance_verified=False)

def serve(a):
    out=b.o.confined(a.output,b.f.REPO/'out');b.o.require(not out.exists(),'Fresh owner output required')
    symbols=b.m.Symbols(b.o.confined(a.kernel,b.f.REPO/'out'))
    layout=json.loads((b.o.ROOT/'research/ios6-alert-dismiss-20261117-0200/ui-runtime-layout.json').read_text())
    main=json.loads((b.o.ROOT/'research/ios6-setup-all-20261116-1203/handlers.json').read_text())
    b.o.require({'UINavigationController','UIViewController','__NSArrayI','__NSArrayM','UIAlertView'}<=layout['classes'].keys() and 'SetupChoice' in main['classes'],'Required original metadata missing')
    profile=json.loads((b.o.OUT/'inventory-20261106-211114-download-profile.json').read_text())
    with b.o.host_lock():
        device=b.o.cdc(b.o.Host().inventory());b.o.require(device and device['service'].lower()=='usbser' and b.o.normalize_location(device['location'])==profile['location'],'Approved CDC absent')
        out.mkdir(parents=True);queue=out/'queue';queue.mkdir();transport=None;processed=set();session=None
        with (out/'events.jsonl').open('x',encoding='utf-8') as events,(out/'received.bin').open('xb') as capture:
            def record(phase,**fields):
                row=dict(time=datetime.now(timezone.utc).isoformat(),phase=phase,**fields);events.write(json.dumps(row)+'\n');events.flush()
                if phase in ('OPEN_OK','DTR_OK','READY','TASK_BEGIN','TASK_DONE','DONE','STOP','CLOSED'):print(json.dumps(row),flush=True)
            try:
                transport=b.f.WinTransport(device['port'],record)
                session=OwnerSession(transport,symbols.tag,record,capture,timeout=20,seconds=a.seconds,allow_input_test=True,allow_reboot_download=a.allow_reboot_download)
                session.handshake();kernel=b.m.Kernel(session,symbols)
                (out/'owner.json').write_text(json.dumps(dict(pid=os.getpid(),tag=symbols.tag,seconds=a.seconds),indent=2)+'\n')
                record('READY',pid=os.getpid(),tag=symbols.tag)
                while time.monotonic()<session.deadline:
                    pending=sorted(p for p in queue.glob('*.json') if p.name not in processed)
                    if not pending:
                        chunk=transport.read()
                        if chunk:capture.write(chunk);capture.flush();session.receiver.feed(chunk)
                        continue
                    path=pending[0];task=validate(json.loads(path.read_text()));b.o.require(path.stem==task['id'],'Task filename differs');processed.add(path.name)
                    b.o.require(len(processed)<=64,'Task count budget reached')
                    target=out/('task-'+task['id']);target.mkdir();record('TASK_BEGIN',id=task['id'],action=task['action'])
                    action=task['action'];result=dict(task=task,tag=symbols.tag)
                    if action=='close':result['closed_by_request']=True
                    elif action=='reboot-download':
                        b.o.require(a.allow_reboot_download,'Download reboot was not enabled');answer,_=session.command('reboot-download');result['reply']=answer
                    else:
                        kernel=b.m.Kernel(session,symbols)
                        if action in ('tap','swipe','home'):result['input']=input_task(session,kernel,symbols,task)
                        elif action=='charge':result['charge']=b.module('owner_charge','inspect-charge-health.py').capture(kernel,symbols,target)
                        elif action=='setup':result['setup']=b.module('owner_setup','inspect-setup-controller.py').capture(session,kernel,symbols,main,layout,target)
                        elif action=='app':result['app']=b.module('owner_app','inspect-ui-app.py').capture(session,kernel,symbols,task.get('process','Setup'),layout,target,flags_only=True,geometry=True)
                        elif action=='stacks':result['stack']=b.stack.capture_process(session,kernel,task.get('process','Setup'),target,b.m,True,task.get('thread_limit',1),True)
                        result['status']=status(session,kernel,symbols)
                        if action=='frame' or task.get('frame',action in ('tap','swipe','home')):
                            image=target/'frame';image.mkdir();result['frame']=b.frame.capture_frame(kernel,symbols,image,device,32768,record)
                    (target/'result.json').write_text(json.dumps(result,indent=2)+'\n')
                    record('TASK_DONE',id=task['id'],action=action,frame='frame' in result,power=result.get('status',{}).get('power'))
                    if action in ('close','reboot-download'):break
                record('DONE',tasks=len(processed))
            except BaseException as exc:
                record('STOP',error=str(exc),retry=False)
                if session and session.receiver.payload:(out/'incomplete-data.partial').write_bytes(session.receiver.payload)
                if session and str(exc) in ('ERR panic-readonly','Panic active; subsequent UI work canceled'):
                    session.receiver.line.clear();session.receiver.drop=False
                    try:b.retain_current_panic(session,out,record)
                    except BaseException as retained:record('PANIC_SAVE_STOP',error=str(retained),retry=False)
                raise
            finally:
                if transport:transport.close()
                capture.flush();record('CLOSED')

def main():
    p=argparse.ArgumentParser(description=__doc__);sub=p.add_subparsers(dest='mode',required=True)
    s=sub.add_parser('serve');s.add_argument('--kernel',type=Path,required=True);s.add_argument('--output',type=Path,required=True);s.add_argument('--seconds',type=int,choices=range(60,1801),default=1200);s.add_argument('--allow-reboot-download',action='store_true')
    q=sub.add_parser('request');q.add_argument('--owner',type=Path,required=True);q.add_argument('--id',required=True);q.add_argument('--action',required=True);q.add_argument('--xy',type=int,nargs='+');q.add_argument('--ms',type=int);q.add_argument('--process');q.add_argument('--thread-limit',type=int);q.add_argument('--no-frame',action='store_true')
    a=p.parse_args()
    if a.mode=='serve':return serve(a)
    owner=b.o.confined(a.owner,b.f.REPO/'out');queue=owner/'queue';b.o.require(queue.is_dir() and (owner/'owner.json').is_file(),'Owner must have reached READY')
    task=dict(id=a.id,action=a.action)
    for name in ('xy','ms','process','thread_limit'):
        if getattr(a,name) is not None:task[name]=getattr(a,name)
    if a.no_frame:task['frame']=False
    validate(task);target=queue/(a.id+'.json');temp=queue/(a.id+'.part')
    b.o.require(not target.exists() and not temp.exists(),'Task id already used')
    temp.write_text(json.dumps(task)+'\n');os.replace(temp,target);print(str(target))
if __name__=='__main__':main()
