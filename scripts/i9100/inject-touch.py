#!/usr/bin/env python3
"""One explicit, bounded touch test through a BUILD-verified serial handle.

No physical GPIO writes, no command retry. Queue completion is not proof that
the UI accepted a gesture; capture the real framebuffer afterwards.
"""
import argparse
from datetime import datetime, timezone
import importlib.util
import json
from pathlib import Path
import struct
import time

HERE=Path(__file__).resolve().parent


def module(name,filename):
    spec=importlib.util.spec_from_file_location(name,HERE/filename)
    value=importlib.util.module_from_spec(spec);spec.loader.exec_module(value)
    return value


def main():
    f=module('input_forensic','forensic-session.py')
    m=module('input_memory','live-memory.py')
    o=module('input_odin','odin-loop.py')
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--kernel',type=Path,required=True)
    p.add_argument('--output',type=Path,required=True)
    gestures=p.add_mutually_exclusive_group(required=True)
    gestures.add_argument('--tap',type=int,nargs=2,metavar=('X','Y'))
    gestures.add_argument('--swipe',type=int,nargs=4,metavar=('X0','Y0','X1','Y1'))
    gestures.add_argument('--home',action='store_true')
    p.add_argument('--ms',type=int)
    p.add_argument('--wake-first',action='store_true',help='One Home press followed by this gesture on the same handle')
    p.add_argument('--follow-tap',type=int,nargs=2,metavar=('X','Y'),
                   help='One bounded tap after this swipe, before an idle transition can interrupt setup')
    p.add_argument('--follow-ms',type=int,choices=range(80,1501),default=100,
                   help='Bounded follow-up duration; 80ms can retain the first Down in the execution ring')
    p.add_argument('--wait-language',action='store_true',
                   help='Before the follow-up, observe the actual language-list card in bounded scanout samples')
    p.add_argument('--ui-layout',type=Path,help='Read Setup application state on this same awake handle before the follow-up')
    p.add_argument('--require-ui-trace',action='store_true',help='Before the follow-up require the actual Setup observer installation')
    p.add_argument('--trace',action='store_true',help='Retain current HID/GS execution immediately after the gesture on the same handle')
    p.add_argument('--awake-check-layout',type=Path,help='Require native SpringBoard interaction flags after Home on this same handle')
    p.add_argument('--frame',action='store_true',help='Save the real scanout after this input on the same handle')
    p.add_argument('--swipe-count',type=int,choices=(1,2,3,4),default=1,help='Explicit bounded consecutive swipes, each with a fresh sequence')
    a=p.parse_args()
    if a.wake_first and a.home:p.error('--wake-first requires a touch gesture')
    if a.follow_tap and not a.swipe:p.error('--follow-tap requires --swipe')
    if a.wait_language and not a.follow_tap:p.error('--wait-language requires --follow-tap')
    if a.ui_layout and not a.wait_language:p.error('--ui-layout requires --wait-language')
    if a.require_ui_trace and not a.wait_language:p.error('--require-ui-trace requires --wait-language')
    if a.awake_check_layout and not a.wake_first:p.error('--awake-check-layout requires --wake-first')
    if a.swipe_count!=1 and (not a.swipe or a.follow_tap):p.error('--swipe-count requires swipe without follow-up')
    points=([0,0,0,0] if a.home else a.swipe if a.swipe else a.tap+a.tap)
    ms=a.ms if a.ms is not None else (200 if a.home else 400 if a.swipe else 100)
    command=('hid-home '+format(ms,'x') if a.home else 'hid-swipe '+' '.join(format(n,'x') for n in [*points,ms]))
    f.validate_command(command,allow_input_test=True)
    symbols=m.Symbols(a.kernel)
    o.require('_i9100_input_test' in symbols.values,'Kernel has no input mailbox')
    out=o.confined(a.output,f.REPO/'out');o.require(not out.exists(),'Fresh output directory required')
    profile=json.loads((f.REPO/'out/automation/inventory-20261109-panic-download.json').read_text())
    with o.host_lock():
        device=o.cdc(o.Host().inventory())
        o.require(device and o.normalize_location(device['location'])==profile['location'],'No approved live CDC')
        out.mkdir(parents=True);transport=None
        with (out/'events.jsonl').open('x') as events,(out/'received.bin').open('xb') as capture:
            def record(phase,**fields):
                row=dict(time=datetime.now(timezone.utc).isoformat(),phase=phase,**fields)
                events.write(json.dumps(row)+'\n');events.flush()
                if phase in ('OPEN_OK','DTR_OK','STOP','DONE'):print(json.dumps(row),flush=True)
            try:
                transport=f.WinTransport(device['port'],record)
                session=f.Session(transport,symbols.tag,record,capture,timeout=20,allow_input_test=True)
                session.handshake();kernel=m.Kernel(session,symbols)
                if a.trace:
                    o.require('_i9100_hid_execution_diag' in symbols.values,'Trace requested but no HID observer exists')
                    probe=struct.unpack('<32I',kernel.read(symbols['_i9100_hid_execution_diag'],128))
                    o.require(probe[0]==2 and probe[1]==2 and probe[10]>0 and probe[24]==probe[10] and probe[26]>=1,
                              'HID observer did not install/self-test; no input command sent')
                address=symbols['_i9100_input_test']
                steps=([(True,[0,0,0,0],200,'hid-home c8')] if a.wake_first else [])+[(a.home,points,ms,command)]*a.swipe_count
                if a.follow_tap:
                    follow=a.follow_tap+a.follow_tap
                    follow_command='hid-swipe '+' '.join(format(n,'x') for n in [*follow,a.follow_ms])
                    f.validate_command(follow_command,allow_input_test=True)
                    steps.append((False,follow,a.follow_ms,follow_command))
                completed=[];gate_failure=None
                for home,step_points,step_ms,step_command in steps:
                    before=struct.unpack('<16I',kernel.read(address,64))
                    o.require(before[0]==1 and before[14 if home else 12]==1 and before[1] in (1,4,5),'Input disabled or reader not ready; no command sent')
                    f.validate_command(step_command,allow_input_test=True)
                    reply,_=session.command(step_command)
                    o.require(reply=='OK input-queued','Input request was not accepted')
                    deadline=time.monotonic()+5;samples=[]
                    while True:
                        state=struct.unpack('<16I',kernel.read(address,64));samples.append(list(state))
                        o.require(list(state[3:8])==[*step_points,step_ms] and state[2]==before[2]+1 and state[13]==int(home),'Mailbox ownership changed')
                        if state[1]==4:break
                        o.require(state[1]!=5,'Input canceled for physical input or closed reader')
                        o.require(time.monotonic()<deadline,'Input queue completion timeout; no resend')
                        time.sleep(.1)
                    step=dict(command=step_command,sequence=state[2],enqueued=state[8],samples=samples)
                    if '_i9100_hid_execution_diag' in symbols.values:
                        raw=kernel.read(symbols['_i9100_hid_execution_diag'],96);diag=struct.unpack('<24I',raw)
                        step['hid_counts']=dict(callback=diag[16],digitizer=diag[17],gs=diag[18],sequence=diag[19])
                    completed.append(step)
                    if a.ui_layout and step_command!=command and not home:
                        ui=module('input_ui_state','inspect-ui-app.py');target=out/'after-tap-ui';target.mkdir()
                        result_ui=ui.capture(session,kernel,symbols,'Setup',json.loads(a.ui_layout.read_text()),target)
                        step['setup_state_after']=result_ui['flags']
                    if a.wake_first and home:
                        time.sleep(.5)
                        if a.awake_check_layout:
                            ui=module('awake_ui','inspect-ui-app.py');target=out/'awake-springboard';target.mkdir()
                            app=ui.capture(session,kernel,symbols,'SpringBoard',json.loads(a.awake_check_layout.read_text()),target,flags_only=True)
                            step['native_awake_flags']=app['flags']
                            o.require(all(app['flags'][name]==0 for name in ('isSuspended','isSuspendedEventsOnly','blockInteractionEvents')),
                                'Native SpringBoard still blocks interaction; swipe not sent')
                    if a.follow_tap and not home and step_command==command:
                        if a.wait_language:
                            physical=kernel.u32(symbols['_i9100_fb_physical'])
                            o.require(0x40000000<=physical and physical+1536000<=0x80000000,'Scanout outside DRAM')
                            deadline=time.monotonic()+12;samples=[]
                            while True:
                                pixels=[list(kernel.read_phys(physical+y*1920+x*4,4)[:3]) for x,y in ((240,240),(240,200),(20,240))]
                                ready=min(pixels[0])>200 and 40<min(pixels[1])<=max(pixels[1])<200 and max(pixels[2])<20
                                samples.append(dict(pixels=pixels,ready=ready))
                                if ready:break
                                if a.frame and time.monotonic()>=deadline:
                                    gate_failure='Language card not observed; follow-up not sent';break
                                o.require(time.monotonic()<deadline,'Language card not observed; follow-up not sent')
                                time.sleep(.2)
                            (out/'language-ready.json').write_text(json.dumps(dict(samples=samples,observed=ready),indent=2)+'\n')
                            if gate_failure:break
                            if a.require_ui_trace:
                                u=struct.unpack('<32I',kernel.read(symbols['_i9100_ui_execution_diag'],128))
                                o.require(u[0] in (1,2) and u[1]==2 and u[10]>0 and u[11]==4,'Setup observer not installed; follow-up not sent')
                                (out/'ui-preflight.bin').write_bytes(struct.pack('<32I',*u))
                            if a.ui_layout:
                                ui=module('input_ui_state','inspect-ui-app.py');target=out/'before-tap-ui';target.mkdir()
                                result_ui=ui.capture(session,kernel,symbols,'Setup',json.loads(a.ui_layout.read_text()),target)
                                step['setup_state_before']=result_ui['flags']
                        else:time.sleep(.5)
                result=dict(tag=symbols.tag,device=device,command=command,sequence=state[2],
                    enqueued=state[8],phase=state[1],queue_completed=True,ui_delivery_verified=False,samples=samples,steps=completed,wake_first=a.wake_first)
                if gate_failure:result['stopped_before_follow_up']=gate_failure
                if a.trace:
                    observed=module('input_observed','inspect-mdns.py')
                    names={'_i9100_hid_execution_diag','_i9100_hid_execution_rows','_i9100_touch_observation','_i9100_input_test','_i9100_process_exit','_i9100_graphics_seq','_i9100_ui_sounds_unavailable_diag'}
                    names.update({'_i9100_slab_publication_diag','_i9100_slab_publication_rows','_i9100_slab_failure_mapping_diag',
                                  '_i9100_backboard_exit','_i9100_backboard_abort_observation','_i9100_abort_frames','_i9100_ios6_slab_payload'})
                    names.update({'_i9100_hid_fixed_cadence_diag','_i9100_touch_sender_identity'})
                    names.update({'_i9100_ui_execution_diag','_i9100_ui_execution_rows'})
                    target=out/'after-input';target.mkdir()
                    result['observations']=observed.capture_ui_observations(kernel,observed.ObservationSymbols(symbols,names),target)
                if a.frame:
                    frame=module('input_frame','capture-framebuffer.py');target=out/'frame';target.mkdir()
                    result['frame']=frame.capture_frame(kernel,symbols,target,device,32768,record)
                (out/'result.json').write_text(json.dumps(result,indent=2)+'\n')
                print(json.dumps(result,indent=2),flush=True)
                if gate_failure:raise ValueError(gate_failure)
                record('DONE',queue_only=True)
            except BaseException as exc:record('STOP',error=str(exc),retry=False);raise
            finally:
                if transport is not None:transport.close()


if __name__=='__main__':main()
