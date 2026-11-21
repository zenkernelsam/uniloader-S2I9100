#!/usr/bin/env python3
"""Exercise the actual new package, same-handle capture/qualify/boot flow offline."""
from contextlib import nullcontext
from datetime import datetime,timezone,timedelta
import importlib.util,json,re,struct
from pathlib import Path

HERE=Path(__file__).resolve().parent
s=importlib.util.spec_from_file_location('verified_session_model',HERE/'charge-verified-session.py')
m=importlib.util.module_from_spec(s);s.loader.exec_module(m)
repo=HERE.parents[1];package=repo/'out/automation/control-20261121-charge-rtc-live'
manifest=m.read_package(package);tag=manifest['control_tag'];charger=manifest['standalone_charge_control_tag']
out=repo/'out'/('charge-same-owner-check-'+datetime.now().strftime('%Y%m%d-%H%M%S'));out.mkdir()
profile=json.loads((m.o.OUT/'inventory-20261106-211114-download-profile.json').read_text())
device=dict(instance=m.readiness.CHARGER,status='OK',service='usbser',port='COM14',location=profile['location'])
m.o.host_lock=lambda:nullcontext()
m.readiness.wait_charger=lambda host,profile,wait,record:device
class Clock:
    def __init__(self):self.now=0
    def monotonic(self):return self.now
clock=Clock();m.time=clock
def utc_now():return (datetime(2026,11,21,tzinfo=timezone.utc)+timedelta(seconds=clock.now)).isoformat()
m.utc_now=utc_now
rtc_seconds=m.check.preflight.rtc_time(0x02130129,0x202611,3)
def group(number):
    ms=number*30000;polls=1+(number-1)*30;waits=number*3000
    t=ms*24000;next_t=t+24000000
    lines=[f'I9LV1 00000001 {waits:08x} {waits+1:08x} {polls:08x} 00000001 00000000\n',
        'I9RT1 0000000f 00000303 02130129 00202611 00000001 00000002\n',
        f'I9CE1 00000001 00000001 00000001 00001234 00000190 000001a6 {rtc_seconds:08x} 00000000\n',
        f'I9CHG2 seq={number:08x} ms={ms:016x} valid=1 soc=75 mv=4000 temp=250 charging=1 reason=0 full=0 timeout=0 recharging=0 elapsed={400+ms//1000}\n',
        f'I9CS1 {number:08x} {ms-3:08x} 00000000 000007d0 000003ff 000003ce 00000001 00000000\n',
        f'I9RG1 {number:08x} 0000c800 00004b00 00000032 010e013e 00000100 00000004 00000000\n',
        'I9PS1 '+' '.join(f'{x:08x}' for x in (number,polls,t&0xffffffff,t>>32,next_t&0xffffffff,next_t>>32,11,1))+'\n',
        f'I9DS1 {number:08x} 00000000 00000000 00000000 00000001 00000001 00000000 00000000\n',
        'I9UI1 00000001 5ec00000 00000780 00000020\n',
        'I9FB1 00000000 00008035 5ec00000 00000780 000efb1f 5ed77000 01000000 00000001\n',
        'I9CR1 00000001 0000000c 00000002 0004e200 00000000 0000001c 00000001 00000000\n',
        'I9DR1 00000002 00000a80 00000a80 00000001 000000a0 00000001 00000001 00000001\n',
        'I9BT1 00000001 0000000b 00000000 00000001 00000fa0 0000004b 00000000 00000000\n',
        'I9UT1 00040000 80488200 20080040 00000000 00000180 000000a0 00000001 00000000\n']
    return ''.join(lines).encode()
cases=[]
for scenario in ('healthy','fragmented','buffered-only','missing-ready','wrong-ready','missing-wake',
                 'wrong-rtc','missing-epoch','short-packet-only','read-disconnect','write-failed',
                 'wrong-ack','refused-boot'):
    clock.now=0;instances=[];directory=out/scenario
    frames=[group(n) for n in (1,2,3)]
    if scenario=='missing-wake':frames=[re.sub(rb'^I9LV1.*\n',b'',x,flags=re.M) for x in frames]
    if scenario=='wrong-rtc':frames[-1]=frames[-1].replace(b'02130129',b'02130119')
    if scenario=='missing-epoch':frames=[re.sub(rb'^I9CE1.*\n',b'',x,flags=re.M) for x in frames]
    class Transport:
        def __init__(self,port,record):
            assert port=='COM14';self.writes=[];self.closed=False;self.number=0;self.pending=[];self.ack_pending=[]
            self.ready=f'I9CHC2 READY {tag} {charger}\n'.encode()
            if scenario=='wrong-ready':self.ready=b'I9CHC2 READY '+b'0'*16+b' '+charger.encode()+b'\n'
            if scenario=='missing-ready':self.ready=b''
            self.ready_sent=False;instances.append(self)
            record('OPEN_BEGIN',port=port);record('OPEN_OK',port=port);record('DTR_BEGIN');record('DTR_OK')
        def read(self):
            clock.now+=.25
            if self.ack_pending:return self.ack_pending.pop(0)
            if not self.ready_sent:
                self.ready_sent=True;return self.ready
            if self.pending:return self.pending.pop(0)
            if scenario=='read-disconnect' and clock.now>20:raise OSError('Modeled USB disconnect')
            if scenario=='short-packet-only':
                if not self.number:self.number=1;return frames[0][:64]
                return b''
            if self.number<3 and (scenario=='buffered-only' or clock.now>=20+self.number*30):
                self.pending=[frames[self.number][i:i+256] for i in range(0,len(frames[self.number]),256)]
                self.number+=1
                return self.pending.pop(0)
            return b''
        def ticks(self):return 123
        def write(self,raw):
            self.writes.append(raw)
            assert raw==f'I9CHC2 0000007b {tag} {charger} boot\n'.encode()
            if scenario=='write-failed':raise RuntimeError('Modeled partial write; no resend')
            answer=b'I9CHC2 0000007b OK boot\n'
            if scenario=='wrong-ack':answer=b'I9CHC2 0000007c OK boot\n'
            if scenario=='refused-boot':answer=b'I9CHC2 0000007b ERR boot-unavailable\n'
            self.ack_pending=[answer[:9],answer[9:]] if scenario=='fragmented' else [answer]
        def close(self):self.closed=True
    expected=scenario in ('healthy','fragmented');failed=False
    try:m.run(package,directory,90,0,Transport)
    except (ValueError,RuntimeError,OSError):failed=True
    assert failed!=expected and len(instances)==1 and instances[0].closed
    events=[json.loads(line) for line in (directory/'events.jsonl').read_text().splitlines()]
    assert events[-1]['phase']=='CLOSED'
    sent=scenario in ('healthy','fragmented','write-failed','wrong-ack','refused-boot')
    assert len(instances[0].writes)==int(sent)
    if expected:
        observation=directory/'observation'
        result=m.qualify_observation(observation,manifest)
        assert result['summary']['interval_complete'] and not result['summary']['closed']
        assert not result['summary']['complete'] and result['charger_liveness']['policy_advanced']
        frozen=[json.loads(line) for line in (observation/'events.jsonl').read_text().splitlines()]
        assert frozen[-1]['phase']=='OBSERVATION_COMPLETE' and not any(x['phase']=='CLOSED' for x in frozen)
        assert not any(x['phase']=='STOP' for x in events)
    else:assert any(x['phase']=='STOP' for x in events)
    cases.append(dict(scenario=scenario,writes=len(instances[0].writes),openers=1,closed=True,accepted=expected,hardware=False))
# Ordinary summary must reject a frozen interval as a finished serial session.
try:m.check.s.summarize(out/'healthy/observation')
except ValueError:pass
else:raise AssertionError('Open observation disguised as a completed/closed owner')
(out/'result.json').write_text(json.dumps(dict(result='PASS',hardware=False,cases=cases,
    package_sha256=manifest['artifacts']['zImage']['sha256'],
    scope='Actual same-owner capture/qualification/parser/write/ACK with native transport and clocks modeled'),indent=2)+'\n')
print('PASS one owner/DTR, real package qualification, stale-buffer refusal, exact ACK, no reopen/resend')
print('EVIDENCE',out)
