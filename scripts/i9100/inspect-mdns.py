#!/usr/bin/env python3
"""Read bounded MDNS startup evidence with one verified serial handle."""
import argparse
from datetime import datetime, timezone
import importlib.util
import json
from pathlib import Path
import struct


def module(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    result = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(result)
    return result


TABLES = {
    'spawn': ('_i9100_mdns_spawn_diag', 8, 4,
              ['caller', 'stage', 'error', 'result']),
    'syscalls': ('_i9100_mdns_syscall_diag', 64, 16,
                 ['pid', 'role', 'syscall', 'nargs'] + ['arg'+str(n) for n in range(7)] +
                 ['error', 'result', 'pc', 'lr', 'stage']),
    'exit_user': ('_i9100_mdns_exit_user_diag', 8, 52,
                  ['pid', 'status', 'pc', 'lr', 'sp', 'fp', 'frames', 'walk_error'] +
                  ['lr'+str(n) for n in range(8)] + ['error_pointer', 'copy_error', 'role', 'stage']),
    'lifecycle': ('_i9100_mdns_lifecycle_diag', 8, 9,
                  ['pid', 'role', 'wait_status', 'task', 'own_context', 'exception', 'code', 'subcode', 'stage']),
    'sandbox': ('_i9100_mdns_sandbox_diag', 8, 5,
                ['pid', 'operation', 'original_error', 'providers', 'stage']),
    'tcc': ('_i9100_tcc_development_diag', 16, 7,
            ['pid', 'operation', 'original_error', 'result', 'providers', 'unconfined', 'stage']),
}

EXIT_FIELDS = ['sequence', 'pid', 'signal', 'exit_code', 'exception_known',
               'exception', 'code', 'subcode', 'free_pages']
GRAPHICS_FIELDS = '''version known loss unknown clients last_client owner_pid
latest_open_client latest_open_pid selector3_calls selector3_successes selector8_calls selector8_successes
selector18_calls selector18_successes prereq_last_client prereq_last_pid prereq_last_selector prereq_last_result
selector4_calls selector4_rejects selector5_calls selector5_rejects selector5_backend_calls selector5_completed
selector6_calls selector6_rejects selector9_calls selector9_rejects port_calls port_rejects
port_entries port_preflight_rejects port_gate_entries port_returns port_entry_client port_entry_pid
port_entry_type port_entry_valid port_last_return send_calls send_success send_failures copy_send_failures
stale_completions last_selector last_result last_reason last_transaction_lo last_transaction_hi
last_surface last_mismatch last_wait_lo last_wait_hi requested enabled closed port_present callback_present
generation_lo generation_hi last_send_status last_timer_status events_published events_taken
selector4_result selector5_result selector6_result selector9_result
selector4_reason selector5_reason selector6_reason selector9_reason'''.split()


def capture_ui_observations(kernel, symbols, out):
    """Retained exit/abort evidence and display counters from this exact BUILD."""
    result = {}
    key='_i9100_render_receive_payload'
    if key in symbols.values:
        data=kernel.read(symbols[key],(6+32)*4)
        (out/'render-receive-payload.bin').write_bytes(data)
        sequence,pid,length,msgid,bits,status=struct.unpack_from('<6I',data)
        if length>128:raise ValueError('Invalid retained render payload')
        result['render_payload']=dict(sequence=sequence,pid=pid,length=length,id=msgid,
                                     bits=bits,status=status,hex=data[24:24+length].hex())
    key='_i9100_render_commit_payload'
    if key in symbols.values:
        data=kernel.read(symbols[key],(6+32)*4)
        (out/'render-commit-payload.bin').write_bytes(data)
        sequence,pid,length,msgid,bits,wire_size=struct.unpack_from('<6I',data)
        if length>128:raise ValueError('Invalid retained commit prefix')
        result['render_commit_payload']=dict(sequence=sequence,pid=pid,length=length,id=msgid,
            bits=bits,wire_size=wire_size,hex=data[24:24+length].hex())
    key='_i9100_render_transport_diag'
    if key in symbols.values:
        data=kernel.read(symbols[key],(1+128*10)*4)
        (out/'render-transport.bin').write_bytes(data)
        words=struct.unpack('<1281I',data)
        fields=['sequence','pid','thread','stage','id','size','user_size','bits','options','result']
        rows=[dict(zip(fields,words[1+n*10:1+(n+1)*10])) for n in range(128) if words[1+n*10]]
        result['render_transport']=dict(sequence=words[0],rows=sorted(rows,key=lambda r:r['sequence']))
    key='_i9100_user_fault_detail_diag'
    if key in symbols.values:
        data=kernel.read(symbols[key],(1+32*29)*4)
        (out/'user-fault-detail.bin').write_bytes(data)
        fields=['sequence','pid','thread','task','type','pc','lr','sp','far','fsr','psr','result']+['r'+str(n) for n in range(13)]
        words=struct.unpack('<929I',data)
        rows=[]
        for n in range(32):
            offset=(1+n*29)*4
            if not words[1+n*29]:continue
            row=dict(zip(fields,words[1+n*29:1+n*29+25]))
            row['name']=data[offset+100:offset+116].split(b'\0')[0].decode('ascii','replace')
            rows.append(row)
        result['user_fault_details']=dict(sequence=words[0],rows=sorted(rows,key=lambda r:r['sequence']))
    for key,count,stride,fields in [
        ('_i9100_render_boundary_diag',64,8,['pid','stage','id','size','user_size','bits','options','result']),
        ('_i9100_user_fault_owner_diag',32,12,['sequence','pid','thread','task','type','pc','lr','sp','far','fsr','psr','result'])]:
        if key in symbols.values:
            data=kernel.read(symbols[key],(1+count*stride)*4)
            (out/(key.lstrip('_')+'.bin')).write_bytes(data)
            words=struct.unpack('<'+'I'*(1+count*stride),data)
            records=[]
            for n in range(count):
                row=words[1+n*stride:1+(n+1)*stride]
                if row[1] if 'boundary' in key else row[0]:records.append(dict(zip(fields,row)))
            result[key.lstrip('_')]=dict(count=words[0],rows=records)
    for name in ('i9100_process_exit', 'i9100_backboard_exit'):
        key = '_'+name
        if key in symbols.values:
            data = kernel.read(symbols[key], 36)
            (out/(name+'.bin')).write_bytes(data)
            result[name] = dict(zip(EXIT_FIELDS, struct.unpack('<9I', data)))
    key = '_i9100_signal_exit'
    if key in symbols.values:
        data = kernel.read(symbols[key], 60)
        (out/'signal-exit.bin').write_bytes(data)
        fields = ['sequence','pid','task','signal','context_pid','pc','lr','caller_pc','irq','flavor']
        result['signal_exit'] = dict(zip(fields, struct.unpack_from('<10I',data)))
        result['signal_exit']['context_name'] = data[40:57].split(b'\0')[0].decode('ascii','replace')
    key = '_i9100_abort_observation'
    if key in symbols.values:
        data = kernel.read(symbols[key], 336)
        (out/'abort-observation.bin').write_bytes(data)
        fields = ['sequence','pid','task','pc','lr','sp','fp','count','error'] + ['frame'+str(n) for n in range(8)] + \
                 ['slab','slab_object','slab_expected','slab_actual','slab_status','text_kind']
        result['abort'] = dict(zip(fields,struct.unpack_from('<23I',data)))
        result['abort']['text'] = data[92:333].split(b'\0')[0].decode('utf-8','replace')
    for name, size in [('i9100_panel_console_enabled',4), ('i9100_fb_physical',4),
                       ('i9100_graphics_seq',8), ('i9100_frame_performance',28)]:
        key = '_'+name
        if key in symbols.values:
            data = kernel.read(symbols[key],size)
            (out/(name+'.bin')).write_bytes(data)
            result[name] = list(struct.unpack('<'+'I'*(size//4),data))
    key='_i9100_copypv_last'
    if key in symbols.values:
        data=kernel.read(symbols[key],32)
        (out/'copypv-last.bin').write_bytes(data)
        result['copypv_last']=dict(zip(['sequence','source_low','source_high','sink_low','sink_high',
                                      'bytes','flags','caller'],struct.unpack('<8I',data)))
    key = '_i9100_previous_boot'
    if key in symbols.values:
        data=kernel.read(symbols[key],64)
        (out/'previous-boot.bin').write_bytes(data)
        fields=['magic','version','bytes','valid','inform6','inform7','stage','reason','pc','lr','far','fsr'] + \
               ['reserved'+str(n) for n in range(4)]
        result['previous_boot']=dict(zip(fields,struct.unpack('<16I',data)))
    keys = [name for name in symbols.values if name.endswith('leo_graphics_state')]
    if len(keys) == 1:
        if len(GRAPHICS_FIELDS) != 73:
            raise ValueError('Unexpected graphics counter layout')
        data = kernel.read(symbols[keys[0]],73*4)
        (out/'graphics-state.bin').write_bytes(data)
        result['graphics'] = dict(zip(GRAPHICS_FIELDS,struct.unpack('<73I',data)))
        if result['graphics']['version'] not in (0,2):
            raise ValueError('Unknown live graphics counter version')
    (out/'ui-observations.json').write_text(json.dumps(result,indent=2)+'\n',encoding='utf-8')
    preview=dict(result)
    for key in ('render_transport','user_fault_details'):
        if key in result:
            preview[key]=dict(sequence=result[key]['sequence'],rows=result[key]['rows'][-8:])
    print('ui-observations',json.dumps(preview),flush=True)
    return result


def decode_table(data, cap, stride, fields):
    words = struct.unpack('<'+str(1+cap*stride)+'I', data)
    if words[0] > cap:
        raise ValueError('Counter exceeds the matching kernel layout')
    rows = []
    for n in range(words[0]):
        values = words[1+n*stride:1+(n+1)*stride]
        row = dict(zip(fields, values))
        if stride == 52:
            row['error_text'] = data[(1+n*stride+20)*4:(1+n*stride+52)*4].split(b'\0')[0].decode('utf-8', 'replace')
        rows.append(row)
    return dict(count=words[0], rows=rows)


def main():
    here = Path(__file__).resolve().parent
    f = module('forensic', here/'forensic-session.py')
    m = module('memory', here/'live-memory.py')
    odin = module('odin', here/'odin-loop.py')
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--kernel', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--stacks', action='store_true',
                        help='Capture SB/configd/backboardd/MDNS stacks before closing this handle')
    a = parser.parse_args()
    symbols = m.Symbols(a.kernel)
    for symbol, _, _, _ in TABLES.values():
        symbols[symbol]
    symbols['_i9100_mdns_stderr_diag']
    out = a.output.resolve()
    if out.exists() or not out.is_relative_to(f.REPO/'out'):
        parser.error('Fresh directory inside loader out required')
    with odin.host_lock():
        device = odin.cdc(odin.Host().inventory())
        profile = json.loads((f.REPO/'out/automation/inventory-20261108-recovery-download.json').read_text(encoding='utf-8'))
        if device is None or odin.normalize_location(device['location']) != profile['location']:
            raise RuntimeError('Approved live device absent')
        out.mkdir(parents=True)
        transport = None
        with (out/'events.jsonl').open('x') as events, (out/'received.bin').open('xb') as capture:
            def record(phase, **fields):
                row = dict(time=datetime.now(timezone.utc).isoformat(), phase=phase, **fields)
                events.write(json.dumps(row)+'\n'); events.flush()
                if phase in ('OPEN_OK', 'DTR_OK', 'STOP', 'DONE', 'CLOSED'):
                    print(json.dumps(row), flush=True)
            try:
                transport = f.WinTransport(device['port'], record)
                session = f.Session(transport, symbols.tag, record, capture, timeout=20)
                session.handshake()
                kernel = m.Kernel(session, symbols)
                result = dict(tag=symbols.tag, device=device, tables={})
                result['ui_observations'] = capture_ui_observations(kernel,symbols,out)
                result['resources'] = {}
                for name in ('_maxproc', '_maxprocperuid', '_hard_maxproc', '_nprocs', '_vm_page_free_count'):
                    if name in symbols.values:
                        data = kernel.read(symbols[name], 4)
                        (out/(name.lstrip('_')+'.bin')).write_bytes(data)
                        result['resources'][name] = struct.unpack('<I', data)[0]
                print('resources', json.dumps(result['resources']), flush=True)
                for name, (symbol, cap, stride, fields) in TABLES.items():
                    data = kernel.read(symbols[symbol], (1+cap*stride)*4)
                    (out/(name+'.bin')).write_bytes(data)
                    result['tables'][name] = decode_table(data, cap, stride, fields)
                    table = result['tables'][name]
                    preview = table if table['count'] <= 8 else dict(count=table['count'],
                        first=table['rows'][:3], last=table['rows'][-3:])
                    print(name, json.dumps(preview), flush=True)
                if '_i9100_mdns_development_diag' in symbols.values:
                    data = kernel.read(symbols['_i9100_mdns_development_diag'], (1+8*7)*4)
                    (out/'development.bin').write_bytes(data)
                    fields = ['pid', 'operation', 'original_error', 'result', 'providers', 'unconfined', 'stage']
                    result['tables']['development'] = decode_table(data, 8, 7, fields)
                    print('development', json.dumps(result['tables']['development']), flush=True)
                data = kernel.read(symbols['_i9100_mdns_stderr_diag'], (6+128)*4)
                (out/'stderr.bin').write_bytes(data)
                sequence, pid, task, role, used, error = struct.unpack_from('<6I', data)
                if used > 511:
                    raise ValueError('Invalid stderr length')
                result['stderr'] = dict(sequence=sequence, pid=pid, task=hex(task), role=role,
                    used=used, copy_error=error, text=data[24:24+used].decode('utf-8', 'replace'))
                print('stderr', json.dumps(result['stderr']), flush=True)
                if a.stacks:
                    stack_tool = module('stack_tool', here/'inspect-stacks.py')
                    processes = []
                    for process in ('SpringBoard', 'configd', 'backboardd', 'mDNSResponder'):
                        processes.append(stack_tool.capture_process(session, kernel, process, out, m, True))
                        (out/'stacks.json').write_text(json.dumps(dict(tag=symbols.tag,
                            processes=processes), indent=2)+'\n', encoding='utf-8')
                    _, data = session.command('threads launchd')
                    (out/'launchd-threads.txt').write_bytes(data)
                else:
                    for process in ('mDNSResponder', 'mDNSResponderHel', 'launchd', 'configd', 'SpringBoard'):
                        _, data = session.command('threads '+process)
                        (out/(process+'-threads.txt')).write_bytes(data)
                (out/'results.json').write_text(json.dumps(result, indent=2)+'\n', encoding='utf-8')
                record('DONE')
            except BaseException as exc:
                record('STOP', error=str(exc), retry=False)
                raise
            finally:
                if transport is not None:
                    transport.close()


if __name__ == '__main__':
    main()
