#!/usr/bin/env python3
"""Read bounded MDNS startup evidence with one verified serial handle."""
import argparse
import hashlib
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


class ObservationSymbols:
    """A read selection; never replace the live mapper's full symbol table."""
    def __init__(self, source, names):
        self.values = {key: value for key, value in source.values.items() if key in names}

    def __getitem__(self, key):
        return self.values[key]


ABORT_SYMBOLS = {'_i9100_abort_frames', '_i9100_abort_observation',
                 '_i9100_backboard_abort_observation', '_i9100_process_exit',
                 '_i9100_backboard_exit', '_i9100_panel_console_enabled',
                 '_i9100_graphics_seq', '_i9100_backboard_vm_diag',
                 '_i9100_ios6_slab_payload', '_i9100_ios6_slab_vm_diag',
                 '_i9100_quartz_fault_payload', '_i9100_input_test',
                 '_i9100_touch_observation','_i9100_ls_ui_diag'} | {
                     '_i9100_power_'+name for name in
                     ('valid', 'percent', 'mv', 'connected', 'charging', 'temp', 'reason', 'revision_value')}
ABORT_SYMBOLS.add('_i9100_audio_property_lock_diag')
ABORT_SYMBOLS.update({'_i9100_audio_property_lock_history','_i9100_media_lifecycle_diag'})
ABORT_SYMBOLS.add('_i9100_media_signal_diag')
ABORT_SYMBOLS.add('_i9100_media_kill_payload')
ABORT_SYMBOLS.add('_i9100_media_audio_runtime')
ABORT_SYMBOLS.add('_i9100_signal_exit')
ABORT_SYMBOLS.update({'_i9100_fig_rpc_diag','_i9100_springboard_kill_payload','_i9100_audio_wait_diag'})
ABORT_SYMBOLS.add('_i9100_syscall_restart_diag')
ABORT_SYMBOLS.add('_i9100_previous_boot')
ABORT_SYMBOLS.add('_i9100_media_threads')
ABORT_SYMBOLS.add('_i9100_audio_owner_diag')
LS_SYMBOLS = {'_i9100_ls_publish_wire_diag','_i9100_ls_bootstrap_diag',
              '_i9100_ls_store_reply_diag','_i9100_ls_fault_stack',
              '_i9100_process_exit','_i9100_backboard_exit','_i9100_ls_ui_diag','_i9100_ls_delivery_diag',
              '_i9100_ls_reply_alloc_diag','_i9100_ls_delivery_stride'}
LS_SYMBOLS.add('_i9100_ls_file_diag')
LS_SYMBOLS.add('_i9100_ls_wire_diag')
LS_SYMBOLS.update({'_i9100_mach_failure_diag', '_i9100_mig_error_diag', '_i9100_vm_error_diag'})
LS_SYMBOLS.update({'_i9100_ls_query_diag','_i9100_ls_query_alloc_diag','_i9100_ls_query_alloc_failure_diag'})
LS_SYMBOLS.add('_i9100_ls_callback_diag')


def capture_ui_observations(kernel, symbols, out):
    """Retained exit/abort evidence and display counters from this exact BUILD."""
    result = {}
    key='_i9100_audio_owner_diag'
    if key in symbols.values:
        data=kernel.read(symbols[key],(4+8*64)*4);(out/'audio-owners.bin').write_bytes(data)
        count,version,capacity,stride=struct.unpack_from('<4I',data)
        if count:
            if version!=1 or capacity!=8 or stride!=64 or count>8:raise ValueError('Unknown audio owner schema')
            rows=[]
            for n in range(count):
                w=struct.unpack_from('<64I',data,(4+n*64)*4)
                if not w[0]:continue
                if w[0]!=n+1 or w[13]!=1 or w[10]>6:raise ValueError('Unknown audio owner row')
                rows.append(dict(sequence=w[0],pid=w[1],task=w[2],wait_mutex=w[3],code=w[4],
                    owner_low=w[5],owner_high=w[6],thread=w[7],state=w[8],error=w[9],
                    frame_count=w[10],stack_error=w[11],mutex_error=w[12],incoming_mask=w[14],scanned=w[15],
                    registers=list(w[16:29]),sp=w[29],lr=w[30],pc=w[31],cpsr=w[32],mutex_words=list(w[34:46]),
                    frame_rows=[dict(fp=w[46+k*3],previous=w[47+k*3],lr=w[48+k*3]) for k in range(w[10])]))
            result['audio_owners']=dict(count=count,rows=rows,retention='owner at original first-task wait; correlate wait sequence')
    key='_i9100_media_threads'
    if key in symbols.values:
        data=kernel.read(symbols[key],(16+16*72)*4);(out/'media-first-threads.bin').write_bytes(data)
        w=struct.unpack_from('<16I',data)
        if w[0]:
            if w[0]!=1 or w[1] not in (1,2) or w[4]>16:raise ValueError('Unknown first-media thread snapshot schema')
            fields='published version pid task count error slide incoming_mask runtime_address runtime_error calls callback_stage released reserved0 reserved1 reserved2'.split()
            r=dict(zip(fields,w));rows=[]
            for n in range(w[4]):
                row=struct.unpack_from('<72I',data,(16+n*72)*4)
                if row[0]!=n+1 or row[23]>6:raise ValueError('Unknown first-media row schema')
                rows.append(dict(sequence=row[0],thread=row[1],tid_low=row[2],tid_high=row[3],state=row[4],error=row[5],
                    registers=list(row[6:19]),sp=row[19],lr=row[20],pc=row[21],cpsr=row[22],frame_count=row[23],
                    mutex_error=row[24],stack_error=row[25],mutex_words=list(row[28:40]),
                    frame_rows=[dict(fp=row[40+k*3],previous=row[41+k*3],lr=row[42+k*3]) for k in range(row[23])],
                    handler_args=list(row[60:66]),handler_args_observed=row[66],
                    instruction_error=row[67] if w[1]==2 and not row[5] and (row[22]&31)==16 else None,
                    instruction_hex=data[(16+n*72+68)*4:(16+n*72+72)*4].hex()
                        if w[1]==2 and not row[5] and (row[22]&31)==16 and row[67]==0 else None))
            r['rows']=rows;result['media_first_threads']=r
    key='_i9100_syscall_restart_diag'
    if key in symbols.values:
        data=kernel.read(symbols[key],(1+16*10)*4);(out/'syscall-restarts.bin').write_bytes(data)
        count=struct.unpack_from('<I',data)[0]
        if count>16:raise ValueError('Unknown syscall restart capacity')
        fields='sequence pid code before_pc restart_pc width cpsr r0 r1 r12'.split();rows=[]
        for n in range(count):
            w=struct.unpack_from('<10I',data,(1+n*10)*4)
            if not w[0]:continue
            r=dict(zip(fields,w))
            if r['sequence']!=n+1 or r['width'] not in (2,4) or ((r['before_pc']-r['restart_pc'])&0xffffffff)!=r['width'] or r['cpsr']&(1<<29):
                raise ValueError('Unknown syscall restart schema')
            rows.append(r)
        result['syscall_restarts']=dict(count=count,rows=rows,retention='first16')
    key='_i9100_audio_wait_diag'
    if key in symbols.values:
        data=kernel.read(symbols[key],(1+8*100)*4);(out/'audio-waits.bin').write_bytes(data)
        count=struct.unpack_from('<I',data)[0]
        if count>8:raise ValueError('Unknown audio wait capacity')
        fields='sequence pid task thread code mutex pc lr sp fp frames stack_error mutex_error version'.split()
        rows=[]
        for n in range(count):
            w=struct.unpack_from('<100I',data,(1+n*100)*4)
            if not w[0]:continue
            r=dict(zip(fields,w[:14]))
            if r['sequence']!=n+1 or r['version']!=1 or r['code'] not in (301,302) or r['frames']>8:
                raise ValueError('Unknown audio wait schema')
            r.update(registers=list(w[14:27]),cpsr=w[27],mutex_words=list(w[28:44]),runtime_words=list(w[44:60]),
                frame_rows=[dict(fp=w[60+i*3],previous=w[61+i*3],lr=w[62+i*3]) for i in range(w[10])])
            rows.append(r)
        result['audio_waits']=dict(count=count,rows=rows,retention='first installed media task, callback stage 2')
    key='_i9100_fig_rpc_diag'
    if key in symbols.values:
        data=kernel.read(symbols[key],(1+64*56)*4);(out/'fig-rpc.bin').write_bytes(data)
        count=struct.unpack_from('<I',data)[0]
        if count>64:raise ValueError('Unknown Fig RPC history capacity')
        fields='sequence version stage pid thread task role id size captured bits option result address peer completion_seen completion_result receive_seen receive_result request_token sender_pid sender_euid reserved0 reserved1'.split()
        rows=[]
        for n in range(count):
            at=(1+n*56)*4;w=struct.unpack_from('<24I',data,at)
            if not w[0]:continue
            r=dict(zip(fields,w))
            if r['sequence']!=n+1 or r['version']!=1 or r['stage'] not in range(1,7) or r['role'] not in (1,2) or r['id'] not in (9393,9493,2020,2120) or not 24<=r['captured']<=128 or r['captured']!=r['size'] or r['completion_seen'] not in (0,1) or r['receive_seen'] not in (0,1):
                raise ValueError('Unknown Fig RPC row schema')
            raw=data[at+96:at+96+r['captured']];r['raw_hex']=raw.hex()
            r['header']=[hex(v) for v in struct.unpack_from('<6I',raw)]
            r['user_bytes_observed']=r['stage']==6 and r['result']==0
            rows.append(r)
        result['fig_rpc']=dict(count=count,rows=rows,capacity=64,retention='first rows only')
    key='_i9100_springboard_kill_payload'
    if key in symbols.values:
        data=kernel.read(symbols[key],768);(out/'springboard-kill-payload.bin').write_bytes(data)
        w=struct.unpack_from('<64I',data)
        if w[0]:
            if w[0]!=1 or w[7]>16 or w[11]>512 or w[13]!=1 or w[14]!=9 or w[15]!=2:
                raise ValueError('Unknown SpringBoard self-kill schema')
            r=dict(zip('sequence pid task pc lr sp fp count stack_error object copy_error bytes slide version signal role'.split(),w[:16]))
            r['frames']=[dict(fp=w[16+n*3],previous=w[17+n*3],lr=w[18+n*3]) for n in range(w[7])]
            r['object_hex']=data[256:256+w[11]].hex();result['springboard_kill_payload']=r
    key='_i9100_media_audio_runtime'
    if key in symbols.values:
        data=kernel.read(symbols[key],96);(out/'media-audio-runtime.bin').write_bytes(data)
        words=struct.unpack('<24I',data)
        if words[0]:
            if words[0]!=1:raise ValueError('Unknown media audio runtime schema')
            result['media_audio_runtime']=dict(zip('version pid task address copy_error site site_copy_error branch_target'.split(),words[:8]))
            result['media_audio_runtime']['words']=list(words[8:])
            result['media_audio_runtime']['stage']=words[9]
    key='_i9100_ls_callback_diag'
    if key in symbols.values:
        data=kernel.read(symbols[key],(1+64*96)*4);(out/'ls-callback.bin').write_bytes(data)
        sequence=struct.unpack_from('<I',data)[0];rows=[]
        fields='sequence version stage pid thread token request_address reply_address vm_result request_error reply_error request_size reply_name kind pc lr sp fp callback_fp stack_error'.split()
        for n in range(64):
            at=(1+n*96)*4;w=struct.unpack_from('<20I',data,at)
            if not w[0] or ((sequence-w[0])&0xffffffff)>=64:continue
            r=dict(zip(fields,w))
            if r['version']!=1 or r['stage'] not in (1,2,3,4) or r['kind'] not in (1,2,3) or r['request_size']!=352:
                raise ValueError('Unknown LS callback observer layout')
            request=data[at+80:at+272];reply=data[at+272:at+320]
            r.update(request_hex=request.hex(),reply_hex=reply.hex(),
                request_header=[hex(v) for v in struct.unpack_from('<6I',request)],
                reply_header=[hex(v) for v in struct.unpack_from('<6I',reply)],
                request_bundle=request[32:].split(b'\0')[0].decode('ascii','replace'),
                reply_retcode=struct.unpack_from('<I',reply,32)[0],
                reply_value=struct.unpack_from('<I',reply,36)[0])
            frames=struct.unpack_from('<16I',data,at+320)
            r['frames']=[dict(fp=hex(frames[i]),lr=hex(frames[i+1])) for i in range(0,16,2) if frames[i]]
            rows.append(r)
        result['ls_callback']=dict(sequence=sequence,rows=sorted(rows,key=lambda r:((sequence-r['sequence'])&0xffffffff),reverse=True))
    key='_i9100_media_kill_payload'
    if key in symbols.values:
        data=kernel.read(symbols[key],768);(out/'media-kill-payload.bin').write_bytes(data)
        w=struct.unpack('<192I',data)
        if w[0]:
            if w[0]!=1 or w[7]>16 or w[11]>512 or w[13]!=1:raise ValueError('Unknown media kill snapshot schema')
            fields='sequence pid task pc lr sp fp count stack_error object copy_error bytes slide version reserved0 reserved1'.split()
            r=dict(zip(fields,w[:16]));r['frames']=[dict(zip(('fp','previous','lr'),w[16+n*3:19+n*3])) for n in range(w[7])]
            r['object_hex']=data[256:256+w[11]].hex();result['media_kill_payload']=r
    key='_i9100_media_signal_diag'
    if key in symbols.values:
        data=kernel.read(symbols[key],(1+8*13)*4);(out/'media-signals.bin').write_bytes(data)
        values=struct.unpack('<105I',data)
        if values[0]>8:raise ValueError('Invalid media signal history count')
        rows=[]
        fields='target signal source pc lr caller irq flavor'.split()
        for n in range(values[0]):
            at=1+n*13;row=dict(zip(fields,values[at:at+8]));row['stage']=values[at+12]
            row['name']=data[(at+8)*4:(at+12)*4].split(b'\0')[0].decode('ascii','replace');rows.append(row)
        result['media_signals']=dict(count=values[0],rows=rows)
    key='_i9100_audio_property_lock_diag'
    if key in symbols.values:
        data=kernel.read(symbols[key],48);(out/'audio-property-lock.bin').write_bytes(data)
        values=struct.unpack('<12I',data)
        if values[0] not in (0,1,2,3) or values[8] not in (0,1):
            raise ValueError('Unknown audio property lock repair state')
        fields='state pid task slide site trampoline vm_result copy_error installed restore_result install_stage attempt'.split()
        result['audio_property_lock']=dict(zip(fields,values))
    for label,key,words,fields in [
        ('audio_property_history','_i9100_audio_property_lock_history',12,
         'state pid task slide site trampoline vm_result copy_error installed restore_result install_stage attempt'.split()),
        ('media_lifecycle','_i9100_media_lifecycle_diag',10,
         'pid wait_status task own_context exception code subcode csflags reserved stage'.split())]:
        if key in symbols.values:
            data=kernel.read(symbols[key],(1+8*words)*4);(out/(label+'.bin')).write_bytes(data)
            values=struct.unpack('<'+'I'*(1+8*words),data)
            if values[0]>8:raise ValueError('Invalid bounded media history count')
            result[label]=dict(count=values[0],rows=[dict(zip(fields,values[1+n*words:1+(n+1)*words])) for n in range(values[0])])
    key='_i9100_ls_query_diag'
    if key in symbols.values:
        data=kernel.read(symbols[key],(1+32*104)*4);(out/'ls-query.bin').write_bytes(data)
        sequence=struct.unpack_from('<I',data)[0];rows=[]
        fields='sequence pid thread stage id message_size captured bits options result sender_pid sender_euid completion_seen completion_result address version'.split()
        for n in range(32):
            at=(1+n*104)*4;values=struct.unpack_from('<16I',data,at)
            if not values[0]:continue
            if ((sequence-values[0])&0xffffffff)>=32:continue
            r=dict(zip(fields,values))
            if r['version']!=1 or r['stage'] not in range(1,7) or r['id'] not in (14012,14112) or not 24<=r['captured']<=352 or r['captured']!=r['message_size']:
                raise ValueError('Unknown LS query observer layout')
            raw=data[at+64:at+64+r['captured']]
            (out/f'query-{r["sequence"]}-stage{r["stage"]}.bin').write_bytes(raw)
            r['sha256']=hashlib.sha256(raw).hexdigest();r['hex']=raw.hex()
            r['header_id']=struct.unpack_from('<I',raw,20)[0]
            r['user_bytes_observed']=r['stage']==6 and r['result']==0
            rows.append(r)
        result['ls_query']=dict(sequence=sequence,rows=sorted(rows,key=lambda x:((sequence-x['sequence'])&0xffffffff),reverse=True))
    for key,label,capacity,ring in (('_i9100_ls_query_alloc_diag','ls_query_alloc',32,True),
                                    ('_i9100_ls_query_alloc_failure_diag','ls_query_alloc_failure',8,False)):
        if key not in symbols.values:continue
        data=kernel.read(symbols[key],(1+capacity*12)*4);(out/(label+'.bin')).write_bytes(data)
        count=struct.unpack_from('<I',data)[0]
        if not ring and count>capacity:raise ValueError('Invalid LS allocation failure capacity')
        rows=[];fields='sequence pid thread target address size_low size_high flags result backend before after'.split()
        for n in range(capacity if ring else count):
            values=struct.unpack_from('<12I',data,(1+n*12)*4)
            if not values[0] or (ring and ((count-values[0])&0xffffffff)>=capacity):continue
            r=dict(zip(fields,values))
            if r['size_low']!=4160 or r['backend'] not in (0,1) or (not ring and not r['result']):
                raise ValueError('Unknown LS allocation observer layout')
            rows.append(r)
        result[label]=dict(sequence=count if ring else None,count=len(rows),rows=sorted(rows,key=lambda x:x['sequence']))
    key='_i9100_ls_file_diag'
    if key in symbols.values:
        data=kernel.read(symbols[key],(1+64*112)*4);(out/'ls-files.bin').write_bytes(data)
        sequence=struct.unpack_from('<I',data)[0];rows=[]
        fields='sequence pid thread code error result fd flags mode count path_error path2_error pc lr stage version'.split()
        for n in range(64):
            at=(1+n*112)*4;values=struct.unpack_from('<16I',data,at)
            if not values[0] or values[0]>sequence or sequence-values[0]>=64:continue
            r=dict(zip(fields,values))
            if r['version']!=1 or r['stage']!=1:raise ValueError('Unknown LS file observer')
            r['path']=data[at+64:at+256].split(b'\0')[0].decode('utf-8','replace')
            r['path2']=data[at+256:at+448].split(b'\0')[0].decode('utf-8','replace')
            rows.append(r)
        result['ls_files']=dict(sequence=sequence,rows=sorted(rows,key=lambda x:x['sequence']))
    key='_i9100_ls_reply_alloc_diag'
    if key in symbols.values:
        data=kernel.read(symbols[key],(1+32*12)*4);(out/'ls-reply-alloc.bin').write_bytes(data)
        count=struct.unpack_from('<I',data)[0]
        if count>32:raise ValueError('Invalid lsd reply allocation count')
        fields='sequence pid thread target address size_low size_high flags result backend before after'.split()
        rows=[]
        for n in range(count):
            values=struct.unpack_from('<12I',data,(1+n*12)*4)
            if values[0]:rows.append(dict(zip(fields,values)))
        result['ls_reply_alloc']=dict(count=count,rows=rows)
    key='_i9100_ls_delivery_diag'
    if key in symbols.values:
        stride=kernel.u32(symbols['_i9100_ls_delivery_stride']) if '_i9100_ls_delivery_stride' in symbols.values else 716
        if stride not in (716,848):raise ValueError('Unknown LS delivery stride')
        capacity=(stride-16)*2;version=1 if stride==716 else 2
        data=kernel.read(symbols[key],(1+8*stride)*4);(out/'ls-delivery.bin').write_bytes(data)
        count=struct.unpack_from('<I',data)[0]
        if count>8:raise ValueError('Invalid delivery reservation count')
        rows=[];fields='sequence pid thread task id address bytes result read_error read_ok version mismatch sender_pid'.split()
        for n in range(count):
            offset=(1+n*stride)*4;values=struct.unpack_from('<13I',data,offset)
            if not values[0]:continue
            r=dict(zip(fields,values))
            if r['version']!=version or r['bytes']>capacity or r['sequence']!=n+1:
                raise ValueError('Unknown LS delivery layout')
            source=data[offset+64:offset+64+r['bytes']]
            actual=data[offset+64+capacity:offset+64+capacity+r['bytes']] if r['read_ok'] else b''
            (out/f'delivery-{n+1}-source.bin').write_bytes(source)
            (out/f'delivery-{n+1}-user.bin').write_bytes(actual)
            r.update(source_sha=hashlib.sha256(source).hexdigest(),user_sha=hashlib.sha256(actual).hexdigest(),
                source_prefix=source[:40].hex(),user_prefix=actual[:40].hex())
            rows.append(r)
        result['ls_delivery']=dict(count=count,rows=rows)
    power = {}
    for name in ('valid', 'percent', 'mv', 'connected', 'charging', 'temp', 'reason', 'revision_value'):
        key = '_i9100_power_'+name
        if key in symbols.values:
            value = kernel.u32(symbols[key])
            if name in ('temp', 'reason') and value & 0x80000000:
                value -= 0x100000000
            power[name] = value
    if power:
        result['power'] = dict(snapshot='non-atomic workloop fields', **power)
    key='_i9100_ls_ui_diag'
    if key in symbols.values:
        data=kernel.read(symbols[key],(1+32*8)*4)
        (out/'ls-ui-budget.bin').write_bytes(data)
        count=struct.unpack_from('<I',data)[0]
        fields='sequence pid thread phase result option budget id'.split()
        rows=[]
        for n in range(32):
            values=struct.unpack_from('<8I',data,(1+n*8)*4)
            if values[0] and values[0]<=count and count-values[0]<32:
                if values[3] not in (1,2,3) or values[6]!=5000 or values[7]!=14012:
                    raise ValueError('Unknown UI receive budget record')
                rows.append(dict(zip(fields,values)))
        rows.sort(key=lambda row:row['sequence'])
        result['ls_ui_budget']=dict(sequence=count,rows=rows)
    for key, capacity, label in (('_i9100_backboard_vm_diag',256,'backboard_vm'),
                                 ('_i9100_ios6_slab_vm_diag',64,'slab_vm')):
        if key not in symbols.values:
            continue
        data = kernel.read(symbols[key], (4+capacity*28)*4)
        (out/(label.replace('_','-')+'.bin')).write_bytes(data)
        count, owner, dropped, sealed = struct.unpack_from('<4I',data)
        if count > capacity or sealed not in (0,1):
            raise ValueError('Unknown backboard VM observation bounds')
        fields = 'sequence pid thread code pc lr address_low address_high length_low length_high protection flags fd position_low position_high argument_error error result_low result_high stage'.split()+['raw'+str(n) for n in range(7)]+['nargs']
        rows, unpublished = [], []
        for n in range(count):
            words = struct.unpack_from('<28I',data,(4+n*28)*4)
            if not words[0]:
                unpublished.append(n)
                continue
            if words[0] != n+1 or words[1] != owner or words[19] != 1:
                raise ValueError('Backboard VM observation ownership changed')
            rows.append(dict(zip(fields,words)))
        result[label] = dict(owner_pid=owner,count=count,dropped=dropped,sealed=sealed,
                             unpublished=unpublished,rows=rows)
    key = '_i9100_quartz_fault_payload'
    if key in symbols.values:
        data=kernel.read(symbols[key],(16+1024)*4)
        (out/'quartz-fault-payload.bin').write_bytes(data)
        fields='sequence pid task pc lr far object page bytes error version slide magic vtable object_offset type'.split()
        row=dict(zip(fields,struct.unpack_from('<16I',data)))
        if row['sequence']:
            if row['version']!=1 or row['bytes'] not in (0,4096) or row['object_offset']>4092:
                raise ValueError('Unknown QuartzCore fault payload layout')
            payload=data[64:64+row['bytes']]
            (out/'quartz-object-page.bin').write_bytes(payload)
            offset=row['object_offset']
            row.update(sha256=hashlib.sha256(payload).hexdigest(),
                       nonzero_bytes=sum(value!=0 for value in payload),
                       object_prefix_hex=payload[offset:offset+64].hex())
        result['quartz_fault']=row
    key = '_i9100_ios6_slab_payload'
    if key in symbols.values:
        data = kernel.read(symbols[key],2*(12+1024)*4)
        (out/'ios6-slab-payload.bin').write_bytes(data)
        fields = 'sequence pid task candidate link expected actual bytes error version slide role'.split()
        rows = []
        for n in range(2):
            at=n*(12+1024)*4
            row=dict(zip(fields,struct.unpack_from('<12I',data,at)))
            if not row['sequence']:continue
            if row['version']!=1 or row['role']!=n or row['bytes']>4096:
                raise ValueError('Unknown retained iOS6 slab payload layout')
            payload=data[at+48:at+48+row['bytes']]
            (out/f'slab-role-{n}-pid-{row["pid"]}.bin').write_bytes(payload)
            row.update(sha256=hashlib.sha256(payload).hexdigest(),
                       nonzero_bytes=sum(value!=0 for value in payload),prefix_hex=payload[:64].hex())
            if len(payload)>=20:
                row['magic_in_payload']=struct.unpack_from('<I',payload,16)[0]
            rows.append(row)
        result['slab_payload'] = dict(rows=rows)
    key='_i9100_small_ool_diag'
    if key in symbols.values:
        data=kernel.read(symbols[key],(1+32*80)*4);(out/'small-ool.bin').write_bytes(data)
        w=struct.unpack('<2561I',data);rows=[]
        fields='sequence pid stage copy type size address map current_map thread_map result copied error map_matches reserved0 reserved1'.split()
        for n in range(32):
            at=1+n*80
            if not w[at]:continue
            row=dict(zip(fields,w[at:at+16]))
            if row['copied']>256:raise ValueError('Invalid small OOL capture bound')
            row['hex']=data[(at+16)*4:(at+16)*4+row['copied']].hex();rows.append(row)
        result['small_ool']=dict(sequence=w[0],rows=sorted(rows,key=lambda r:r['sequence']))
    key = '_i9100_ls_publish_wire_diag'
    if key in symbols.values:
        data=kernel.read(symbols[key],(1+16*352)*4);(out/'ls-publish-wire.bin').write_bytes(data)
        w=struct.unpack('<5633I',data);rows=[]
        fields='sequence pid thread stage id wire_size length bits options status sender_pid sender_euid copyin_seen copyin_result send_seen send_result'.split()
        for n in range(16):
            at=1+n*352
            if not w[at]:continue
            row=dict(zip(fields,w[at:at+16]))
            if row['length']>1344:raise ValueError('Invalid LS publish capture length')
            row['hex']=data[(at+16)*4:(at+16)*4+row['length']].hex();rows.append(row)
        result['ls_publish_wire']=dict(sequence=w[0],rows=sorted(rows,key=lambda r:r['sequence']))
    key = '_i9100_surface_create_diag'
    if key in symbols.values:
        data = kernel.read(symbols[key], (1+8*268)*4)
        (out/'surface-create.bin').write_bytes(data)
        words = struct.unpack('<2145I', data)
        fields = 'sequence pid input_size result copied output_size output_capacity si so descriptors reserved stage'.split()
        rows = []
        for n in range(8):
            at = 1+n*268
            if not words[at] or words[at+11] != 1:
                continue
            row = dict(zip(fields, words[at:at+12]))
            if row['copied'] > 1024 or row['copied'] > row['input_size']:
                raise ValueError('Invalid surface create capture length')
            request = data[(at+12)*4:(at+12)*4+row['copied']]
            row['truncated'] = row['copied'] != row['input_size']
            row['request_hex'] = request.hex()
            row['xml'] = request.split(b'\0')[0].decode('utf-8', 'replace')
            rows.append(row)
        result['surface_create'] = dict(sequence=words[0], rows=sorted(rows,key=lambda r:r['sequence']))
    key='_i9100_aks_development_diag'
    if key in symbols.values:
        data=kernel.read(symbols[key],(1+32*12)*4);(out/'aks-development.bin').write_bytes(data)
        w=struct.unpack('<385I',data);fields='pid selector si so sti sto result value bag_id unconfined reserved stage'.split()
        if w[0]>32:raise ValueError('Invalid AKS development count')
        result['aks_development']=dict(count=w[0],rows=[dict(zip(fields,w[1+n*12:1+(n+1)*12])) for n in range(w[0])])
    key='_i9100_input_test'
    if key in symbols.values:
        data=kernel.read(symbols[key],64);(out/'input-test.bin').write_bytes(data)
        fields='enabled phase sequence x0 y0 x1 y1 ms enqueued reason last_x last_y touch_ready kind home_ready reserved'.split()
        result['input_test']=dict(zip(fields,struct.unpack('<16I',data)))
    key='_i9100_hid_copy_diag'
    if key in symbols.values:
        data=kernel.read(symbols[key],(1+16*30)*4);(out/'hid-copy.bin').write_bytes(data)
        w=struct.unpack('<481I',data);rows=[]
        if w[0]>16:raise ValueError('Invalid HID copy count')
        for n in range(w[0]):
            at=1+n*30;offset=at*4
            row=dict(zip(['pid','result','si','sti','so','sto'],w[at:at+6]))
            row['scalars']=list(struct.unpack_from('<2Q',data,offset+24))
            row['selector']=w[at+10];row['stage']=w[at+11]
            row['input_hex']=data[offset+48:offset+104].hex();row['output_hex']=data[offset+104:offset+120].hex()
            rows.append(row)
        result['hid_copy']=dict(count=w[0],rows=rows)
    for label,key,fields in [
        ('home','_i9100_home_observation','enabled down opened edges enqueued head tail'.split()),
        ('home_test','_i9100_home_test_diag','enabled phase physical_down effective_down done client_pid'.split()),
        ('touch','_i9100_touch_observation','ready init_result stage opened polls reports enqueued head tail errors'.split())]:
        if key in symbols.values:
            data=kernel.read(symbols[key],len(fields)*4);(out/(label+'.bin')).write_bytes(data)
            result[label]=dict(zip(fields,struct.unpack('<'+'I'*len(fields),data)))
    fields = ['sequence','pid','selector','result','si','sti','so','sto',
              'input_descriptor','output_descriptor','flags','output_capacity']
    for label in ('framebuffer_io','surface_io','other_io_error'):
        key = '_i9100_' + label + '_diag'
        if key not in symbols.values: continue
        data = kernel.read(symbols[key],(1+64*40)*4); (out/(label+'.bin')).write_bytes(data)
        words = struct.unpack('<2561I',data); rows = []
        for n in range(64):
            at = 1+n*40
            if not words[at]: continue
            row = dict(zip(fields,words[at:at+12])); offset = at*4
            row['class'] = data[offset+48:offset+80].split(b'\0')[0].decode('ascii','replace')
            row['scalars'] = list(struct.unpack_from('<3Q',data,offset+80))
            row['input_hex'] = data[offset+104:offset+136].hex()
            row['output_hex'] = data[offset+136:offset+160].hex(); rows.append(row)
        result[label] = dict(sequence=words[0],rows=sorted(rows,key=lambda r:r['sequence']))
    key = '_i9100_tcc_extension_diag'
    if key in symbols.values:
        data = kernel.read(symbols[key], (1+32*72)*4)
        (out/'tcc-extension.bin').write_bytes(data)
        words = struct.unpack('<2305I',data); rows = []
        fields = ['sequence','pid','original','result','type','flags','class_address',
                  'path_address','token_address','copy_error','enabled','providers',
                  'eligible','token_bytes','reserved','stage']
        for n in range(32):
            at = 1+n*72
            if not words[at]: continue
            row = dict(zip(fields,words[at:at+16])); offset = at*4
            row['class'] = data[offset+64:offset+160].split(b'\0')[0].decode('utf8','replace')
            row['path'] = data[offset+160:offset+288].split(b'\0')[0].decode('utf8','replace')
            rows.append(row)
        result['tcc_extensions'] = dict(sequence=words[0],rows=sorted(rows,key=lambda r:r['sequence']))
    key = '_i9100_amfi_output_diag'
    if key in symbols.values:
        data = kernel.read(symbols[key], (1 + 64 * 16) * 4)
        (out / 'amfi-output.bin').write_bytes(data)
        result['amfi_output'] = decode_table(data, 64, 16,
            ['pid', 'selector', 'si', 'so', 'sti', 'sto_before', 'descriptor_before',
             'flags', 'copied', 'result', 'sto_after', 'descriptor_after', 'token_pid',
             'blob_bytes', 'reserved', 'stage'])
    key = '_i9100_tcc_identity_diag'
    if key in symbols.values:
        data = kernel.read(symbols[key], (1 + 64 * 20) * 4)
        (out / 'tcc-identity.bin').write_bytes(data)
        result['tcc_identity'] = decode_table(data, 64, 20,
            ['pid', 'syscall', 'nargs'] + ['arg'+str(n) for n in range(7)] +
            ['error', 'result', 'pc', 'lr', 'fp', 'stage'] + ['entry_r'+str(n) for n in range(4)])
    key = '_i9100_ls_bootstrap_diag'
    if key in symbols.values:
        data = kernel.read(symbols[key], 32)
        (out / 'ls-bootstrap.bin').write_bytes(data)
        result['ls_bootstrap'] = dict(zip(['budgets', 'timeouts', 'replies', 'ready',
                                          'last_id', 'send_size', 'receive_size', 'options'],
                                         struct.unpack('<8I', data)))
    key = '_i9100_ls_store_reply_diag'
    if key in symbols.values:
        data = kernel.read(symbols[key], (1 + 16 * 8) * 4)
        (out / 'ls-store-reply.bin').write_bytes(data)
        result['ls_store_replies'] = decode_table(data, 16, 8,
            ['pid', 'native_size', 'user_size', 'type', 'bytes', 'initial_result', 'result', 'stage'])
    fields = ['sequence', 'pid', 'thread', 'stage', 'id', 'wire_size', 'length',
              'bits', 'options', 'status', 'sender_pid', 'sender_euid']
    for label, stride, cap in [('tcc-wire', 140, 512), ('ls-wire', 48, 144)]:
        key = '_i9100_' + label.replace('-', '_') + '_diag'
        if key not in symbols.values:
            continue
        size = (1 + 64 * stride) * 4
        data = b''.join(kernel.read(symbols[key] + start, min(32768, size - start))
                        for start in range(0, size, 32768))
        (out / (label + '.bin')).write_bytes(data)
        w = struct.unpack('<' + str(1 + 64 * stride) + 'I', data)
        rows = []
        for n in range(64):
            at = 1 + n * stride
            if not w[at]:
                continue
            row = dict(zip(fields, w[at:at + 12]))
            if row['length'] > cap:
                raise ValueError('Invalid service envelope prefix')
            offset = (at + 12) * 4
            row['hex'] = data[offset:offset + row['length']].hex()
            rows.append(row)
        result[label.replace('-', '_')] = dict(sequence=w[0], rows=sorted(rows, key=lambda r: r['sequence']))
    key='_i9100_ls_fault_payload'
    if key in symbols.values:
        data=kernel.read(symbols[key],(16+2048)*4);(out/'ls-fault-payload.bin').write_bytes(data)
        w=struct.unpack_from('<16I',data)
        fields='sequence pid task pc lr sp fp address size copied error truncated slide reserved0 reserved1 reserved2'.split()
        row=dict(zip(fields,w))
        if row['copied']>8192 or row['copied']>row['size']:raise ValueError('Invalid LS fault payload bound')
        payload=data[64:64+row['copied']];(out/'ls-plist-parser-input.bin').write_bytes(payload)
        row['prefix_hex']=payload[:128].hex();result['ls_fault_payload']=row
    key='_i9100_tcc_bootstrap_diag'
    if key in symbols.values:
        data=kernel.read(symbols[key],(1+32*72)*4);(out/'tcc-bootstrap.bin').write_bytes(data)
        w=struct.unpack('<2305I',data);rows=[]
        fields=['sequence','pid','thread','stage','id','length','bits','status']
        for n in range(32):
            if not w[1+n*72]:continue
            row=dict(zip(fields,w[1+n*72:9+n*72]));at=(1+n*72+8)*4
            if row['length']>256:raise ValueError('Invalid bootstrap prefix')
            row['hex']=data[at:at+row['length']].hex();rows.append(row)
        result['tcc_bootstrap']=dict(sequence=w[0],rows=sorted(rows,key=lambda r:r['sequence']))
    key='_i9100_shared_directory_added'
    if key in symbols.values:
        data=kernel.read(symbols[key],8);(out/'shared-directory-added.bin').write_bytes(data)
        result['shared_directory_added']=dict(zip(['SpringBoard','kbd'],struct.unpack('<2I',data)))
    for label,key in [('springboard_fault_stack','_i9100_springboard_fault_stack'),
                      ('keyboard_fault_stack','_i9100_keyboard_fault_stack'),
                      ('ls_fault_stack','_i9100_ls_fault_stack')]:
        if key in symbols.values:
            data=kernel.read(symbols[key],52*4);(out/(label+'.bin')).write_bytes(data)
            w=struct.unpack('<52I',data)
            if w[8]>14:raise ValueError('Invalid UI frame count')
            result[label]=dict(zip(['sequence','pid','task','type','pc','lr','sp','fp','count','error'],w[:10]))
            result[label]['frames']=[dict(zip(['fp','previous','lr'],w[10+n*3:13+n*3])) for n in range(w[8])]
    key='_i9100_addressbook_file_diag'
    if key in symbols.values:
        data=kernel.read(symbols[key],(1+64*44)*4);(out/'addressbook-files.bin').write_bytes(data)
        w=struct.unpack('<2817I',data);rows=[]
        for n in range(64):
            if not w[1+n*44]:continue
            row=dict(zip(['sequence','pid','syscall','error','result','flags','mode','copy_error'],w[1+n*44:9+n*44]))
            at=(1+n*44)*4;row['name']=data[at+32:at+48].split(b'\0')[0].decode('ascii','replace')
            row['path']=data[at+48:at+176].split(b'\0')[0].decode('utf8','replace');rows.append(row)
        result['addressbook_files']=dict(sequence=w[0],rows=sorted(rows,key=lambda r:r['sequence']))
    key='_i9100_ui_sandbox_diag'
    if key in symbols.values:
        data=kernel.read(symbols[key],(1+64*10)*4);(out/'ui-sandbox.bin').write_bytes(data)
        w=struct.unpack('<641I',data);rows=[]
        for n in range(64):
            if not w[1+n*10]:continue
            row=dict(zip(['sequence','pid','operation','error','providers'],w[1+n*10:6+n*10]))
            at=(1+n*10+5)*4;row['name']=data[at:at+16].split(b'\0')[0].decode('ascii','replace');rows.append(row)
        result['ui_sandbox']=dict(sequence=w[0],rows=sorted(rows,key=lambda r:r['sequence']))
    key='_i9100_vm_remap_diag'
    if key in symbols.values:
        data=kernel.read(symbols[key],(1+128*20)*4)
        (out/'vm-remap.bin').write_bytes(data)
        words=struct.unpack('<2561I',data);rows=[]
        if words[0]>128:raise ValueError('Invalid remap count')
        fields=['sequence','pid','api','target_map','source_map','before','after','size',
                'mask','flags','source_address','copy','inheritance','result','cur','max']
        for n in range(words[0]):
            row=dict(zip(fields,words[1+n*20:1+n*20+16]))
            offset=(1+n*20+16)*4
            row['name']=data[offset:offset+16].split(b'\0')[0].decode('ascii','replace')
            if row['sequence']:rows.append(row)
        result['vm_remap']=dict(count=words[0],rows=rows)
    key='_i9100_mach_failure_diag'
    if key in symbols.values:
        data=kernel.read(symbols[key],(1+64*6)*4)
        (out/'mach-failures.bin').write_bytes(data)
        table=decode_table(data,64,6,['pid','stage','address','size','options','result'])
        if any(row['stage'] not in (0,1,2) for row in table['rows']):
            raise ValueError('Unknown Mach failure stage')
        table['unpublished']=sum(row['stage']==0 for row in table['rows'])
        table['rows']=[row for row in table['rows'] if row['stage']]
        result['mach_failures']=table
    key='_i9100_mig_error_diag'
    if key in symbols.values:
        data=kernel.read(symbols[key],(1+128*6)*4)
        (out/'mig-errors.bin').write_bytes(data)
        result['mig_errors']=decode_table(data,128,6,['pid','id','retcode','size','bits','options'])
    key='_i9100_vm_error_diag'
    if key in symbols.values:
        data=kernel.read(symbols[key],(1+64*6)*4)
        (out/'vm-errors.bin').write_bytes(data)
        result['vm_errors']=decode_table(data,64,6,['pid','id','retcode','size','bits','options'])
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
    for label, key in [('abort', '_i9100_abort_observation'),
                       ('backboard_abort', '_i9100_backboard_abort_observation')]:
        if key not in symbols.values:
            continue
        frames = kernel.u32(symbols['_i9100_abort_frames']) if '_i9100_abort_frames' in symbols.values else 8
        if frames not in (8, 16):
            raise ValueError('Unknown retained abort frame layout')
        words = 15+frames
        data = kernel.read(symbols[key], words*4+244)
        (out/(label+'-observation.bin')).write_bytes(data)
        fields = ['sequence','pid','task','pc','lr','sp','fp','count','error'] + ['frame'+str(n) for n in range(frames)] + \
                 ['slab','slab_object','slab_expected','slab_actual','slab_status','text_kind']
        result[label] = dict(zip(fields,struct.unpack_from('<'+str(words)+'I',data)))
        if result[label]['count'] > frames:
            raise ValueError('Retained abort count exceeds its schema')
        result[label]['text'] = data[words*4:words*4+241].split(b'\0')[0].decode('utf-8','replace')
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
    for key in ('backboard_vm','slab_vm'):
        if key in result:
            preview[key]=dict(result[key],rows=result[key]['rows'][-6:])
    for key in ('render_transport','user_fault_details','vm_remap','tcc_wire','ls_wire','ls_publish_wire','ls_query','ls_query_alloc','ls_query_alloc_failure','framebuffer_io','surface_io','other_io_error'):
        if key in result:
            preview[key]=dict(count=len(result[key]['rows']),rows=result[key]['rows'][-8:])
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
    scope=parser.add_mutually_exclusive_group()
    scope.add_argument('--abort-only', action='store_true',
                        help='Read retained UI aborts, power and display state without unrelated service tables')
    scope.add_argument('--ls-only',action='store_true',
                        help='Read current LS query/reply and fault records without unrelated service tables')
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
                selected = LS_SYMBOLS if a.ls_only else ABORT_SYMBOLS | {key for key in symbols.values if key.endswith('leo_graphics_state')}
                observed_symbols = ObservationSymbols(symbols, selected) if a.abort_only or a.ls_only else symbols
                result['ui_observations'] = capture_ui_observations(kernel,observed_symbols,out)
                result['resources'] = {}
                for name in ('_maxproc', '_maxprocperuid', '_hard_maxproc', '_nprocs', '_vm_page_free_count'):
                    if name in symbols.values:
                        data = kernel.read(symbols[name], 4)
                        (out/(name.lstrip('_')+'.bin')).write_bytes(data)
                        result['resources'][name] = struct.unpack('<I', data)[0]
                print('resources', json.dumps(result['resources']), flush=True)
                if a.abort_only or a.ls_only:
                    if a.stacks:
                        names=('SpringBoard','lsd','installd') if a.ls_only else ('SpringBoard','backboardd')
                        for name in names:
                            _, data = session.command('threads '+name)
                            (out/(name+'-threads.txt')).write_bytes(data)
                    (out/'results.json').write_text(json.dumps(result, indent=2)+'\n')
                    record('DONE', observation='LS query/reply' if a.ls_only else 'retained UI aborts and power')
                    return
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
