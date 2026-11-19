#!/usr/bin/env python3
"""Decode retained native charging measurements on the existing CDC owner."""
import json, struct
from pathlib import Path

FIELDS=('sequence','polls','time_lo','time_hi','revision','sub_charger',
    'read_validity','reason','percent','millivolts','temperature_deci_c',
    'enabled','connected','charging','full','timeout','recharging',
    'charge_elapsed_seconds','current_raw','avg_current_raw','fuel_config',
    'fuel_misc_config','fuel_cgain','pmic_status4','mbcctrl1','mbcctrl2',
    'mbcctrl3','mbcctrl4','mbcctrl5','mbcctrl6','safeoutctrl',
    'muic_ctrl2','muic_status2','gpl2con','gpl2dat','gpl2pud',
    'charge_current_adc','probe_phase','probe_result','reserved')

CPU_FIELDS=('sequence','time_lo','time_hi','polls','api_valid','api_result',
    'returned_count','available_cpus','user_ticks','system_ticks','idle_ticks',
    'nice_ticks','tick_interval','precise_user_kernel_time','master_processor',
    'graphics_known','latest_graphics_client','graphics_send_calls',
    'graphics_send_success','latest_graphics_flags')
CLIENT_FIELDS=('sequence','time_lo','time_hi','requested_state','hardware_result',
    'client','owner_pid','vsync_requested','vsync_enabled','closed','port_present',
    'callback_present','generation_lo','generation_hi','send_count_lo','send_count_hi',
    'diag_enabled','reserved','graphics_diagnostic_losses','graphics_diagnostic_unknown')


def decode_budget(raw,kind):
    if kind not in ('cpu','display_clients') or len(raw)!=4*(4+16*20):
        raise ValueError('Power budget type/size differs')
    version,count,stride,capacity=struct.unpack_from('<4I',raw)
    if (version,stride,capacity)!=(1,20,16):raise ValueError('Unknown power budget schema')
    fields=CPU_FIELDS if kind=='cpu' else CLIENT_FIELDS
    samples=[]
    for slot in range(capacity):
        values=struct.unpack_from('<20I',raw,16+slot*80)
        if not values[0]:continue
        if not count or ((count-values[0])&0xffffffff)>=16 or ((values[0]-1)&15)!=slot:
            raise ValueError('Incomplete/foreign power budget record')
        row=dict(zip(fields,values))
        row['time_ns']=(row['time_hi']<<32)|row['time_lo']
        if kind=='cpu':
            if row['api_valid'] not in (0,1) or row['graphics_known'] not in (0,1) or row['precise_user_kernel_time'] not in (0,1):
                raise ValueError('Corrupt native accounting validity')
            if row['api_valid'] and (row['api_result'] or row['returned_count']!=4 or not row['tick_interval'] or
                    not row['master_processor'] or not 1<=row['available_cpus']<=32):
                raise ValueError('Native API success signature differs')
        else:
            row['generation']=(row['generation_hi']<<32)|row['generation_lo']
            row['send_count']=(row['send_count_hi']<<32)|row['send_count_lo']
        samples.append(row)
    samples.sort(key=lambda row:((count-row['sequence'])&0xffffffff),reverse=True)
    result=dict(version=version,count=count,samples=samples)
    if kind=='display_clients':
        result['identity_limit']='These are actual power-request callers; a caller snapshot does not prove ownership of every display client.'
        return result
    intervals=[]
    for before,after in zip(samples,samples[1:]):
        interval=dict(first_sequence=before['sequence'],last_sequence=after['sequence'],usable=False)
        elapsed=after['time_ns']-before['time_ns']
        same=all(after[key]==before[key] for key in ('master_processor','tick_interval','available_cpus','precise_user_kernel_time'))
        if not before['api_valid'] or not after['api_valid'] or not same or elapsed<=0 or elapsed>3600*1000000000:
            interval['reason']='Failed native sample, changed CPU/clock identity, or invalid time window'
        else:
            deltas={key:(after[key]-before[key])&0xffffffff for key in ('user_ticks','system_ticks','idle_ticks','nice_ticks')}
            total=sum(deltas.values());expected=elapsed/after['tick_interval']
            interval.update(elapsed_ns=elapsed,deltas=deltas,total_ticks=total,
                tick_coverage=total/expected if expected else None)
            # Reject stale/inconsistent timer data instead of reporting false idle.
            if total and abs(total-expected)<=max(4,expected*0.2):
                interval.update(usable=True,idle_percent=100*deltas['idle_ticks']/total,
                    busy_percent=100*(total-deltas['idle_ticks'])/total,
                    user_kernel_split_valid=bool(after['precise_user_kernel_time']))
            else:interval['reason']='Native CPU ticks do not cover the observed clock window'
            if before['graphics_known'] and after['graphics_known']:
                for key in ('graphics_send_calls','graphics_send_success'):
                    if before[key]!=0xffffffff and after[key]>=before[key] and after[key]!=0xffffffff:
                        interval[key+'_delta']=after[key]-before[key]
        intervals.append(interval)
    result.update(scope='Native master-CPU accounting; not aggregate load or a current measurement',intervals=intervals,
        graphics_counter_limit='Shared try-guard diagnostic counters can drop updates. A positive delta witnesses activity; zero does not prove refresh stopped. Latest client/flags are historical.')
    return result


def capture_budget(kernel,address,out,kind):
    raw=kernel.read(address,4*(4+16*20))
    (out/('power-budget-'+kind+'.bin')).write_bytes(raw)
    result=decode_budget(raw,kind)
    header=struct.unpack('<4I',kernel.read(address,16))
    if (header[0],header[2],header[3])!=(1,20,16):
        raise ValueError('Power budget schema changed during read; retained, not retried')
    result['producer_count_after']=header[1]
    (out/('power-budget-'+kind+'.json')).write_text(json.dumps(result,indent=2)+'\n')
    return result

def decode(raw):
    if len(raw)<16:raise ValueError('Native charger table size differs')
    version,count,stride,capacity=struct.unpack_from('<4I',raw)
    if capacity!=16 or (version,stride) not in ((1,36),(2,40)) or len(raw)!=4*(4+16*stride):
        raise ValueError('Unknown charger schema')
    samples=[]
    for n in range(16):
        values=struct.unpack_from('<'+str(stride)+'I',raw,16+n*stride*4)
        if not values[0]:continue
        if not count or ((count-values[0])&0xffffffff)>=16 or ((values[0]-1)&15)!=n:
            raise ValueError('Incomplete/foreign charger record')
        row=dict(zip(FIELDS,values))
        for key in ('reason','temperature_deci_c'):
            if row[key]&0x80000000:row[key]-=1<<32
        row['time_ns']=(row['time_hi']<<32)|row['time_lo']
        row['measurements_valid']=bool(row['read_validity']&0x80000000)
        row['current_calibration']='unverified; raw values do not prove milliamps'
        row['gpio_enable_level']=bool(row['gpl2dat']&4)
        row['gpio_pok_low']=not bool(row['gpl2dat']&32)
        row['gpio_chg_low']=not bool(row['gpl2dat']&16)
        samples.append(row)
    samples.sort(key=lambda x:x['sequence'])
    return dict(version=version,count=count,samples=samples,
        net_charging_verified=False,reason='Charge-state bits alone do not establish energy balance')

def capture(kernel,symbols,out):
    address=symbols['_i9100_charge_diag']
    before=kernel.read(address,16)
    version,_,stride,capacity=struct.unpack('<4I',before)
    if capacity!=16 or (version,stride) not in ((1,36),(2,40)):raise ValueError('Unknown charger schema')
    raw=kernel.read(address,4*(4+16*stride))
    (out/'charge-diag.bin').write_bytes(raw)
    result=decode(raw)
    (out/'charge-diag.json').write_text(json.dumps(result,indent=2)+'\n')
    if '_do_power_save' in symbols.values:
        result['do_power_save']=kernel.u32(symbols['_do_power_save'])
    if '_i9100_display_power_diag' in symbols.values:
        words=struct.unpack('<12I',kernel.read(symbols['_i9100_display_power_diag'],48))
        result['display_power']=dict(zip(('version','requests','requested_state','result',
            'winmap_before','winmap_after','blanked','saved_winmap','reserved0','reserved1','reserved2','reserved3'),words))
    if '_i9100_boot_source' in symbols.values:
        words=struct.unpack('<8I',kernel.read(symbols['_i9100_boot_source'],32))
        result['boot_source']=dict(zip(('magic','version','flags','inform2','inform3','sboot_mode','r1','r2'),words))
    if '_i9100_setup_dev_finish_diag' in symbols.values:
        finish_address=symbols['_i9100_setup_dev_finish_diag']
        words=struct.unpack('<12I',kernel.read(finish_address,48))
        result['setup_development_finish']=dict(zip(('version','state','pid','header','idversion',
            'reason','vm_result','copy_error','restore_error','restore_rx','site','target'),words))
        if words[0]==2:
            extra=struct.unpack('<4I',kernel.read(finish_address+48,16))
            result['setup_development_finish'].update(zip(('code','code_bytes','perform_selector_ref','finish_selector_ref'),extra))
    if '_i9100_power_key_observation' in symbols.values:
        words=struct.unpack('<7I',kernel.read(symbols['_i9100_power_key_observation'],28))
        result['power_key']=dict(zip(('enabled','down','opened','edges','enqueued','head','tail'),words))
    if '_i9100_irq_pc_sample' in symbols.values:
        raw_pc=kernel.read(symbols['_i9100_irq_pc_sample'],4*(7+64*4))
        (out/'irq-pc-sample.bin').write_bytes(raw_pc)
        version,sequence,samples,used,overflow,period,epoch=struct.unpack_from('<7I',raw_pc)
        if version!=2 or used>64 or period!=37 or samples>512:raise ValueError('Unknown PC histogram schema')
        table=dict(version=version,sequence=sequence,samples=samples,used=used,overflow=overflow,period=period,epoch=epoch,
            consistent=not sequence&1,limit='Up to 512 interrupted-PC samples in this epoch; not an exact causal profile or per-process accounting')
        if table['consistent']:
            rows=[]
            for n in range(used):
                page,pc,mode,count=struct.unpack_from('<4I',raw_pc,28+n*16)
                if pc&~255!=page or mode not in (16,18,19):raise ValueError('Malformed PC histogram bin')
                row=dict(page=hex(page),last_pc=hex(pc),mode=mode,count=count)
                if 0x80000000<=pc<=0xfffffff0:
                    nearest=max(((v,k) for k,v in symbols.values.items() if v<=pc),default=(0,'unknown'))
                    row.update(nearest_symbol=nearest[1],displacement=hex(pc-nearest[0]))
                rows.append(row)
            table['bins']=sorted(rows,key=lambda x:x['count'],reverse=True)
        result['irq_pc_sample']=table
    if '_i9100_idle_wait_diag' in symbols.values:
        raw_idle=kernel.read(symbols['_i9100_idle_wait_diag'],32)
        (out/'idle-wait.bin').write_bytes(raw_idle)
        words=struct.unpack('<8I',raw_idle)
        if words[0]!=1:raise ValueError('Unknown WFI timing schema')
        result['idle_wait']=dict(zip(('version','sequence','waits','ticks_low','ticks_high','last_ticks','maximum_ticks','reserved'),words))
        result['idle_wait'].update(consistent=not words[1]&1,
            limit='Masked WFI wall-time modulo one 32-bit MCT wrap per wait; not processor_info CPU attribution')
        if not words[1]&1:result['idle_wait']['wait_ns']=(((words[4]<<32)|words[3])*1000)//24
    for symbol,kind in (('_i9100_cpu_load_diag','cpu'),('_i9100_display_client_power_diag','display_clients')):
        if symbol in symbols.values:
            result[kind]=capture_budget(kernel,symbols[symbol],out,kind)
    header=kernel.read(address,16)
    after_version,after_count,after_stride,after_capacity=struct.unpack('<4I',header)
    if (after_version,after_stride,after_capacity)!=(version,stride,capacity):
        raise ValueError('Charge schema changed during read; retained, not retried')
    # Each read-memory response is an immutable kernel staging snapshot.
    # Later Power ticks may publish newer samples while ancillary snapshots
    # are read; that does not invalidate the already validated historical rows.
    result['producer_count_after']=after_count
    result['producer_advanced_after_snapshot']=after_count!=result['count']
    (out/'charge-diag.json').write_text(json.dumps(result,indent=2)+'\n')
    return result
