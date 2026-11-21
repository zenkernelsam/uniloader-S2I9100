#!/usr/bin/env python3
"""Decode retained native charging measurements on the existing CDC owner."""
import json, struct, importlib.util
from pathlib import Path

FIELDS=('sequence','polls','time_lo','time_hi','revision','sub_charger',
    'read_validity','reason','percent','millivolts','temperature_deci_c',
    'enabled','connected','charging','full','timeout','recharging',
    'charge_elapsed_seconds','current_raw','avg_current_raw','fuel_config',
    'fuel_misc_config','fuel_cgain','pmic_status4','mbcctrl1','mbcctrl2',
    'mbcctrl3','mbcctrl4','mbcctrl5','mbcctrl6','safeoutctrl',
    'muic_ctrl2','muic_status2','gpl2con','gpl2dat','gpl2pud',
    'charge_current_adc','probe_phase','probe_result','stop_uncertain')

CPU_FIELDS=('sequence','time_lo','time_hi','polls','api_valid','api_result',
    'returned_count','available_cpus','user_ticks','system_ticks','idle_ticks',
    'nice_ticks','tick_interval','precise_user_kernel_time','master_processor',
    'graphics_known','latest_graphics_client','graphics_send_calls',
    'graphics_send_success','latest_graphics_flags')
CLIENT_FIELDS=('sequence','time_lo','time_hi','requested_state','hardware_result',
    'client','owner_pid','vsync_requested','vsync_enabled','closed','port_present',
    'callback_present','generation_lo','generation_hi','send_count_lo','send_count_hi',
    'diag_enabled','vsync_paused','graphics_diagnostic_losses','graphics_diagnostic_unknown')
IDLE_FIELDS=('version','sequence','irq','waits','mct_low','mct_high','wait_low','wait_high','last','maximum',
    'frequency','map_ready')

CDC_FIELDS=('mode','in_poll','polls','interrupt_history','rx_status_count','rx_bytes','tx_arms',
    'in_busy','configured','host_open','reply_flight','reply_bytes','commands','gintsts','daint',
    'in_ctl','reconnects','last_tx_age_seconds','out_ctl','out_size','out_rearms','control_started',
    'init_attempts','init_gate','out_arms','reset_errors','timebase_ready')

def decode_cdc_liveness(raw,header_after=None):
    if len(raw)!=140:raise ValueError('CDC liveness snapshot size differs')
    words=struct.unpack('<35I',raw)
    if (words[0],words[2])!=(1,27) or words[5]&~0x1f1f:
        raise ValueError('Unknown CDC liveness schema/reason')
    value=dict(version=words[0],sequence=words[1],emitted=words[3],suppressed=words[4],
        last_reason=words[5]&255,faults=words[5]>>8,time_ns=(words[7]<<32)|words[6],
        consistent=not bool(words[1]&1),stats=dict(zip(CDC_FIELDS,words[8:])))
    if header_after is not None:
        if len(header_after)!=8:raise ValueError('CDC liveness publication header size differs')
        value['publication_rechecked']=True
        value['consistent']=value['consistent'] and struct.unpack('<2I',header_after)==words[:2]
    value['limit']='Complete Power-workloop USB snapshot and log decisions; no opener, wire token, phone energy or physical display measurement'
    return value

def decode_charge_adopt(raw):
    if len(raw) not in (48,64):raise ValueError('Charge deadline adoption size differs')
    words=struct.unpack('<'+str(len(raw)//4)+'I',raw)
    version=words[0];publication=11 if version==1 else 15
    if (version,len(raw)) not in ((1,48),(2,64)) or words[1]>4 or any(words[n]>1 for n in (5,6,7,10,publication)):
        raise ValueError('Unknown charge deadline adoption schema')
    fields=('version','state','revision','start_low','start_high','full','timeout','recharging',
        'time_low','time_high','enabled_after_init')
    fields+=('published',) if version==1 else ('elapsed_base_low','elapsed_base_high','reserved0','reserved1','published')
    value=dict(zip(fields,words));value['consistent']=bool(words[publication])
    value['limit']='Initial Power-owner deadline adoption; current charging and energy balance still require fresh measurements'
    if not value['consistent']:return value
    start=(words[4]<<32)|words[3];now=(words[9]<<32)|words[8]
    if words[2]>15 or words[10] or not now or (start and start>now):
        raise ValueError('Malformed initial charge deadline state')
    if words[1] in (3,4) and not words[6]:raise ValueError('Rejected/expired handoff did not retain timeout stop')
    if words[1]==1 and not words[5] and not start:raise ValueError('Inherited charging deadline is absent')
    elapsed_base=0 if version==1 else (words[12]<<32)|words[11]
    value.update(charge_start_ns=start,observed_ns=now,elapsed_base_ns=elapsed_base,deadline_seconds=5400 if words[7] else 18000)
    if start:value['elapsed_ns']=elapsed_base+now-start
    return value

def decode_idle_paired(raw,header_after=None):
    if len(raw)!=48:raise ValueError('Paired WFI size differs')
    words=struct.unpack('<12I',raw)
    if words[0] not in (0,1) or (words[0]==1 and (words[10]!=24000000 or words[11]>1)):
        raise ValueError('Unknown paired WFI schema')
    paired=dict(zip(IDLE_FIELDS,words))
    paired['consistent']=words[0]==1 and not words[1]&1 and words[11]==1
    if header_after is not None:
        if len(header_after)!=8:raise ValueError('Paired WFI publication header size differs')
        version,sequence=struct.unpack('<2I',header_after)
        paired['producer_version_after']=version;paired['producer_sequence_after']=sequence
        paired['consistent']=paired['consistent'] and (version,sequence)==words[:2]
        paired['publication_rechecked']=True
    if paired['consistent']:
        paired['mct_ticks']=(words[5]<<32)|words[4];paired['wait_ticks']=(words[7]<<32)|words[6]
    paired['limit']='Same-IRQ MCT and completed WFI waits; interval interpretation requires two qualified observations'
    return paired

def idle_interval(before,after):
    result=dict(usable=False,measurement='Measured WFI wait fraction; not processor_info idle percent')
    if not before.get('consistent') or not after.get('consistent'):
        result['reason']='Missing, inactive or partial paired sample';return result
    if before['frequency']!=after['frequency'] or before['frequency']!=24000000:
        result['reason']='MCT frequency changed';return result
    elapsed=after['mct_ticks']-before['mct_ticks'];wait=after['wait_ticks']-before['wait_ticks']
    irq=(after['irq']-before['irq'])&0xffffffff;waits=(after['waits']-before['waits'])&0xffffffff
    if elapsed<=0 or elapsed>before['frequency']*3600 or wait<0 or wait>elapsed or not 0<irq<0x80000000 or waits>=0x80000000:
        result['reason']='Clock/cumulative waits/IRQ counters reset or do not cover one valid interval';return result
    result.update(usable=True,elapsed_ticks=elapsed,wait_ticks=wait,irq_count=irq,wait_count=waits,
        elapsed_ns=(elapsed*1000)//24,wait_ns=(wait*1000)//24,wfi_wait_percent=100*wait/elapsed)
    return result

def decode_vsync_power(raw,header_after=None):
    if len(raw)!=64:raise ValueError('Display Vsync power snapshot size differs')
    words=struct.unpack('<16I',raw)
    fields=('version','sequence','requests','requested_state','hardware_result','domain_paused',
        'clients','paused_clients','enabled_clients','requested_clients','closed_clients',
        'timer_errors','request_pid','faulted_clients','reserved0','reserved1')
    if words[0]!=1 or words[3]>2 or words[5]>1 or any(words[n]>words[6] for n in (7,8,9,10,13)):
        raise ValueError('Malformed display Vsync power snapshot')
    result=dict(zip(fields,words));result['consistent']=not words[1]&1
    if header_after is not None:
        if len(header_after)!=8:raise ValueError('Display Vsync publication header size differs')
        version,sequence=struct.unpack('<2I',header_after)
        result.update(producer_version_after=version,producer_sequence_after=sequence)
        result['consistent']=result['consistent'] and (version,sequence)==words[:2]
    result['limit']='Whole physical display domain at the last power request; not measured refresh or electrical suspend'
    return result

def decode_panel_sleep(raw,header_after=None):
    if len(raw) not in (64,80):raise ValueError('Panel sleep snapshot size differs')
    words=struct.unpack('<'+str(len(raw)//4)+'I',raw)
    if (words[0],len(raw)) not in ((1,64),(2,80)):raise ValueError('Unknown panel sleep snapshot schema')
    fields=('version','sequence','enabled','qualified','stage','error','cleanup_error','mode',
        'commands','requests','saved_scanout','owned_scanout','id0','id1','id2','identity_reads')
    if words[0]==2:fields+=('recovery_attempts','recovery_commands','current_scanout','reserved')
    if words[2]>1 or words[3]>1 or words[4]>4 or words[7]>255 or words[15]&~0x7f or any(words[n]>255 for n in (12,13,14)):
        raise ValueError('Malformed panel sleep snapshot')
    if words[0]==2 and (words[16]>1 or words[17]>2 or words[17] and not words[16]):
        raise ValueError('Malformed panel recovery budget')
    result=dict(zip(fields,words));result['consistent']=not words[1]&1
    if header_after is not None:
        if len(header_after)!=8:raise ValueError('Panel publication header size differs')
        version,sequence=struct.unpack('<2I',header_after)
        result.update(producer_version_after=version,producer_sequence_after=sequence)
        result['consistent']=result['consistent'] and (version,sequence)==words[:2]
    result['limit']='Actual panel-mode/scanout owner path; electrical power savings require separate measurements'
    result['identity_read_limit']='Bits0..2 first ID reads, bits3..5 second ID reads, bit6 unstable mismatch; zero may be a legacy producer'
    return result


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
            if row['vsync_paused']>1:raise ValueError('Malformed display client paused state')
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
    if capacity!=16 or (version,stride) not in ((1,36),(2,40),(3,40)) or len(raw)!=4*(4+16*stride):
        raise ValueError('Unknown charger schema')
    samples=[]
    for n in range(16):
        values=struct.unpack_from('<'+str(stride)+'I',raw,16+n*stride*4)
        if not values[0]:continue
        if not count or ((count-values[0])&0xffffffff)>=16 or ((values[0]-1)&15)!=n:
            raise ValueError('Incomplete/foreign charger record')
        row=dict(zip(FIELDS,values))
        if version<3:
            row['reserved']=row.pop('stop_uncertain',0)
            row['stop_confirmation_available']=False
        else:
            if row['stop_uncertain']>1:raise ValueError('Unknown charger stop-confirmation state')
            row['stop_confirmation_available']=True
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

def decode_low_battery_retreat(raw,header_after=None):
    if len(raw)!=72:raise ValueError('Low-battery publication size differs')
    words=struct.unpack('<18I',raw)
    if words[0]==1 and not any(words[1:]):
        return dict(version=1,initialized=False,consistent=False,
            limit='Power has not published its low-battery reserve state')
    if (words[0],words[14],words[15],words[16],words[17])!=(1,3,3400,5,4) or words[2]>1 or words[3]>4 or words[4]>5 or words[5]>1 or words[6]>100 or words[7]>4300:
        raise ValueError('Low-battery publication schema/state differs')
    first=(words[9]<<32)|words[8];last=(words[11]<<32)|words[10];submitted=(words[13]<<32)|words[12]
    if words[5] and (words[4]!=5 or not first or last<first or last-first<4000000000):
        raise ValueError('Low-battery admission did not span its actual time window')
    if submitted and (not words[2] or not words[5] or submitted<last or words[6]>3 or not 2500<=words[7]<=3400):
        raise ValueError('Low-battery submission lacks its qualified trigger measurements')
    value=dict(version=words[0],sequence=words[1],enabled=bool(words[2]),request_state=words[3],
        samples=words[4],admitted=bool(words[5]),percent=words[6],millivolts=words[7],
        first_ns=first,last_ns=last,submitted_ns=submitted,initialized=True,consistent=not words[1]&1,
        limit='One normal-halt request from qualified low voltage and SOC; no successful shutdown or net charging inferred')
    if header_after is not None:
        if len(header_after)!=8:raise ValueError('Low-battery publication header size differs')
        version,sequence=struct.unpack('<2I',header_after)
        value['consistent']=value['consistent'] and (version,sequence)==words[:2]
    return value

def capture(kernel,symbols,out):
    address=symbols['_i9100_charge_diag']
    before=kernel.read(address,16)
    version,_,stride,capacity=struct.unpack('<4I',before)
    if capacity!=16 or (version,stride) not in ((1,36),(2,40),(3,40)):raise ValueError('Unknown charger schema')
    raw=kernel.read(address,4*(4+16*stride))
    (out/'charge-diag.bin').write_bytes(raw)
    result=decode(raw)
    (out/'charge-diag.json').write_text(json.dumps(result,indent=2)+'\n')
    if '_i9100_cdc_liveness_diag' in symbols.values:
        cdc_address=symbols['_i9100_cdc_liveness_diag']
        cdc=kernel.read(cdc_address,140);cdc_after=kernel.read(cdc_address,8)
        (out/'cdc-liveness.bin').write_bytes(cdc)
        (out/'cdc-liveness-after.bin').write_bytes(cdc_after)
        result['cdc_liveness']=decode_cdc_liveness(cdc,cdc_after)
    if '_do_power_save' in symbols.values:
        result['do_power_save']=kernel.u32(symbols['_do_power_save'])
    if '_i9100_power_stop_uncertain' in symbols.values:
        uncertain=kernel.u32(symbols['_i9100_power_stop_uncertain'])
        if uncertain>1:raise ValueError('Unknown live stop-confirmation state')
        valid=kernel.u32(symbols['_i9100_power_valid'])
        if valid>1:raise ValueError('Unknown live Power measurement validity')
        result['stop_confirmation']=dict(uncertain=bool(uncertain),measurement_valid=bool(valid),
            limit='Last Power policy disable/readback and live measurement validity; timer failure clears validity; ADC/current still require separate evidence')
    if '_i9100_low_battery_retreat_diag' in symbols.values:
        address_low=symbols['_i9100_low_battery_retreat_diag']
        low=kernel.read(address_low,72);low_after=kernel.read(address_low,8)
        (out/'low-battery-retreat.bin').write_bytes(low)
        (out/'low-battery-retreat-after.bin').write_bytes(low_after)
        result['low_battery_retreat']=decode_low_battery_retreat(low,low_after)
    if '_i9100_display_power_diag' in symbols.values:
        words=struct.unpack('<12I',kernel.read(symbols['_i9100_display_power_diag'],48))
        result['display_power']=dict(zip(('version','requests','requested_state','result',
            'winmap_before','winmap_after','blanked','saved_winmap','reserved0','reserved1','reserved2','reserved3'),words))
    if '_i9100_boot_source' in symbols.values:
        words=struct.unpack('<8I',kernel.read(symbols['_i9100_boot_source'],32))
        result['boot_source']=dict(zip(('magic','version','flags','inform2','inform3','sboot_mode','r1','r2'),words))
    spec=importlib.util.spec_from_file_location('charge_takeover',Path(__file__).with_name('charge-handoff.py'))
    handoff=importlib.util.module_from_spec(spec);spec.loader.exec_module(handoff)
    observed=handoff.capture(kernel,symbols,out)
    if observed is not None:
        result['charger_handoff']=observed
        result['charger_takeover_observation']=handoff.first_kernel_sample(observed,result['samples'])
    if '_i9100_charge_epoch_live' in symbols.values:
        epoch_address=symbols['_i9100_charge_epoch_live']
        epoch=kernel.read(epoch_address,128);epoch_after=kernel.read(epoch_address,128)
        (out/'charge-epoch-live.bin').write_bytes(epoch)
        (out/'charge-epoch-live-after.bin').write_bytes(epoch_after)
        try:
            source=handoff.decode_epoch(epoch,0)
            latest=handoff.decode_epoch(epoch_after,0)
        except ValueError as error:
            result['shutdown_epoch_source']=dict(valid=False,error=str(error))
        else:
            result['shutdown_epoch_source']=dict(valid=True,source=source,after=latest,
                stable=epoch==epoch_after,limit='Two retained complete publications, no retry; only sealed next-boot evidence proves shutdown inheritance')
    if '_i9100_rtc_read_diag' in symbols.values:
        rtc_address=symbols['_i9100_rtc_read_diag'];rtc=kernel.read(rtc_address,48)
        rtc_after=kernel.read(rtc_address,8)
        (out/'rtc-read.bin').write_bytes(rtc);(out/'rtc-read-after.bin').write_bytes(rtc_after)
        words=struct.unpack('<12I',rtc)
        value=dict(zip(('version','sequence','read_mask','controls','first_low','first_high',
                        'last_low','last_high','status','seconds_low','seconds_high','reserved'),words))
        if value['version']!=1 or value['status']>9 or value['read_mask']>15 or value['reserved']:
            raise ValueError('Unknown RTC raw observation')
        value['consistent']=not value['sequence']&1 and struct.unpack('<2I',rtc_after)==words[:2]
        value['seconds']=(value['seconds_high']<<32)|value['seconds_low']
        value['raw_format']=('BCD24' if value['controls']&3==3 else 'binary24' if value['controls']&3==2 else 'unsupported')
        value['limit']='Raw read transaction only; zero/failed RTC is not a proven clock or a fresh charging deadline'
        result['rtc_read']=value
    if '_i9100_charge_adopt_diag' in symbols.values:
        adopt_address=symbols['_i9100_charge_adopt_diag']
        adopt_version=kernel.u32(adopt_address)
        if adopt_version not in (1,2):raise ValueError('Unknown charge adoption producer')
        adopted=kernel.read(adopt_address,48 if adopt_version==1 else 64)
        (out/'charge-adopt.bin').write_bytes(adopted)
        result['charger_deadline_adoption']=decode_charge_adopt(adopted)
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
        pc_version,sequence,samples,used,overflow,period,epoch=struct.unpack_from('<7I',raw_pc)
        if pc_version!=2 or used>64 or period!=37 or samples>512:raise ValueError('Unknown PC histogram schema')
        table=dict(version=pc_version,sequence=sequence,samples=samples,used=used,overflow=overflow,period=period,epoch=epoch,
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
    if '_i9100_idle_observation' in symbols.values:
        paired_address=symbols['_i9100_idle_observation']
        raw_paired=kernel.read(paired_address,48)
        (out/'idle-paired.bin').write_bytes(raw_paired)
        # A virtual read may span physical pages and therefore two USB
        # snapshots. Qualify that original read; a changed publisher is
        # retained as partial instead of re-reading until it looks stable.
        after_paired=kernel.read(paired_address,8)
        (out/'idle-paired-after.bin').write_bytes(after_paired)
        result['idle_paired']=decode_idle_paired(raw_paired,after_paired)
    if '_i9100_display_vsync_power_diag' in symbols.values:
        address_vsync=symbols['_i9100_display_vsync_power_diag']
        raw_vsync=kernel.read(address_vsync,64);after_vsync=kernel.read(address_vsync,8)
        (out/'display-vsync-power.bin').write_bytes(raw_vsync)
        (out/'display-vsync-power-after.bin').write_bytes(after_vsync)
        result['display_vsync_power']=decode_vsync_power(raw_vsync,after_vsync)
    if '_i9100_panel_sleep_diag' in symbols.values:
        address_panel=symbols['_i9100_panel_sleep_diag']
        panel_version=struct.unpack('<I',kernel.read(address_panel,4))[0]
        if panel_version not in (1,2):raise ValueError('Unknown panel sleep producer schema')
        raw_panel=kernel.read(address_panel,64 if panel_version==1 else 80);after_panel=kernel.read(address_panel,8)
        (out/'panel-sleep.bin').write_bytes(raw_panel);(out/'panel-sleep-after.bin').write_bytes(after_panel)
        result['panel_sleep']=decode_panel_sleep(raw_panel,after_panel)
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
