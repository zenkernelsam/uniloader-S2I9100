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
