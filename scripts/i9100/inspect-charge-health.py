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
    if '_do_power_save' in symbols.values:
        result['do_power_save']=kernel.u32(symbols['_do_power_save'])
    header=kernel.read(address,16)
    if header!=raw[:16]:raise ValueError('Charge snapshot changed during read; retained, not retried')
    (out/'charge-diag.json').write_text(json.dumps(result,indent=2)+'\n')
    return result
