"""Decode same-group charger ADC/register evidence; no device access or mA claim."""
import re


def decode(block, sample):
    records = {}
    for tag in ('I9CS1', 'I9RG1'):
        rows = re.findall(rb'^'+tag.encode()+rb' ((?:[0-9a-f]{8} ){7}[0-9a-f]{8})\r?\n',
                          block, re.MULTILINE)
        if len(rows) != 1:
            raise ValueError('Exactly one complete '+tag+' must follow its timed charger sample')
        records[tag] = [int(value, 16) for value in rows[0].split()]
    timing, registers = records['I9CS1'], records['I9RG1']
    if timing[0] != sample['sequence'] or registers[0] != timing[0]:
        raise ValueError('ADC/register sample identity differs from its timed charger group')
    started_ms = (timing[2] << 32) | timing[1]
    duration_us, mask = timing[3:5]
    if not started_ms or duration_us > 500000 or mask & ~0x3ff:
        raise ValueError('ADC/register clock or validity mask is unqualified')
    if not 0 <= sample['measured_ms']-started_ms <= 502:
        raise ValueError('ADC/register evidence is stale or later than its timed charger sample')
    if duration_us > (sample['measured_ms']-started_ms+1)*1000:
        raise ValueError('ADC/register duration extends beyond its timed charger sample')
    adc, enabled, uncertain = timing[5:]
    if enabled > 1 or uncertain > 1 or (mask & 1 and adc > 4095) or (not mask & 1 and adc != 0xffffffff):
        raise ValueError('Invalid ADC or charger control state')
    vcell, soc, charger, muic = registers[1:5]
    if vcell > 0xffff or soc > 0xffff or charger > 0xffff or muic & 0xfe000000:
        raise ValueError('Native charger register width or reserved bits differ')
    revision, sub = (muic >> 16) & 255, (muic >> 24) & 1
    if revision > 15 or sub != int(8 <= revision <= 15):
        raise ValueError('Native charger controller differs from its board revision')
    names = ('vcell_raw', 'soc_vf_raw', 'pmic_status4', 'pmic_mbcctrl2',
             'muic_ctrl2', 'muic_status2', 'gpl2con', 'gpl2dat', 'gpl2pud')
    values = (vcell, soc, charger & 255, (charger >> 8) & 255,
              muic & 255, (muic >> 8) & 255, *registers[5:])
    value_masks = (2, 4, 8, 16, 32, 64, 128, 256, 512)
    decoded = {name: value if mask & bit else None for name, value, bit in zip(names, values, value_masks)}
    result = dict(sequence=timing[0], started_ms=started_ms, duration_us=duration_us,
        mask=mask, charge_current_adc=adc if mask & 1 else None,
        enabled=bool(enabled), stop_uncertain=bool(uncertain), revision=revision,
        sub_charger=bool(sub), registers=decoded,
        observed_millivolts=vcell*625//8000 if mask & 2 else None,
        observed_soc=min(100, soc//256) if mask & 4 else None,
        net_charging_verified=False,
        limit='Raw ADC1 and charger/gauge readback at a bounded device time; no calibrated milliamps or net energy inferred')
    if (mask & 0x380) == 0x380 and sub:
        con, pins = registers[5:7]
        result['sub_enable_output'] = bool(pins & 4) if (con >> 8) & 15 == 1 else None
        result['sub_connected_pin'] = not bool(pins & 32) if not con & (15 << 20) else None
        result['sub_charging_pin'] = not bool(pins & 16) if not con & (15 << 16) else None
    if mask & 16:
        result['main_charger_enable_bits'] = (charger >> 8) & 0xc0
    issues = []
    if mask & 2 and (vcell == 0xffff or not 2500 <= result['observed_millivolts'] <= 4300):
        issues.append('VCELL readback outside qualified battery range')
    if mask & 4 and soc > 105*256:
        issues.append('SOC_VF readback outside qualified gauge range')
    if mask & 2 and abs(result['observed_millivolts']-sample['millivolts']) > 80:
        issues.append('VCELL changed more than 80mV across the bounded status/sense sample')
    if mask & 4 and abs(result['observed_soc']-sample['soc']) > 2:
        issues.append('SOC_VF differs by more than 2 percentage points from status')
    if mask & 8 and decoded['pmic_status4'] == 255:
        issues.append('PMIC STATUS4 readback is all ones')
    if sub and (mask & 0x390) == 0x390:
        if result['main_charger_enable_bits'] != 0:
            issues.append('Both charger controllers may be enabled on the sub-charger board')
        if result.get('sub_enable_output') is None or result['sub_enable_output'] != bool(enabled):
            issues.append('Selected charger enable pin/mux differs from its policy state')
        if result.get('sub_connected_pin') is None or result.get('sub_charging_pin') is None:
            issues.append('Selected charger status pins are not qualified inputs')
        elif bool(sample['charging']) != (result['sub_connected_pin'] and result['sub_charging_pin']):
            issues.append('Selected charger status pins differ from the timed charging state')
    elif not sub and mask & 16 and result['main_charger_enable_bits'] != (0xc0 if enabled else 0):
        issues.append('Main charger enable bits differ from its policy state')
    result['readback_issues'] = issues
    result['readback_consistent'] = not issues
    return result


def grouped(raw, timed):
    groups = []
    for index, sample in enumerate(timed):
        end = timed[index+1]['end_offset'] if index+1 < len(timed) else len(raw)
        block = raw[sample['end_offset']:end]
        if not re.search(rb'^I9(?:CS|RG)1(?: |$)', block, re.MULTILINE):
            groups.append(dict(sequence=sample['sequence'], available=False,
                               error='ADC/register evidence absent from this legacy or dropped group'))
            continue
        try:
            result = decode(block, sample)
        except ValueError as error:
            groups.append(dict(sequence=sample['sequence'], available=False, error=str(error)))
        else:
            groups.append(dict(result, available=True))
    return groups
