#!/usr/bin/env python3
"""Verify actual linked Mach-O internal-root definitions and paired compile provenance."""
import argparse
import hashlib
import json
from pathlib import Path
import re
import struct
ROOT=Path(__file__).resolve().parents[3];XNU=ROOT/'xnu-S2I9100'
def sha(path):return hashlib.sha256(Path(path).read_bytes()).hexdigest()
def definitions(raw):
    if len(raw)<28 or struct.unpack_from('<I',raw)[0]!=0xfeedface:raise ValueError('Require ARM32 Mach-O kernel')
    count,total=struct.unpack_from('<II',raw,16);at=28;symtabs=[]
    if count>128 or at+total>len(raw):raise ValueError('Invalid Mach-O load commands')
    for _ in range(count):
        cmd,size=struct.unpack_from('<II',raw,at)
        if size<8 or at+size>28+total:raise ValueError('Invalid Mach-O load command length')
        if cmd==2:
            if size!=24:raise ValueError('Invalid LC_SYMTAB')
            symtabs.append(struct.unpack_from('<4I',raw,at+8))
        at+=size
    if at!=28+total or len(symtabs)!=1:raise ValueError('Require exact kernel symtab')
    symoff,nsyms,stroff,strsize=symtabs[0]
    if nsyms>200000 or symoff+nsyms*12>len(raw) or stroff+strsize>len(raw):raise ValueError('Truncated symbols')
    names={}
    for i in range(nsyms):
        index,kind,section,desc,value=struct.unpack_from('<IBBHI',raw,symoff+i*12)
        if kind&0xe0 or (kind&0xe)!=0xe or not section:continue # non-STAB real N_SECT definitions
        if index>=strsize:raise ValueError('Symbol string out of range')
        end=raw.find(b'\0',stroff+index,stroff+strsize)
        if end<0:raise ValueError('Unterminated Mach-O symbol')
        name=raw[stroff+index:end].decode('ascii')
        if name in names and names[name]!=value:
            if name in ('_i9100_emmc_boot_decode','_i9100_emmc_boot_match','_i9100_emmc_native_seal_data',
                        '_i9100_hfs_data_bootstrap','_i9100_storage_shutdown_diag','_i9100_emmc_alias_devices',
                        '_i9100_emmc_clock_capture','_i9100_emmc_clock_rate','_i9100_emmc_clock_observation',
                        '_i9100_emmc_clock_observation_diag','_i9100_emmc_clock_observe_open') or name.startswith(('__Z20i9100_emmc_boot_open','__Z28ios6i9100_register_emmc_boot')):
                raise ValueError('Ambiguous internal boot definition')
            continue # unrelated static functions legitimately share local names
        names[name]=value
    return names
def verify(kernel):
    kernel=Path(kernel).resolve()
    if not kernel.is_relative_to(XNU/'out'):raise ValueError('Require retained project kernel')
    raw=kernel.read_bytes();required=('_i9100_emmc_boot_decode','_i9100_emmc_boot_match','_i9100_emmc_native_seal_data',
       '_i9100_hfs_data_bootstrap','_i9100_storage_shutdown_diag','_i9100_emmc_alias_devices',
       '_i9100_emmc_clock_capture','_i9100_emmc_clock_rate','_i9100_emmc_clock_observe_open',
       '_i9100_emmc_clock_observation','_i9100_emmc_clock_observation_diag')
    symbols=definitions(raw)
    if any(name not in symbols for name in required):raise ValueError('Missing actual native/HFS/checked-shutdown definitions')
    # C++ boot owner symbols use real Itanium name mangling; enforce uniquely
    # defined signatures instead of searching text strings in flat payloads.
    cpp={}
    for stem in ('i9100_emmc_boot_open','ios6i9100_register_emmc_boot'):
        matches={name:value for name,value in symbols.items() if name.startswith('__Z'+str(len(stem))+stem)}
        if len(matches)!=1:raise ValueError('Missing/ambiguous real C++ boot definition: '+stem)
        cpp.update(matches)
    folder=kernel.parent;manifest=json.loads((folder/'manifest.json').read_text())
    if manifest.get('result')!='PASS' or manifest.get('complete_kernel_link')is not True or manifest.get('linked_kernel_sha256')!=sha(kernel):
        raise ValueError('Internal-root package requires verified full source provenance')
    proofs={};needed={'AppleARMPE.cpp','vfs_syscalls.c','hfs_vfsops.c','bsd_init.c','kern_shutdown.c','i9100_usbcdc.c',
       'IOS6I9100EMMCBlockDriver.cpp','IOS6I9100EMMCRaw.cpp','IOS6I9100EMMCStorage.cpp','i9100_emmc_publication.cpp',
       'i9100_emmc_alias.cpp','i9100_emmc_boot.cpp','i9100_emmc_boot_contract.c','i9100_emmc_clock.c','i9100_emmc_clock_native.cpp','i9100_emmc_native.cpp'}
    cursor=folder;seen=set()
    for _ in range(32):
        if cursor in seen:raise ValueError('Cyclic kernel source ancestry')
        seen.add(cursor);record=json.loads((cursor/'manifest.json').read_text())
        for item in json.loads((cursor/'compile-commands.json').read_text()):
            if item['source'] in needed and item['source'] not in proofs:proofs[item['source']]=item
        if needed.issubset(proofs):break
        if not record.get('base'):break
        cursor=(ROOT/record['base']).resolve()
        if not cursor.is_relative_to(XNU/'out'):raise ValueError('Source proof escaped project')
    if not needed.issubset(proofs):raise ValueError('Missing paired PE/BSD/HFS/USB compile provenance')
    files=(folder/'link.filelist').read_text().splitlines()
    for name,item in proofs.items():
        source=(ROOT/item['source_file']).resolve();compiled=(ROOT/item['object']).resolve()
        if not source.is_relative_to(XNU) or sha(source)!=item['source_sha256'] or not compiled.is_relative_to(XNU/'out'):
            raise ValueError('Paired compiler source drift')
        if item.get('module_header') and sha(ROOT/item['module_header'])!=item['module_header_sha256']:
            raise ValueError('Paired native storage header drift')
        if any(arg=='-DI9100_HFS_FROZEN_REFERENCE=1' for arg in item['arguments']):
            raise ValueError('Historical LPM-disabled offline fixture cannot become a deployment kernel')
        suffix=(name+('.cpo' if name.endswith('.cpp') else '.o'),Path(name).stem+('.cpo' if name.endswith('.cpp') else '.o'))
        matches=[Path(path) for path in files if re.sub(r'^(?:[0-9]{4}-)+','',Path(path).name) in suffix]
        if len(matches)!=1 or sha(matches[0])!=sha(compiled):raise ValueError('Compiled paired object absent from final link')
    if 'ios6i9100_register_emmc_boot(this)' not in (ROOT/proofs['AppleARMPE.cpp']['source_file']).read_text():raise ValueError('PE entry unconnected')
    if 'ios6i9100_register_emmc_clock_observation();' not in (ROOT/proofs['AppleARMPE.cpp']['source_file']).read_text():
        raise ValueError('Read-only clock observer PE entry unconnected')
    if 'i9100_hfs_data_bootstrap();' not in (ROOT/proofs['bsd_init.c']['source_file']).read_text():raise ValueError('Prelaunchd mount unconnected')
    for name,anchor in (('IOS6I9100EMMCBlockDriver.cpp','IOS6I9100EMMCMedia::matchPropertyTable'),
                       ('IOS6I9100EMMCRaw.cpp','IOS6I9100EMMCRaw::matchPropertyTable'),
                       ('i9100_emmc_publication.cpp','gIOCatalogue->addDrivers(drivers,false)')):
        if anchor not in (ROOT/proofs[name]['source_file']).read_text():raise ValueError('Native storage matching unconnected: '+name)
    return dict(result='PASS',kernel_sha256=sha(kernel),actual_definitions={name:symbols[name] for name in required},cpp_definitions=cpp,
      source_sha256={name:item['source_sha256'] for name,item in proofs.items()},hardware_tested=False,device_contacted=False)
def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('kernel',type=Path);a=p.parse_args();print(json.dumps(verify(a.kernel),indent=2))
if __name__=='__main__':main()
