#!/usr/bin/env python3
"""Verify retained deployment packages and source/link evidence after maintenance."""
import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import sys

ROOT=Path(__file__).resolve().parents[3]

def sha(path):
    value=hashlib.sha256()
    with path.open('rb') as stream:
        for block in iter(lambda:stream.read(1024*1024),b''):
            value.update(block)
    return value.hexdigest()

def path(value):
    text=str(value).replace('\\','/')
    for prefix in ('/root/i9100d/','/mnt/d/Desktop/Git/ios-samsung-i9100/'):
        if text.startswith(prefix):
            text=text[len(prefix):]
            break
    p=(ROOT/text).resolve()
    if not p.is_relative_to(ROOT):
        raise ValueError('Dependency escaped project: '+text)
    return p

def main():
    if os.name!='posix':
        raise RuntimeError('Use WSL CPU envelope')
    if os.environ.get('I9100_CPU_CAPPED')!='1':
        os.execvpe('taskset',['taskset','-c','0-13','nice','-n10','ionice','-c2','-n7',
              sys.executable,'-B',*sys.argv],dict(os.environ,I9100_CPU_CAPPED='1'))
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output',type=Path,required=True)
    args=parser.parse_args()
    output=args.output.resolve()
    if not output.is_relative_to(ROOT/'research/archive') or output.exists():
        raise ValueError('Use fresh archive receipt')
    verified={}
    def check(name,expected=None):
        p=path(name)
        if p.is_symlink() or not p.is_file():
            raise ValueError('Missing retained input: '+str(p))
        value=sha(p)
        if expected and value!=expected:
            raise ValueError('Retained SHA changed: '+str(p))
        verified[p.relative_to(ROOT).as_posix()]=value
        return p
    folder=ROOT/'uniloader-S2I9100/out/automation/control-20261120-charge-liquid'
    manifest=json.loads((folder/'manifest.json').read_text())
    for name,expected in manifest['artifacts'].items():
        p=check(folder/name,expected['sha256'])
        if p.stat().st_size!=expected['bytes']:
            raise ValueError('Artifact length changed')
    check(folder/'candidate-origin.json')
    check(folder/'charger-identity.json')
    check(ROOT/'uniloader-S2I9100/out/automation/plan-20261120-233647-98db23db/zImage',
          manifest['artifacts']['zImage']['sha256'])
    # Exact replacement/reuse paths remain present; newer working BUILD can
    # legitimately differ from the already recorded frozen source hashes.
    sd=ROOT/'xnu-S2I9100/out/automation/sd-root-recovery-20261120-2142'
    sd_snapshot=json.loads((sd/'snapshot.json').read_text())
    reused_paths=[path(name) for name in sd_snapshot['reused_link_inputs']]
    if not all(p.is_file() for p in reused_paths):
        raise ValueError('SD charge link ancestry missing')
    for line in (sd/'link.filelist').read_text().splitlines():
        if line.strip() and not path(line.strip()).is_file():
            raise ValueError('SD final link input missing: '+line)
    emmc=ROOT/'xnu-S2I9100/out/audio-client-link-20261120-230451-832235'
    emmc_manifest=json.loads((emmc/'manifest.json').read_text())
    check(emmc/'mach_kernel.sys',emmc_manifest['linked_kernel_sha256'])
    for sub in ('frozen-final','frozen-reference','frozen-aux'):
        snapshot=json.loads((emmc/sub/'snapshot.json').read_text())
        for row in snapshot['inputs']:
            check(row['frozen'],row['sha256'])
    pair=ROOT/'uniloader-S2I9100/out/ios6-volume-pair-20261120-025359-621241/pair-manifest.json'
    check(pair,'6537b80fbe6ee071a895a5c3b8279121f3ccae63d82506d6280f1aa1a319b0f7')
    # Bulk HFS/recycle payload SHA evidence is already independently retained.
    prior=ROOT/'research/archive/maintenance-20261121/s2-research-recycle-sha-verification.json'
    bulk=json.loads(prior.read_text())
    if bulk['result']!='PASS' or not bulk['every_recycle_payload_sha256_verified']:
        raise ValueError('Bulk retirement verification did not finish')
    result=dict(schema=1,result='PASS',created_utc=datetime.now(timezone.utc).isoformat(),
       hardware_contacted=False,verified_file_count=len(verified),sha256=verified,
       sd_reused_link_paths_present=len(reused_paths),bulk_receipt_sha256=sha(prior),
       current_package_sha256=manifest['artifacts']['zImage']['sha256'],
       emmc_kernel_sha256=emmc_manifest['linked_kernel_sha256'],
       limitation='Frozen input bytes verified; live BUILD path presence only. Device not reopened.')
    output.write_text(json.dumps(result,indent=2)+'\n',encoding='utf8')
    print(json.dumps(dict(result='PASS',sha_verified=len(verified),
          sd_link_paths_present=len(reused_paths),output=str(output))))
if __name__=='__main__':
    main()
