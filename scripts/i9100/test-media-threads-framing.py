#!/usr/bin/env python3
"""Parse production first-media peer registers/handlers and reject bad sizes."""
import argparse
import contextlib
from datetime import datetime
import importlib.util
import io
from pathlib import Path
import struct
p=argparse.ArgumentParser(description=__doc__);p.add_argument('--fixture',type=Path,required=True);p.add_argument('--identity-fixture',type=Path);p.add_argument('--native-fixture',type=Path);p.add_argument('--selected-fixture',type=Path);p.add_argument('--target-fixture',type=Path);p.add_argument('--early-payload-fixture',type=Path);p.add_argument('--selected-runtime-fixture',type=Path);p.add_argument('--owner-fixture',type=Path);p.add_argument('--dispatch-fixture',type=Path);p.add_argument('--catalog-fixture',type=Path);p.add_argument('--exit-fixture',type=Path);a=p.parse_args()
s=importlib.util.spec_from_file_location('peers_parser',Path(__file__).with_name('inspect-mdns.py'));m=importlib.util.module_from_spec(s);s.loader.exec_module(m)
repo=Path(__file__).resolve().parents[2];out=repo/'out'/('media-threads-framing-'+datetime.now().strftime('%Y%m%d-%H%M%S'));out.mkdir()
class Symbols:
    values={'_i9100_media_threads':0x1000}
    def __getitem__(self,key):return self.values[key]
class Memory:
    def __init__(self,data):self.data=data
    def read(self,address,size):
        regions=self.data if isinstance(self.data,dict) else {0x1000:self.data}
        if address in regions:
            assert size<=len(regions[address])
            return regions[address][:size]
        for base,data in regions.items():
            if base<=address and address+size<=base+len(data):return data[address-base:address-base+size]
        raise AssertionError('Read outside fixture')
def decode(label,data,symbols=None,key='media_first_threads'):
    target=out/label;target.mkdir()
    with contextlib.redirect_stdout(io.StringIO()):return m.capture_ui_observations(Memory(data),symbols or Symbols(),target)[key]
raw=a.fixture.read_bytes();r=decode('production',raw);assert r['count']==3 and r['pid']==33 and r['callback_stage']==2
assert r['runtime_available']
if a.identity_fixture:
    combined=Symbols();combined.values={'_i9100_media_threads':0x1000,'_i9100_media_identity':0x2000}
    identity_raw=a.identity_fixture.read_bytes()
    def decode_identity(label,data,peer=raw):
        return decode(label,{0x1000:peer,0x2000:data},combined,'media_identity')
    identity=decode_identity('identity-production',identity_raw)
    row=identity['rows'][0]
    assert identity['count']==3 and row['tid_low']==578 and row['raw_tls_low']==0x40003
    assert row['tls_word']==row['mutex_prefix']==0x40080 and row['tls_error']==row['prefix_error']==0
    for label,word,value in [('id-version',1,2),('id-pid',2,34),('id-task',3,0xdead),('id-count',4,2),
                             ('id-cap',5,17),('id-stride',6,9),('id-sequence',8,2),
                             ('id-high-with-copy',10,1),('id-raw-error-with-copy',11,1)]:
        changed=bytearray(identity_raw);struct.pack_into('<I',changed,word*4,value)
        try:decode_identity(label,bytes(changed));raise AssertionError('Bad identity accepted')
        except ValueError:pass
    changed=bytearray(identity_raw);struct.pack_into('<I',changed,(8+5)*4,14);struct.pack_into('<I',changed,(8+7)*4,14)
    failed=decode_identity('identity-user-read-failed',bytes(changed))
    assert failed['rows'][0]['tls_error']==failed['rows'][0]['prefix_error']==14
    changed_peer=bytearray(raw);struct.pack_into('<I',changed_peer,(16+18)*4,31)
    try:decode_identity('identity-not-a-wait',identity_raw,bytes(changed_peer));raise AssertionError('Non-wait prefix accepted')
    except ValueError:pass
if a.native_fixture:
    native=decode('native-no-repair',a.native_fixture.read_bytes())
    assert native['count']==3 and native['pid']==33 and not native['runtime_available']
    assert native['calls'] is None and native['callback_stage'] is None and native['released'] is None
    assert native['raw_runtime_words']==[0,0,0] and native['runtime_error']==0xffffffff
    assert native['rows'][0]['tid_low']==578 and native['rows'][0]['instruction_hex']==r['rows'][0]['instruction_hex']
changed=bytearray(raw);struct.pack_into('<I',changed,9*4,14)
failed_runtime=decode('runtime-read-failed',bytes(changed))
assert not failed_runtime['runtime_available'] and failed_runtime['callback_stage'] is None
if a.target_fixture:
    target_symbols=Symbols();target_symbols.values={'_i9100_audio_observation_target':0x1000}
    target_raw=a.target_fixture.read_bytes();target=decode('target',target_raw,target_symbols,'audio_observation_target')
    assert target['state']==2 and target['pid']==34 and target['calls_at_selection']>0
    for label,word,value in [('target-version',0,2),('target-state',1,3),('target-empty-pid',2,0),('target-empty-calls',6,0),('target-stage',7,0)]:
        changed=bytearray(target_raw);struct.pack_into('<I',changed,word*4,value)
        try:decode(label,bytes(changed),target_symbols,'audio_observation_target');raise AssertionError('Bad target accepted')
        except ValueError:pass
    if a.selected_fixture:
        selected_raw=a.selected_fixture.read_bytes()
        # Both production C fixtures use modeled tasks at different host
        # addresses. Adapt only that address for the combined parser fixture.
        combined_target=bytearray(target_raw);struct.pack_into('<I',combined_target,3*4,struct.unpack_from('<I',selected_raw,3*4)[0])
        combined=Symbols();combined.values={'_i9100_audio_observation_target':0x1000,'_i9100_media_threads':0x2000}
        selected=decode('selected-combined',{0x1000:bytes(combined_target),0x2000:selected_raw},combined)
        assert selected['pid']==34 and selected['selection']=='executed-callback'
        for label,word,value in [('selected-wrong-pid',2,35),('selected-wrong-task',3,0xdead),('selected-wrong-slide',4,0x200000)]:
            changed=bytearray(combined_target);struct.pack_into('<I',changed,word*4,value)
            try:decode(label,{0x1000:bytes(changed),0x2000:selected_raw},combined);raise AssertionError('Mixed selected identity accepted')
            except ValueError:pass
    if a.early_payload_fixture and a.selected_runtime_fixture:
        retained=Symbols();retained.values={'_i9100_audio_observation_target':0x1000,'_i9100_media_kill_payload':0x2000,'_i9100_media_audio_runtime':0x3000}
        data={0x1000:target_raw,0x2000:a.early_payload_fixture.read_bytes(),0x3000:a.selected_runtime_fixture.read_bytes()}
        result=decode('earliest-plus-selected',data,retained,'media_kill_payload')
        assert result['pid']==33
        changed=bytearray(data[0x3000]);struct.pack_into('<I',changed,4,35)
        try:decode('runtime-wrong-target',{**data,0x3000:bytes(changed)},retained,'media_audio_runtime');raise AssertionError('Wrong runtime target accepted')
        except ValueError:pass
first=r['rows'][0];assert first['tid_low']==578 and first['registers'][12]==301 and first['mutex_words'][8]==578
assert first['frame_rows'][0]['lr']==0x310fdd65 and first['handler_args'][0]==0x5500 and first['handler_args_observed']==1
assert r['version']==2 and first['instruction_error']==0 and first['instruction_hex']=='0000a0e11eff2fe14433221188776655'
legacy=bytearray(raw);struct.pack_into('<I',legacy,4,1)
old=decode('legacy',bytes(legacy));assert old['rows'][0]['instruction_error'] is None and old['rows'][0]['instruction_hex'] is None
for label,word,value in [('version',1,3),('count',4,17),('sequence',16,2),('frames',16+23,7)]:
    changed=bytearray(raw);struct.pack_into('<I',changed,word*4,value)
    try:decode(label,bytes(changed));raise AssertionError('Unknown peer layout accepted')
    except ValueError:pass
if a.owner_fixture:
    owner_symbols=Symbols();owner_symbols.values={'_i9100_audio_owner_diag':0x1000}
    owner_raw=a.owner_fixture.read_bytes();owners=decode('owners',owner_raw,owner_symbols,'audio_owners')
    assert owners['count']==2 and owners['rows'][0]['sequence']==1 and owners['rows'][0]['owner_low']==579
    assert owners['rows'][0]['registers'][0]==0x12040 and owners['rows'][0]['frame_rows'][0]['lr']==0x310fdd65
    assert owners['rows'][1]['error']==2 and owners['rows'][1]['frame_count']==0
    assert owners['version']==2
    stack_path=a.owner_fixture.with_name('audio-owner-stack.bin')
    if stack_path.exists():
        stack_symbols=Symbols();stack_symbols.values={'_i9100_audio_owner_stack':0x1000}
        stack_raw=stack_path.read_bytes()
        stack=decode('owner-stack',stack_raw,stack_symbols,'audio_owner_stack')
        assert stack['frame_matches'] and stack['candidate_guard']==dict(sp=0x30750,lock_return=1,mutex=0x12000,release_byte=1,cleanup_stage=7)
        for label,word,value in [('stack-version',1,2),('stack-sequence',4,9),('stack-length',10,252),('stack-caller',12,0x310fdd65),('stack-match',14,0)]:
            changed=bytearray(stack_raw);struct.pack_into('<I',changed,word*4,value)
            try:decode(label,bytes(changed),stack_symbols,'audio_owner_stack');raise AssertionError('Bad stack accepted')
            except ValueError:pass
        changed=bytearray(stack_raw);struct.pack_into('<I',changed,9*4,14);struct.pack_into('<I',changed,14*4,0)
        badcopy=decode('stack-copy-failed',bytes(changed),stack_symbols,'audio_owner_stack')
        assert not badcopy['frame_matches'] and 'candidate_guard' not in badcopy
        changed=bytearray(stack_raw);struct.pack_into('<I',changed,78*4,0x30820);struct.pack_into('<I',changed,14*4,0)
        moved=decode('stack-frame-moved',bytes(changed),stack_symbols,'audio_owner_stack')
        assert not moved['frame_matches'] and 'candidate_guard' not in moved
        mixed=Symbols();mixed.values={'_i9100_audio_owner_diag':0x1000,'_i9100_audio_owner_stack':0x4000}
        try:decode('stack-other-walk',{0x1000:owner_raw,0x4000:stack_raw},mixed,'audio_owner_stack');raise AssertionError('Unrelated owner stack accepted')
        except ValueError:pass
    deep_path=a.owner_fixture.with_name('audio-owner-deep.bin')
    if deep_path.exists():
        deep=decode('deep-owner',deep_path.read_bytes(),owner_symbols,'audio_owners')
        assert deep['count']==3 and deep['rows'][2]['frame_count']==16
        assert deep['rows'][2]['frame_rows'][15]['lr']==0x310fdd65
    legacy=bytearray(struct.pack('<4I',2,1,8,64))
    for n in range(8):
        row=bytearray(owner_raw[(4+n*96)*4:(4+n*96+64)*4])
        if struct.unpack_from('<I',row)[0]:struct.pack_into('<I',row,13*4,1)
        legacy.extend(row)
    old=decode('legacy-owner',bytes(legacy),owner_symbols,'audio_owners')
    assert old['version']==1 and old['rows'][0]['frame_rows']==owners['rows'][0]['frame_rows']
    for label,word,value in [('owner-version',1,3),('owner-cap',2,9),('owner-row-version',4+13,3),('owner-frames',4+10,17),('owner-stride',3,95)]:
        changed=bytearray(owner_raw);struct.pack_into('<I',changed,word*4,value)
        try:decode(label,bytes(changed),owner_symbols,'audio_owners');raise AssertionError('Unknown owner layout accepted')
        except ValueError:pass
if a.dispatch_fixture:
    dispatch_symbols=Symbols();dispatch_symbols.values={'_i9100_media_dispatch_diag':0x1000}
    dispatch_raw=a.dispatch_fixture.read_bytes();q=decode('dispatch',dispatch_raw,dispatch_symbols,'media_dispatch')
    assert q['pid']==33 and q['slot']==0x39594dd0 and q['queue']==0x25000 and q['bytes']==256
    assert b'com.apple.coremedia.fixture' in bytes.fromhex(q['raw_hex'])
    for label,word,value in [('dispatch-version',1,2),('dispatch-bytes',9,257),('dispatch-error',8,14)]:
        changed=bytearray(dispatch_raw);struct.pack_into('<I',changed,word*4,value)
        try:decode(label,bytes(changed),dispatch_symbols,'media_dispatch');raise AssertionError('Unknown dispatch layout accepted')
        except ValueError:pass
if a.catalog_fixture:
    catalog_symbols=Symbols();catalog_symbols.values={'_i9100_early_process_diag':0x1000}
    catalog_raw=a.catalog_fixture.read_bytes();catalog=decode('catalog',catalog_raw,catalog_symbols,'early_processes')
    assert len(catalog['rows'])==1 and catalog['rows'][0]['pid']==14 and catalog['rows'][0]['idversion']==15
    assert catalog['rows'][0]['name']=='FixtureExec' and catalog['rows'][0]['updates']==2
    for label,word,value in [('catalog-version',0,2),('catalog-capacity',1,65),('catalog-pid',4+14*12+1,15)]:
        changed=bytearray(catalog_raw);struct.pack_into('<I',changed,word*4,value)
        try:decode(label,bytes(changed),catalog_symbols,'early_processes');raise AssertionError('Unknown catalog layout accepted')
        except ValueError:pass
if a.exit_fixture:
    exit_symbols=Symbols();exit_symbols.values={'_i9100_early_exit_diag':0x1000}
    exit_raw=a.exit_fixture.read_bytes();exits=decode('exits',exit_raw,exit_symbols,'early_exits')
    assert len(exits['rows'])==1 and exits['rows'][0]['pid']==14 and exits['rows'][0]['wait_status']==0x100
    assert exits['rows'][0]['own_context']==1 and exits['rows'][0]['user_state_known']==0 and exits['rows'][0]['pc']==0
    for label,word,value in [('exit-version',0,2),('exit-pid',4+14*16+1,15),('exit-context',4+14*16+5,2)]:
        changed=bytearray(exit_raw);struct.pack_into('<I',changed,word*4,value)
        try:decode(label,bytes(changed),exit_symbols,'early_exits');raise AssertionError('Unknown exit layout accepted')
        except ValueError:pass
print('PASS production peer identities, saved registers/handler args/owner/frame layout; unknown schemas rejected')
print('EVIDENCE',out)
