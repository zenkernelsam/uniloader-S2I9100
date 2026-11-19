"""Bounded desktop qualification from a coherent saved physical frame.

Only the already witnessed 360x600 desktop expanded onto the S2 panel is
supported. Three disjoint static icon patches qualify the visible desktop;
this does not prove app execution or any other viewport/screen state.
"""
import hashlib,json,struct,time
from pathlib import Path

TILES=((50,61,18,14),(410,61,18,14),(290,453,18,14))
BANDS=((60,16),(452,16))
WIDTH,HEIGHT,STRIDE=480,800,1920

def load_reference(path,root):
    path=Path(path).resolve();root=Path(root).resolve()
    if not path.is_relative_to(root/'out') or not path.is_file():raise ValueError('Desktop reference must be retained in loader out')
    data=json.loads(path.read_text());raw_path=path.parent/'framebuffer.bin'
    if (data.get('width'),data.get('height'),data.get('stride'),data.get('depth'),data.get('format'))!=(480,800,1920,32,'BGRX32'):
        raise ValueError('Expected actual physical S2 reference geometry')
    if data.get('coherent') is not True or data.get('sequence_before')!=data.get('sequence_after'):
        raise ValueError('A coherent original desktop reference is required')
    raw=raw_path.read_bytes()
    if len(raw)!=STRIDE*HEIGHT or hashlib.sha256(raw).hexdigest()!=data.get('raw_sha256'):
        raise ValueError('Desktop reference pixels differ from retained SHA')
    if data.get('console')!=0:raise ValueError('Console framebuffer is not a qualified desktop reference')
    return dict(path=str(path),tag=data['tag'],raw_sha256=data['raw_sha256'],raw=raw)

def tile_rgb(raw,x,y,w,h,origin=0):
    colors=bytearray()
    for yy in range(y,y+h):
        line=(yy-origin)*STRIDE+x*4
        for xx in range(w):colors.extend(raw[line+xx*4:line+xx*4+3])
    if len(colors)!=w*h*3:raise ValueError('Desktop sample is truncated')
    return bytes(colors)

def compare_tiles(reference,bands):
    scores=[]
    for x,y,w,h in TILES:
        start=next(start for start,lines in BANDS if start<=y and y+h<=start+lines)
        actual=tile_rgb(bands[start],x,y,w,h,start);expected=tile_rgb(reference['raw'],x,y,w,h)
        distances=[abs(a-b) for a,b in zip(actual,expected)]
        mean=sum(distances)/len(distances);close=sum(n<=24 for n in distances)/len(distances)
        scores.append(dict(rect=[x,y,w,h],mean_absolute_error=mean,close_fraction=close,
            match=mean<=12 and close>=.85))
    return scores

def wait_desktop(kernel,symbols,reference,out,record=lambda *a,**kw:None,clock=time.monotonic,sleep=time.sleep):
    out=Path(out);out.mkdir();deadline=clock()+6;samples=[]
    base,stride,width,height,depth=struct.unpack('<5I',kernel.read(symbols['_PE_state']+4,20))
    if (stride,width,height,depth)!=(1920,480,800,32):raise ValueError('Live scanout does not match the desktop reference')
    physical=kernel.u32(symbols['_i9100_fb_physical'])
    if not 0x40000000<=physical<physical+STRIDE*HEIGHT<=0x80000000:raise ValueError('Live scanout outside DRAM')
    symbol_names=symbols.values if hasattr(symbols,'values') and not callable(symbols.values) else symbols
    if '_i9100_display_power_diag' not in symbol_names:raise ValueError('Actual display-power evidence is required before a desktop action')
    def display_state():
        words=struct.unpack('<12I',kernel.read(symbols['_i9100_display_power_diag'],48))
        if words[0]!=1:raise ValueError('Unknown display-power schema')
        return dict(requests=words[1],requested_state=words[2],result=words[3],blanked=words[6])
    reference_public={k:v for k,v in reference.items() if k!='raw'}
    def save(ready=False):
        result=dict(ready=ready,reference=reference_public,physical=hex(physical),mapped_base=hex(base),
            samples=samples,scope='Saved static desktop icons only; not app or physical-touch acceptance')
        (out/'result.json').write_text(json.dumps(result,indent=2)+'\n');return result
    while clock()<deadline:
        number=len(samples);power_before=display_state();before=kernel.read(symbols['_i9100_graphics_seq'],8)
        console=kernel.u32(symbols['_i9100_panel_console_enabled']);blocks={}
        for start,lines in BANDS:
            if clock()>=deadline:save();raise TimeoutError('Desktop qualification expired before the next read')
            blocks[start]=kernel.read_phys(physical+start*STRIDE,lines*STRIDE)
            if len(blocks[start])!=lines*STRIDE:save();raise ValueError('Desktop band is incomplete; no follow-up')
            (out/f'sample-{number:02d}-rows-{start}.bin').write_bytes(blocks[start])
        after=kernel.read(symbols['_i9100_graphics_seq'],8);power_after=display_state();scores=compare_tiles(reference,blocks)
        awake=power_before==power_after and power_after['requested_state']>0 and power_after['blanked']==0 and power_after['result']==0
        sample=dict(sequence_before=struct.unpack('<Q',before)[0],sequence_after=struct.unpack('<Q',after)[0],
            sequence_stable=before==after,console=console,tiles=scores,display_before=power_before,display_after=power_after,awake=awake)
        sample['within_deadline']=clock()<deadline
        samples.append(sample);ready=sample['within_deadline'] and console==0 and awake and before==after and all(x['match'] for x in scores)
        sample['ready']=ready;save(ready);record('DESKTOP_SAMPLE',**sample)
        if ready:return save(True)
        sleep(.15)
    save();raise TimeoutError('Saved desktop was not observed; follow-up not sent')
