import re
data = open("/root/i9100d/out/uart2-probe2.log","rb").read().decode("latin1")
l1={}; det={}
for m in re.finditer(r"pmap_create: pmap=0x([0-9a-f]+) l1phys=0x([0-9a-f]+)",data):
    l1[int(m.group(1),16)]=int(m.group(2),16)
    print("CREATE pmap=%x l1phys=%x @%d"%(int(m.group(1),16),int(m.group(2),16),m.start()))
for m in re.finditer(r"pmap_destroy: pmap=0x([0-9a-f]+) l1phys=0x([0-9a-f]+) l1size=0x([0-9a-f]+)",data):
    det[int(m.group(1),16)]=(int(m.group(2),16),int(m.group(3),16),m.start())
    print("DESTROY pmap=%x l1phys=%x l1size=%x @%d"%(int(m.group(1),16),int(m.group(2),16),int(m.group(3),16),m.start()))
alive={k:v for k,v in l1.items() if k not in det}
print("ALIVE L1:",[hex(v) for v in alive.values()])
# stack pa in the last 2000 events before J10 (offset)
j10off = data.find("RETURN=802p")
print("J10 offset:",j10off)
stacks=[]
for m in re.finditer(r"machine_stack_attach: th=0x([0-9a-f]+) stpg(\d) va=0x([0-9a-f]+) pa=0x([0-9a-f]+)",data):
    if m.start()<j10off: stacks.append((int(m.group(1),16),int(m.group(2)),int(m.group(3),16),int(m.group(4),16),m.start()))
live={}
for th,pg,va,pa,o in stacks: live.setdefault((th,va),[]).append((pa,o))
# last attached stacks still live
seen={}
for th,pg,va,pa,o in stacks: seen[(th,va)]=pa
print("stack pa set near hang:",sorted(set(hex(p) for p in seen.values())))
overlap = set(alive.values()) & set(seen.values())
print("L1∩STACK overlap:",[hex(x) for x in overlap])
