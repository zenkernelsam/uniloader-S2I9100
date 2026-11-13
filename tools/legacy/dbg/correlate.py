import re, sys
data = open("/root/i9100d/out/uart2-probe2.log","rb").read().decode("latin1")
l1s = []
expands = []
stacks = []
destroys = []
for m in re.finditer(r"pmap_create: pmap=0x([0-9a-f]+) l1phys=0x([0-9a-f]+)", data):
    l1s.append((int(m.group(1),16), int(m.group(2),16)))
for m in re.finditer(r"pmap_expand_ttb: pmap=0x([0-9a-f]+) l1pg(\d+) ppn=0x([0-9a-f]+)", data):
    expands.append((int(m.group(1),16), int(m.group(2)), int(m.group(3),16)))
for m in re.finditer(r"machine_stack_attach: th=0x([0-9a-f]+) stpg(\d+) va=0x([0-9a-f]+) pa=0x([0-9a-f]+)", data):
    stacks.append((int(m.group(1),16), int(m.group(2)), int(m.group(3),16), int(m.group(4),16)))
for m in re.finditer(r"pmap_destroy: pmap=0x([0-9a-f]+) l1phys=0x([0-9a-f]+) l1size=0x([0-9a-f]+)", data):
    destroys.append((int(m.group(1),16), int(m.group(2),16), int(m.group(3),16)))
print("pmap_create:",len(l1s),"expand_ttb:",len(expands),"stack pages:",len(stacks),"pmap_destroy:",len(destroys))
l1pages = {}
for pm,ph in l1s:
    l1pages[ph] = ("l1",pm)
for pm,idx,ppn in expands:
    l1pages[ppn<<12] = ("l1x",pm,idx)
stkpages = {}
for th,pg,va,pa in stacks:
    stkpages.setdefault(pa,[]).append((th,va,pg))
print("unique L1 phys:",len(l1pages),"unique stack phys:",len(stkpages))
overlap = set(l1pages) & set(stkpages)
print("OVERLAPPING PHYS:",[hex(x) for x in sorted(overlap)])
for o in sorted(overlap):
    print(" pa=%x"%o, l1pages[o], stkpages[o])
