import re
data = open("/root/i9100d/out/uart2-probe3.log","rb").read().decode("latin1")
j10 = data.rfind("RETURN=802")
print("log bytes:",len(data),"j10_off:",j10)
grabs=[]; stacks=[]; creates=[]; destroys=[]; detach=[]
for m in re.finditer(r"pmap_grab_page: pmap=0x([0-9a-f]+) ppn=0x([0-9a-f]+) lr=0x([0-9a-f]+)",data):
    grabs.append((int(m.group(1),16),int(m.group(2),16),int(m.group(3),16),m.start()))
for m in re.finditer(r"machine_stack_attach: th=0x([0-9a-f]+) stpg(\d) va=0x([0-9a-f]+) pa=0x([0-9a-f]+)",data):
    stacks.append((int(m.group(1),16),int(m.group(2)),int(m.group(3),16),int(m.group(4),16),m.start()))
for m in re.finditer(r"machine_stack_detach: th=0x([0-9a-f]+) stva=0x([0-9a-f]+) pa=0x([0-9a-f]+)",data):
    detach.append((int(m.group(1),16),int(m.group(2),16),int(m.group(3),16),m.start()))
for m in re.finditer(r"pmap_create: pmap=0x([0-9a-f]+) l1phys=0x([0-9a-f]+)",data):
    creates.append((int(m.group(1),16),int(m.group(2),16),m.start()))
for m in re.finditer(r"pmap_destroy: pmap=0x([0-9a-f]+) l1phys=0x([0-9a-f]+) l1size=0x([0-9a-f]+)",data):
    destroys.append((int(m.group(1),16),int(m.group(2),16),m.start()))
print("grabs:",len(grabs),"stackpg:",len(stacks),"create:",len(creates),"destroy:",len(destroys))
pgtab={}
for pm,ppn,lr,o in grabs: pgtab.setdefault(ppn<<12,[]).append((pm,lr,o,"grab"))
for pm,ph,o in creates: pgtab.setdefault(ph,[]).append((pm,0,o,"L1"))
stk={}
for th,pg,va,pa,o in stacks: stk.setdefault(pa,[]).append((th,va,pg,o))
both=set(pgtab)&set(stk)
print("PTpage∩STACK overlap:",[hex(x) for x in sorted(both)])
for b in sorted(both):
    print(" pa=%x:"%b)
    for e in pgtab[b]: print("   PT:",e)
    for e in stk[b]: print("   STK:",e)
# L1 phys vs grab pages from OTHER pmaps (L1 being grabbed as L2!)
for pm,ph,o in creates:
    if ph in pgtab and not any(e[3]=="L1" and e[0]==pm for e in pgtab[ph]):
        print("L1 phys %x of pmap %x ALSO grabbed:"%(ph,pm),pgtab[ph])
