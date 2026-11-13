import re
data = open("/root/i9100d/out/uart2-probe2.log","rb").read().decode("latin1")
pat = re.compile(r"(pmap_create: pmap=0x[0-9a-f]+ l1phys=0x[0-9a-f]+|pmap_destroy: pmap=0x[0-9a-f]+ l1phys=0x[0-9a-f]+ l1size=0x[0-9a-f]+|machine_stack_attach: th=0x[0-9a-f]+ stpg\d va=0x[0-9a-f]+ pa=0x[0-9a-f]+|machine_stack_detach: th=0x[0-9a-f]+ stva=0x[0-9a-f]+ pa=0x[0-9a-f]+|Leo J10[^\n]*|J1EXEC[^\n]*)")
evs = [(m.start(), m.group(1)[:110]) for m in pat.finditer(data)]
j10 = [i for i,(o,e) in enumerate(evs) if "J10" in e]
print("total events:",len(evs),"J10 hits:",len(j10))
for o,e in evs[-45:]:
    print(e)
