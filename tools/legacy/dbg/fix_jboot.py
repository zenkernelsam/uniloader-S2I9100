p = "/root/i9100d/xnu-S2I9100/xnu/bsd/kern/kern_shutdown.c"
s = open(p).read()
broken = 'kdb_printf("JBOOT: boot(pid=%d %s paniced=%d howto=0x%x)\n",'
fixed = 'kdb_printf("JBOOT: boot(pid=%d %s paniced=%d howto=0x%x)' + "\\n" + '",'
assert broken in s, "pattern not found"
s = s.replace(broken, fixed, 1)
open(p, "w").write(s)
print("fixed")
