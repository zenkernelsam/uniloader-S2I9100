p = "/root/i9100d/xnu-S2I9100/xnu/bsd/kern/kern_exec.c"
s = open(p).read()
anchor = """		imgp->ip_ndp ? imgp->ip_ndp->ni_cnd.cn_nameptr :
		(imgp->ip_vp && imgp->ip_vp->v_name ? imgp->ip_vp->v_name : "??"));
#endif
#if BOARD_CONFIG_ARMPBA8
	if (ios7lab_exec_trace)"""
probe = """		imgp->ip_ndp ? imgp->ip_ndp->ni_cnd.cn_nameptr :
		(imgp->ip_vp && imgp->ip_vp->v_name ? imgp->ip_vp->v_name : "??"));
	if (error == 0 && imgp->ip_startargv && imgp->ip_endargv &&
	    imgp->ip_endargv > imgp->ip_startargv &&
	    imgp->ip_endargv <= imgp->ip_strendp && imgp->ip_argc > 0) {
		char *ac = (char *)imgp->ip_startargv;
		char *ae = (char *)imgp->ip_endargv;
		int ai;
		for (ai = 0; ai < imgp->ip_argc && ai < 8 && ac < ae; ai++) {
			char ab[96];
			int al = 0;
			while (ac < ae && *ac && al < (int)sizeof(ab) - 1)
				ab[al++] = *ac++;
			ab[al] = 0;
			if (ac < ae && *ac) { while (ac < ae && *ac) ac++; }
			kprintf("J1ARGV [%d]=%s\\n", ai, ab);
			if (ac < ae) ac++;
		}
	}
#endif
#if BOARD_CONFIG_ARMPBA8
	if (ios7lab_exec_trace)"""
count = s.count(anchor)
assert count >= 1, "anchor not found"
# patch BOTH occurrences (posix_spawn path at ~2073 and execve at ~2487)
s = s.replace(anchor, probe)
open(p, "w").write(s)
print("patched", count, "sites")
