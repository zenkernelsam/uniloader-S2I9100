p = "/root/i9100d/xnu-S2I9100/xnu/osfmk/arm/trap.c"
s = open(p).read()
anchor = """                    printf("dyld_all_image_info_addr: 0x%08x   dyld_all_image_info_size: 0x%08x\\n",
                            thread->task->all_image_info_addr, thread->task->all_image_info_size);
                } else {"""
assert anchor in s, "anchor not found"
probe = """                    printf("dyld_all_image_info_addr: 0x%08x   dyld_all_image_info_size: 0x%08x\\n",
                            thread->task->all_image_info_addr, thread->task->all_image_info_size);
#if defined(BOARD_CONFIG_EXYNOS4210_I9100)
                    {
                        extern boolean_t vm_map_lookup_entry(vm_map_t, vm_map_address_t, vm_map_entry_t *);
                        unsigned addrs[3] = { (unsigned)arm_ctx->pc, (unsigned)arm_ctx->lr, (unsigned)arm_ctx->sp };
                        const char *names[3] = { "pc", "lr", "sp" };
                        int ai;
                        for (ai = 0; ai < 3; ai++) {
                            vm_map_entry_t fe = (vm_map_entry_t)0;
                            unsigned a = addrs[ai] & ~1U;
                            if (vm_map_lookup_entry(map, (vm_map_address_t)a, &fe) && fe)
                                kprintf("JCRASH %s=%08x entry=[%08x-%08x] off=%llx obj=%p pager=%p\\n",
                                        names[ai], a,
                                        (unsigned)fe->vme_start, (unsigned)fe->vme_end,
                                        (unsigned long long)fe->offset,
                                        fe->object.vm_object,
                                        fe->object.vm_object ? fe->object.vm_object->pager : 0);
                            else
                                kprintf("JCRASH %s=%08x unmapped\\n", names[ai], a);
                        }
                        {
                            unsigned short iw[4];
                            if (copyin((user_addr_t)(arm_ctx->pc & ~1U), (char *)iw, 8) == 0)
                                kprintf("JCRASH insn=%04x %04x %04x %04x\\n",
                                        iw[0], iw[1], iw[2], iw[3]);
                        }
                    }
#endif
                } else {"""
s = s.replace(anchor, probe, 1)
open(p, "w").write(s)
print("patched")
