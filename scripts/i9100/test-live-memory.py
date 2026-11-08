#!/usr/bin/env python3
"""Offline ARM page geometry checks, including failure instead of zero filling."""
import importlib.util
from pathlib import Path
import struct
import unittest

spec=importlib.util.spec_from_file_location('memory',Path(__file__).with_name('live-memory.py'))
m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)


class Tests(unittest.TestCase):
    def setup_map(self, va, entry, l2=None):
        l1=bytearray(0x4000);struct.pack_into('<I',l1,(va>>20)*4,entry)
        def read(pa,n):
            if pa==0x41804000:return bytes(l1)
            if pa==0x42000000 and l2 is not None:return bytes(l2)
            return bytes((pa+i)&255 for i in range(n))
        return m.PageMap(read,0x41804000)

    def test_section(self):
        p=self.setup_map(0xc20578c0,0x45000002)
        self.assertEqual(p.translate(0xc20578c0),0x450578c0)

    def test_supersection(self):
        p=self.setup_map(0xc20578c0,0x45040002)
        self.assertEqual(p.translate(0xc20578c0),0x450578c0)

    def test_small_pages_and_cross_page_read(self):
        l2=bytearray(0x400)
        struct.pack_into('<I',l2,0x57*4,0x46001002)
        struct.pack_into('<I',l2,0x58*4,0x47001003)
        p=self.setup_map(0xc20578c0,0x42000001,l2)
        self.assertEqual(p.translate(0xc20578c0),0x460018c0)
        self.assertEqual(p.read(0xc2057ffe,4),bytes([254,255,0,1]))

    def test_large_page(self):
        l2=bytearray(0x400);struct.pack_into('<I',l2,0x57*4,0x46000001)
        p=self.setup_map(0xc20578c0,0x42000001,l2)
        self.assertEqual(p.translate(0xc20578c0),0x460078c0)

    def test_faults_do_not_return_zeroes(self):
        p=self.setup_map(0xc20578c0,0)
        with self.assertRaises(m.MappingError):p.read(0xc20578c0,4)
        p=self.setup_map(0xc20578c0,0x42000001,bytearray(0x400))
        with self.assertRaises(m.MappingError):p.translate(0xc20578c0)

    def test_reduced_user_l1_geometry(self):
        data=bytearray(0x1000)
        struct.pack_into('<I',data,(0x3acc2eb4>>20)*4,0x45000002)
        p=m.PageMap(lambda pa,n:bytes(data),0x50502000,0x1000)
        self.assertEqual(p.translate(0x3acc2eb4),0x450c2eb4)
        with self.assertRaises(m.MappingError):p.translate(0x40000000)

    def test_mmio_and_out_of_range_blocked(self):
        for entry in (0x10000002,0x10000001,0x80000002):
            p=self.setup_map(0xc20578c0,entry)
            with self.assertRaises(m.MappingError):p.translate(0xc20578c0)
        with self.assertRaises(m.MappingError):m.ram(0x7fffffff,2)
        with self.assertRaises(m.MappingError):m.PageMap(lambda a,n:bytes(n),0x41804004)


if __name__=='__main__':unittest.main()
