"""Read-only ARMv7 page-table inspection over an existing forensic Session."""
import hashlib
from pathlib import Path
import struct


class MappingError(RuntimeError):
    pass


def ram(addr, size):
    if not (0x40000000 <= addr < 0x80000000 and 0 < size <= 32768 and addr + size <= 0x80000000):
        raise MappingError(f'Not bounded DRAM: {addr:x}+{size:x}')


class Symbols:
    def __init__(self, path):
        self.path = Path(path)
        data = self.path.read_bytes()
        self.tag = hashlib.sha256(data).hexdigest()[:16]
        magic, cpu, _, _, count, _, _ = struct.unpack_from('<7I', data)
        if magic != 0xfeedface or cpu != 12:
            raise ValueError('Expected a 32-bit ARM Mach-O kernel')
        pos = 28
        bases = []
        self.values = {}
        symtab = None
        for _ in range(count):
            command, size = struct.unpack_from('<II', data, pos)
            if size < 8 or pos + size > len(data):
                raise ValueError('Malformed Mach-O load command')
            if command == 1:
                bases.append(struct.unpack_from('<I', data, pos + 24)[0])
            elif command == 2:
                symtab = struct.unpack_from('<4I', data, pos + 8)
            pos += size
        self.base = min(bases)
        if symtab is None:
            raise ValueError('Kernel lacks a symbol table')
        offset, count, strings, size = symtab
        for index in range(count):
            name, kind, _, _, value = struct.unpack_from('<IBBHI', data, offset + index * 12)
            if not value or kind & 0xe0 or name >= size:
                continue
            start = strings + name
            end = data.index(b'\0', start, strings + size)
            self.values[data[start:end].decode('ascii')] = value

    def __getitem__(self, name):
        return self.values[name]


class PageMap:
    def __init__(self, read_phys, l1_phys, l1_size=0x4000):
        # TTBR0 may use a reduced table (the live i9100 user maps start at
        # 4KiB, TTBCR.N=2); only the kernel's full L1 requires 16KiB alignment.
        if l1_size not in (0x1000, 0x2000, 0x4000) or l1_phys & (l1_size - 1):
            raise MappingError('Invalid ARM L1 geometry')
        ram(l1_phys, l1_size)
        self.read_phys = read_phys
        self.l1 = read_phys(l1_phys, l1_size)
        self.l2 = {}

    def translate(self, va):
        if not 0 <= va <= 0xffffffff:
            raise MappingError('Not an ARMv7 virtual address')
        offset = (va >> 20) * 4
        if offset + 4 > len(self.l1):
            raise MappingError('VA outside this L1 table')
        entry = struct.unpack_from('<I', self.l1, offset)[0]
        if entry & 3 == 2:
            pa = ((entry & 0xff000000) | (va & 0xffffff)) if entry & (1 << 18) else ((entry & 0xfff00000) | (va & 0xfffff))
        elif entry & 3 == 1:
            base = entry & 0xfffffc00
            ram(base, 0x400)
            if base not in self.l2:
                self.l2[base] = self.read_phys(base, 0x400)
            pte = struct.unpack_from('<I', self.l2[base], ((va >> 12) & 255) * 4)[0]
            if pte & 3 == 1:
                pa = (pte & 0xffff0000) | (va & 0xffff)
            elif pte & 2:
                pa = (pte & 0xfffff000) | (va & 0xfff)
            else:
                raise MappingError(f'Unmapped L2 VA {va:08x}')
        else:
            raise MappingError(f'Unmapped L1 VA {va:08x}')
        ram(pa, 1)
        return pa

    def read(self, va, size):
        if not 0 < size <= 32768:
            raise MappingError('Invalid virtual read length')
        result = bytearray()
        while size:
            count = min(size, 4096 - (va & 4095))
            result.extend(self.read_phys(self.translate(va), count))
            va += count
            size -= count
        return bytes(result)


class Kernel:
    def __init__(self, session, symbols, load_phys=0x40001000):
        if session.receiver.expected_tag != symbols.tag:
            raise MappingError('Live build and symbol kernel differ')
        self.session, self.symbols = session, symbols
        self.bias = symbols.base - load_phys
        self.phys_base = self.u32_phys(symbols['_gPhysBase'] - self.bias)
        self.virt_base = self.u32_phys(symbols['_gVirtBase'] - self.bias)
        if self.phys_base != 0x40000000 or self.virt_base != 0x80000000:
            raise MappingError('Unexpected live i9100 physmap')
        self.pmap_va = self.u32_phys(symbols['_kernel_pmap'] - self.bias)
        header = self.read_phys(self.pmap_va - self.bias, 0x34)
        self.pmap = PageMap(self.read_phys, struct.unpack_from('<I', header)[0], struct.unpack_from('<I', header, 0x30)[0])

    def read_phys(self, addr, size):
        ram(addr, size)
        _, data = self.session.command(f'read-memory {addr:08x} {size:x}')
        if len(data) != size:
            raise MappingError('Incomplete physical read')
        return data

    def u32_phys(self, addr):
        return struct.unpack('<I', self.read_phys(addr, 4))[0]

    def read(self, va, size):
        return self.pmap.read(va, size)

    def u32(self, va):
        return struct.unpack('<I', self.read(va, 4))[0]

    def user_pmap(self, pmap_va):
        header = self.read(pmap_va, 0x34)
        return PageMap(self.read_phys, struct.unpack_from('<I', header)[0], struct.unpack_from('<I', header, 0x30)[0])
