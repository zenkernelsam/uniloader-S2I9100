"""Bounded read-only ARM Mach-O reference used to resolve unmapped metadata."""
import hashlib,struct
from pathlib import Path

class MachImage:
    def __init__(self,path,uuid=None):
        self.path=Path(path).resolve();self.data=self.path.read_bytes();self.segments=[];self.uuid=None
        h=struct.unpack_from('<7I',self.data)
        if h[0]!=0xfeedface or h[1]!=12 or h[3]!=2 or not 0<h[4]<=128 or h[5]>16384:
            raise ValueError('Expected bounded ARM executable')
        at=28;end=at+h[5]
        if end>len(self.data):raise ValueError('Executable commands outside file')
        for _ in range(h[4]):
            command,size=struct.unpack_from('<2I',self.data,at)
            if size<8 or at+size>end:raise ValueError('Invalid executable load command')
            if command==1:
                name=self.data[at+8:at+24].rstrip(b'\0');va,extent,off,n=struct.unpack_from('<4I',self.data,at+24)
                if off+n>len(self.data):raise ValueError('Executable segment outside file')
                self.segments.append((va,extent,off,n))
                if name==b'__TEXT':self.base=va
            if command==27:
                if size!=24:raise ValueError('Invalid executable UUID command')
                self.uuid=self.data[at+8:at+24].hex()
            at+=size
        if uuid is not None and self.uuid!=uuid:raise ValueError('Original executable UUID differs')
        self.sha256=hashlib.sha256(self.data).hexdigest()
    def offset(self,address,size=1):
        for va,_,off,n in self.segments:
            if va<=address and 0<size and address+size<=va+n:return off+address-va
        raise ValueError('Address outside file-backed original executable')
    def read(self,address,size):at=self.offset(address,size);return self.data[at:at+size]
    def string(self,address,limit=16384):
        at=self.offset(address);end=self.data.find(b'\0',at,min(len(self.data),at+limit))
        if end<at:raise ValueError('Unterminated original executable string')
        self.offset(address,end-at+1)
        return self.data[at:end].decode('utf-8','strict')
