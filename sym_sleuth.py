#!/usr/bin/env python

import struct
from reader import ReadException

class ParseException(Exception):
  def __init_(self, msg):
    super(ParseException, self).__init__(msg)

class ELFSizes(object):
  def __init__(self, elf64):
    self.half_sz=2
    self.word_sz=4
    if elf64:
      self.addr_sz=8
      self.xword_sz=8
    else:
      self.addr_sz=4

  @staticmethod
  def unpack_fmt(le, sizes):
    ret = "<" if le else ">"
    if not type(sizes) == type([]):
      sizes = [sizes]
    for sz in sizes:
      if sz == 8:
        ret += "Q"
      elif sz == 4:
        ret += "I"
      elif sz == 2:
        ret += "H"
      elif sz == 1:
        ret += "B"
      else:
        assert False
    return ret

class SymbolTableEntry(object):
  def __str__(self):
        return "name: 0x{:x}, value: 0x{:x}, size: 0x{:x}, bind: 0x{:x}, type: 0x{:x}, other: 0x{:x}, shndx: 0x{:x}".format(self.name, self.value, self.size, self.bind, self.type, self.other, self.shndx)

class SymbolTableEntry32(SymbolTableEntry):
  elf_sizes = ELFSizes(elf64=False)

  def __init__(self, data, le=True):
    if len(data) != self.size():
      raise ParseException("Invalid length.")
    unpack_fmt = ELFSizes.unpack_fmt(le, self.size_list())
    self.name, self.value, self.size, self.info, self.other, self.shndx = struct.unpack(unpack_fmt, data)
    self.bind = self.info >> 4
    self.type = self.info & 0xf

  @staticmethod
  def size_list():
    elf_sizes = SymbolTableEntry32.elf_sizes
    ret = []
    ret.append(elf_sizes.word_sz)
    ret.append(elf_sizes.addr_sz)
    ret.append(elf_sizes.word_sz)
    ret.append(1)
    ret.append(1)
    ret.append(elf_sizes.half_sz)
    return ret

  @staticmethod
  def size():
    return sum(SymbolTableEntry32.size_list())

class SymbolTableEntry64(SymbolTableEntry):
  elf_sizes = ELFSizes(elf64=True)

  def __init__(self, data, le=True):
    if len(data) != self.size():
      raise ParseException("Invalid length.")
    unpack_fmt = ELFSizes.unpack_fmt(le, self.size_list())
    self.name, self.info, self.other, self.shndx, self.value, self.size = struct.unpack(unpack_fmt, data)
    self.bind = self.info >> 4
    self.type = self.info & 0xf

  @staticmethod
  def size_list():
    elf_sizes = SymbolTableEntry64.elf_sizes
    ret = []
    ret.append(elf_sizes.word_sz)
    ret.append(1)
    ret.append(1)
    ret.append(elf_sizes.half_sz)
    ret.append(elf_sizes.addr_sz)
    ret.append(elf_sizes.xword_sz)
    return ret

  @staticmethod
  def size():
    return sum(SymbolTableEntry64.size_list())

class ELFHeader(object):
  MAGIC = "\x7fELF"

  def __init__(self, addr, reader):
    if reader.read(addr, 4) != self.MAGIC:
      raise ParseException("Invalid magic bytes.")
    addr += 4

    elf64 = reader.read(addr, 1)
    if elf64 not in ["\x01","\x02"]:
      raise ParseException("Invalid format (32/64).")
    self.elf64 = elf64 == "\x02"
    addr += 1

    endianness = reader.read(addr, 1)
    if endianness not in ["\x01","\x02"]:
      raise ParseException("Invalid endianness field.")
    self.le = endianness == "\x01"
    addr += 1

    #skip until entry point
    addr += 18

    self.sizes = ELFSizes(self.elf64)

    #skip entry point
    addr += self.sizes.addr_sz

    prog_hdr_off = reader.read(addr, self.sizes.addr_sz)
    self.prog_hdr_off = struct.unpack(ELFSizes.unpack_fmt(self.le, self.sizes.addr_sz), prog_hdr_off)[0]
    addr += self.sizes.addr_sz

    #skip section header offset
    addr += self.sizes.addr_sz

    #skip flags
    addr += 4

    #skip elf header size
    addr += 2

    prog_hdr_sz = reader.read(addr, 2)
    self.prog_hdr_sz = struct.unpack(ELFSizes.unpack_fmt(self.le, 2), prog_hdr_sz)[0]
    assert self.prog_hdr_sz == 2*4 + 6*self.sizes.addr_sz
    addr += 2

    prog_hdr_cnt = reader.read(addr, 2)
    self.prog_hdr_cnt = struct.unpack(ELFSizes.unpack_fmt(self.le, 2), prog_hdr_cnt)[0]
    addr += 2

class ProgramHeader(object):
  LOAD = 1
  DYNAMIC = 2

class ProgramHeader32(ProgramHeader):
  def __init__(self, reader):
    self.type, self.offset, self.vaddr, self.f_size = reader([(0,4),(4,4),(8,4),(16,4)])

class ProgramHeader64(ProgramHeader):
  def __init__(self, reader):
    self.type, self.offset, self.vaddr, self.f_size = reader([(0,4),(8,8),(16,8),(32,8)])

class DynamicEntry(object):
  HASH = 4
  STRTAB = 5
  SYMTAB = 6

class DynamicEntry32(DynamicEntry):
  def __init__(self, reader):
    addr_sz = ELFSizes(False).addr_sz
    self.size = 2*addr_sz
    self.tag, self.val = reader([(0, addr_sz), (addr_sz, addr_sz)])

class DynamicEntry64(DynamicEntry):
  def __init__(self, reader):
    addr_sz = ELFSizes(True).addr_sz
    self.size = 2*addr_sz
    self.tag, self.val = reader([(0, addr_sz), (addr_sz, addr_sz)])

class MemoryELF(object):
  def __init__(self, reader, some_addr, page_sz=4096):
    self._reader = reader
    self._some_addr = some_addr

    #set self.base and self.header
    self._find_base(some_addr, page_sz)

    self._dynstr_addr = None
    self._dynsym_addr = None
    self._dynamic_sec_addr = None
    self._base_vaddr = None

  def _read_values(self, addr, offsets):
    ret = []
    for offset in offsets:
      read = self._reader.read(addr+offset[0], offset[1])
      ret.append(struct.unpack(self.header.sizes.unpack_fmt(self.header.le, offset[1]), read)[0])
    return ret

  def _find_base(self, some_addr, page_sz)
    page_start = self._some_addr - (self._some_addr % self._page_sz)

    while page_start >= 0:
      try:
        self.header = ELFHeader(page_start, self._reader)
        self.base = page_start
        return
      except (ReadException, ParseException):
        pass
      page_start -= self._page_sz

    raise Exception("ELF start not found!")

  def _parse_dynamic_section(self):
    DynamicEntryClass = DynamicEntry64 if self.header.elf64 else DynamicEntry32
    addr = self.dynamic_sec_addr
    while True:
      entry = DynamicEntryClass(lambda x: self._read_values(addr, x))
      addr += entry.size
      if entry.tag == 0:
        break
      elif entry.tag == DynamicEntry.HASH:
        self._hash_addr = self.base + entry.val - self.base_vaddr
      elif entry.tag == DynamicEntry.STRTAB:
        self._dynstr_addr = self.base + entry.val - self.base_vaddr
      elif entry.tag == DynamicEntry.SYMTAB:
        self._dynsym_addr = self.base + entry.val - self.base_vaddr

  @property
  def dynamic_sec_addr(self):
    if self._dynamic_sec_addr != None:
      return self._dynamic_sec_addr

    self._parse_program_headers()

    assert self._dynamic_sec_addr != None
    return self._dynamic_sec_addr

  @property
  def base_vaddr(self):
    if self._base_vaddr != None:
      return self._base_vaddr

    self._parse_program_headers()

    assert self._base_vaddr != None
    return self._base_vaddr

  def _parse_program_headers(self):
    ProgramHeaderClass = ProgramHeader64 if self.header.elf64 else ProgramHeader32
    load_segments = []
    dynamic = None
    for i in range(self.header.prog_hdr_cnt):
      prog_hdr_addr = self.base + self.header.prog_hdr_off + i*self.header.prog_hdr_sz
      hdr = ProgramHeaderClass(lambda x: self._read_values(prog_hdr_addr, x))
      if hdr.type == ProgramHeader.LOAD:
        if hdr.offset == 0:
          self._base_vaddr = hdr.vaddr
        else:
          load_segments.append(hdr)
      elif hdr.type == ProgramHeader.DYNAMIC:
        dynamic = hdr

    for segment in load_segments:
      if segment.offset <= dynamic.offset < segment.offset + segment.f_size:
        self._dynamic_sec_addr = self.base + (segment.vaddr - self._base_vaddr) + (dynamic.offset - segment.offset)
        return self._dynamic_sec_addr

    assert False

  @property
  def dynstr_addr(self):
    if self._dynstr_addr != None:
      return self._dynstr_addr

    self._parse_dynamic_section()

    assert self._dynstr_addr != None
    return self._dynstr_addr

  @property
  def dynsym_addr(self):
    if self._dynsym_addr != None:
      return self._dynsym_addr

    self._parse_dynamic_section()

    assert self._dynsym_addr != None
    return self._dynsym_addr

  @property
  def hash_addr(self):
    if self._hash_addr != None:
      return self._hash_addr

    self._parse_dynamic_section()

    assert self._hash_addr != None
    return self._hash_addr

  def _iterate_hashes(self, hash):
    nbucket, nchain = self._read_values(self.hash_addr, [(0,4), (4,4)])
    bucket_addr = self.hash_addr + 2*4
    chain_addr = bucket_addr + nbucket*4

    bucket_index = hash%nbucket
    index = self._read_values(bucket_addr+bucket_index*4, [(0,4)])[0]
    while index != 0:
      yield index
      index = self._read_values(chain_addr+index*4, [(0,4)])[0]

  def find_symbol(self, name):
    SymbolTableEntryClass = SymbolTableEntry64 if self.header.elf64 else SymbolTableEntry32
    sym_tbl_entry_sz = SymbolTableEntryClass.size()
    def elf_hash(name):
        h = 0
        for c in name:
          h = ((h << 4) + ord(c)) % 2**32;
          g = h & 0xf0000000
          if g != 0:
            h ^= g >> 24
          h &= (~g) % 2**32
        return h
    for i in self._iterate_hashes(elf_hash(name)):
      sym_tbl_entry = SymbolTableEntryClass(self._reader.read(self.dynsym_addr+i*sym_tbl_entry_sz, sym_tbl_entry_sz), self.header.le)
      sym_name = self._reader.read_until(self.dynstr_addr+sym_tbl_entry.name, "\x00")[:-1]
      if sym_name == name:
        return sym_tbl_entry.value
    assert False

