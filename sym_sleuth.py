#!/usr/bin/env python

import struct
import string
import re
from reader import Reader, ArrayBufferedReader

class ParseException(Exception):
  def __init_(self, msg):
    super(ParseException, self).__init__(msg)

class ReadException(Exception):
  def __init_(self, msg):
    super(ReadException, self).__init__(msg)

#TODO charset could be chosen smaller
DYNSTR_PRINTABLE = string.printable

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

  def is_valid(self, max_symstr_sz=2**16, max_sym_sz=2**16):
    if self.name > max_symstr_sz:
      return False
    #if self.value == 0:
    #  return False
    if self.size > max_sym_sz:
      return False
    #if self.bind not in [0,1,2,13,14,15]:
    #  return False
    if self.other != 0:
      return False
    #if self.type not in [0,1,2,3,4,13,14,15]:
    #  return False
    #TODO check shndx
    return True

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

  def is_valid(self, max_symstr_sz=2**16, max_sym_sz=2**16):
    if self.name > max_symstr_sz:
      return False
    #if self.value == 0:
    #  return False
    if self.size > max_sym_sz:
      return False
    #if self.bind not in [0,1,2,10,11,12,13,14,15]:
    #  return False
    if self.other != 0:
      return False
    #if self.type not in [0,1,2,3,4,10,11,12,13,14,15]:
    #  return False
    #TODO check shndx
    if self.type == 4: #STT_FILE
      if self.bind != 0 or self.shndx != 0xfff1: #STB_LOCAL / SHN_ABS
        return False
    return True

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
  def __init__(self, addr, elf_header, reader):
    if elf_header.elf64:
      off_off = 8
      vaddr_off = 16
      f_sz_off = 32
    else:
      off_off = 4
      vaddr_off = 8
      f_sz_off = 16

    addr_sz = elf_header.sizes.addr_sz

    type = reader.read(addr, 4)
    self.type = struct.unpack(elf_header.sizes.unpack_fmt(elf_header.le, 4), type)[0]

    offset = reader.read(addr+off_off, addr_sz)
    self.offset = struct.unpack(elf_header.sizes.unpack_fmt(elf_header.le, addr_sz), offset)[0]

    vaddr = reader.read(addr+vaddr_off, addr_sz)
    self.vaddr = struct.unpack(elf_header.sizes.unpack_fmt(elf_header.le, addr_sz), vaddr)[0]

    f_size = reader.read(addr+f_sz_off, addr_sz)
    self.f_size = struct.unpack(elf_header.sizes.unpack_fmt(elf_header.le, addr_sz), f_size)[0]

class DynamicEntry(object):
  HASH = 4
  STRTAB = 5
  SYMTAB = 6
  def __init__(self, addr, elf_header, reader):
    addr_sz = elf_header.sizes.addr_sz
    self.size = 2*addr_sz
    tag = reader.read(addr, addr_sz)
    self.tag = struct.unpack(elf_header.sizes.unpack_fmt(elf_header.le, addr_sz), tag)[0]
    val = reader.read(addr+addr_sz, addr_sz)
    self.val = struct.unpack(elf_header.sizes.unpack_fmt(elf_header.le, addr_sz), val)[0]

class MemoryELF(object):
  def __init__(self, read_callback, some_addr, page_sz=4096):
    self._reader = Reader(read_callback)
    #store the callback to switch readers later
    self._read_cb = read_callback
    self._page_sz = page_sz
    self._some_addr = some_addr

    self._base = None
    self._header = None
    self._dynstr_addr = None
    self._dynsym_addr = None
    self._dynamic_sec_addr = None
    self._base_vaddr = None

  @property
  def header(self):
    if self._header != None:
      return self._header
    self._header = ELFHeader(self.base, self._reader)
    return self._header

  @property
  def base(self):
    if self._base != None:
      return self._base

    page_start = self._some_addr - (self._some_addr % self._page_sz)

    while True:
      try:
        page_data = self._reader.read(page_start, len(ELFHeader.MAGIC))
        if page_data == ELFHeader.MAGIC:
          self._base = page_start
          #do this for a header sanity check as long as big endian is not implemented
          header = self.header
          #switch to a more efficient reader implementation
          self._reader = ArrayBufferedReader(self._read_cb, self._base)
          return self._base
      except ReadException:
        pass
      page_start -= self._page_sz
      if page_start < 0:
        raise Exception("ELF start not found!")

  def _parse_dynamic_section(self):
    addr = self.dynamic_sec_addr
    while True:
      entry = DynamicEntry(addr, self.header, self._reader)
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
    load_segments = []
    dynamic = None
    for i in range(self.header.prog_hdr_cnt):
      prog_hdr_addr = self.base + self.header.prog_hdr_off + i*self.header.prog_hdr_sz
      hdr = ProgramHeader(prog_hdr_addr, self.header, self._reader)
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

  def iterate_symbols(self):
    SymbolTableEntryClass = SymbolTableEntry64 if self.header.elf64 else SymbolTableEntry32
    sym_tbl_entry_sz = SymbolTableEntryClass.size()

    sym_tbl_addr = self.dynsym_addr
    while True:
      sym_tbl_addr += sym_tbl_entry_sz
      try:
        sym_tbl_entry = SymbolTableEntryClass(self._reader.read(sym_tbl_addr, sym_tbl_entry_sz), self.header.le)
      except ReadException, ParseException:
        return
      if not sym_tbl_entry.is_valid():
        return
      yield (sym_tbl_entry.value, self._reader.read_until(self.dynstr_addr+sym_tbl_entry.name, "\x00")[:-1])

  def find_symbol(self, name, regex=False):
    for addr, sym in self.iterate_symbols():
      if regex and re.match(name, sym) != None:
          return (addr, sym)
      elif not regex and name == sym:
        return (addr, sym)

