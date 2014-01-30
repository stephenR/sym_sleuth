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
  def unpack_fmt(sz):
    if sz == 8:
      return "Q"
    if sz == 4:
      return "I"
    if sz == 2:
      return "H"
    if sz == 1:
      return "B"
    assert False

class SymbolTableEntry(object):
  def __str__(self):
        return "name: 0x{:x}, value: 0x{:x}, size: 0x{:x}, bind: 0x{:x}, type: 0x{:x}, other: 0x{:x}, shndx: 0x{:x}".format(self.name, self.value, self.size, self.bind, self.type, self.other, self.shndx)

class SymbolTableEntry32(SymbolTableEntry):
  elf_sizes = ELFSizes(elf64=False)

  def __init__(self, data):
    if len(data) != self.size():
      raise ParseException("Invalid length.")
    unpack_fmt = "<"
    for sz in self.size_list():
      unpack_fmt += ELFSizes.unpack_fmt(sz)
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

  def __init__(self, data):
    if len(data) != self.size():
      raise ParseException("Invalid length.")
    unpack_fmt = "<"
    for sz in self.size_list():
      unpack_fmt += ELFSizes.unpack_fmt(sz)
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
    #TODO Big endian
    assert(self.le == True)

class MemoryELF(object):
  def __init__(self, read_callback, some_addr, page_sz=4096, sym_tbl_accept_sz=10, dynstr_accept_sz=10, dynstr_min_sz=256):
    self._reader = Reader(read_callback)
    #store the callback to switch readers later
    self._read_cb = read_callback
    self._page_sz = page_sz
    self._some_addr = some_addr
    self._sym_tbl_accept_sz = sym_tbl_accept_sz
    self._dynstr_accept_sz = sym_tbl_accept_sz
    self._dynstr_min_sz = dynstr_min_sz

    self._base = None
    self._header = None
    self._dynstr_addr = None
    self._dynsym_addr = None

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

  @property
  def dynstr_addr(self):
    if self._dynstr_addr != None:
      return self._dynstr_addr

    dynstr_base = self.base

    while True:
      #skip block if there is no valid byte using the minimal size as offset
      if self._reader.read(dynstr_base+self._dynstr_min_sz, 1) not in DYNSTR_PRINTABLE + "\x00":
        dynstr_base += self._dynstr_min_sz + 1
        continue
      #find first null byte
      if self._reader.read(dynstr_base, 1) != "\x00":
        dynstr_base += 1
        continue

      str_cnt = 0
      strlen = 0
      check_addr = dynstr_base + 1
      while True:
        next_byte = self._reader.read(check_addr, 1)
        if next_byte in DYNSTR_PRINTABLE:
          strlen += 1
        elif next_byte == "\x00":
          if strlen == 0:
            str_cnt = 0
            dynstr_base = check_addr
          else:
            strlen = 0
            str_cnt += 1
            if str_cnt == self._dynstr_accept_sz:
              self._dynstr_addr = dynstr_base
              return dynstr_base
        else:
          #we have to look for the first null byte again
          dynstr_base = check_addr + 1
          break
        check_addr += 1

  @property
  def dynsym_addr(self):
    if self._dynsym_addr != None:
      return self._dynsym_addr


    SymbolTableEntryClass = SymbolTableEntry64 if self.header.elf64 else SymbolTableEntry32

    sym_tbl_entry_sz = SymbolTableEntryClass.size()

    check_addr_coarse = self.base + sym_tbl_entry_sz -1

    while True:
      for check_addr in range(check_addr_coarse, check_addr_coarse-sym_tbl_entry_sz, -1):
        if self._reader.read(check_addr, 1) != "\x00":
          break
        if self._reader.read(check_addr, sym_tbl_entry_sz) == "\x00"*sym_tbl_entry_sz:
          for sym_tbl_off in range(self._sym_tbl_accept_sz):
            entry_data = self._reader.read(check_addr+(sym_tbl_off+1)*sym_tbl_entry_sz, sym_tbl_entry_sz)
            try:
              sym_tbl_entry = SymbolTableEntryClass(entry_data)
              if not sym_tbl_entry.is_valid():
                break
            except ParseException as e:
              break
            if sym_tbl_off == self._sym_tbl_accept_sz-1:
              return check_addr
      check_addr_coarse += sym_tbl_entry_sz
    return self._dynsym_addr

  def iterate_symbols(self):
    SymbolTableEntryClass = SymbolTableEntry64 if self.header.elf64 else SymbolTableEntry32
    sym_tbl_entry_sz = SymbolTableEntryClass.size()

    sym_tbl_addr = self.dynsym_addr
    while True:
      sym_tbl_addr += sym_tbl_entry_sz
      try:
        sym_tbl_entry = SymbolTableEntryClass(self._reader.read(sym_tbl_addr, sym_tbl_entry_sz))
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

