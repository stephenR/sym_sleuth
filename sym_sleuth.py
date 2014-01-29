#!/usr/bin/env python

import struct
import string

#TODO Big endian

class ReadException(Exception):
  def __init_(self, msg):
    super(ReadException, self).__init__(msg)

class ParseException(Exception):
  def __init_(self, msg):
    super(ParseException, self).__init__(msg)

class RandomAccessBufferedReader(object):
  def __init__(self, read_callback, buf_size = 65536):
    self._read_cb = read_callback
    self._buf_size = buf_size
  def read(self, offset, count):
    #TODO implement
    return self._read_cb(offset, count)
  def read_until(self, offset, c):
    ret = ""
    next = ""
    while next != c:
      next = self.read(offset, 1)
      offset += 1
      ret += next
    return ret

ELF_MAGIC = "\x7fELF"

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
    if self.bind not in [0,1,2,13,14,15]:
      return False
    if self.other != 0:
      return False
    if self.type not in [0,1,2,3,4,13,14,15]:
      return False
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
    if self.bind not in [0,1,2,10,11,12,13,14,15]:
      return False
    if self.other != 0:
      return False
    if self.type not in [0,1,2,3,4,10,11,12,13,14,15]:
      return False
    #TODO check shndx
    if self.type == 4: #STT_FILE
      if self.bind != 0 or self.shndx != 0xfff1: #STB_LOCAL / SHN_ABS
        return False
    return True

class MemoryELF(object):
  def __init__(self, read_callback, some_addr, elf64=True, page_sz=4096, sym_tbl_accept_sz=10, dynstr_accept_sz=10):
    self._reader = RandomAccessBufferedReader(read_callback)
    self._page_sz = page_sz
    self._some_addr = some_addr
    self._sym_tbl_accept_sz = sym_tbl_accept_sz
    self._dynstr_accept_sz = sym_tbl_accept_sz

    self._base = None
    self._dynstr_addr = None
    self._dynsym_addr = None

    self._elf64 = elf64

  @property
  def base(self):
    if self._base != None:
      return self._base

    page_start = self._some_addr - (self._some_addr % self._page_sz)

    while True:
      try:
        page_data = self._reader.read(page_start, len(ELF_MAGIC))
        if page_data == ELF_MAGIC:
          self._base = page_start
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
      #find first null byte
      if self._reader.read(dynstr_base, 1) != "\x00":
        dynstr_base += 1
        continue

      str_cnt = 0
      strlen = 0
      check_addr = dynstr_base + 1
      while True:
        next_byte = self._reader.read(check_addr, 1)
        #TODO charset could be chosen smaller
        if next_byte in string.printable:
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


    SymbolTableEntryClass = SymbolTableEntry64 if self._elf64 else SymbolTableEntry32

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

if __name__ == "__main__":
  mem_dump = open("ls.libc.bin", "r").read()

  FAIL_MIN = 1794047
  FAIL_MAX = FAIL_MIN + 2097151 - 1

  def read_cb(addr, sz):
    if FAIL_MIN <= addr <= FAIL_MAX or addr >= len(mem_dump):
      raise ReadException("fail")

    ret = ""
    while sz > 0:
      if FAIL_MIN <= addr <= FAIL_MAX or addr >= len(mem_dump):
        break
      ret += mem_dump[addr]
      addr += 1
      sz -= 1
    return ret

  elf = MemoryELF(read_cb, FAIL_MAX + 20)
  print "base: 0x{:x}".format(elf.base)
  print "dynstr: 0x{:x}".format(elf.dynstr_addr)
  print "dynsym: 0x{:x}".format(elf.dynsym_addr)
