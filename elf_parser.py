#!?usr/bin/env python

import struct

class ParseException(Exception):
  def __init_(self, msg):
    super(ParseException, self).__init__(msg)

class MagicByteException(ParseException):
  def __init_(self, msg):
    super(MagicByteException, self).__init__(msg)

class ELFSizes(object):
  def __init__(self, elf64):
    self.half_sz=2
    self.word_sz=4
    if elf64:
      self.addr_sz=8
      self.xword_sz=8
    else:
      self.addr_sz=4

class ELFHeader(object):
  __slots__ = ["elf64", "le", "prog_hdr_off", "prog_hdr_sz", "prog_hdr_cnt"]

class ProgramHeader(object):
  __slots__ = ["type", "offset", "vaddr", "f_size"]

class DynamicEntry(object):
  __slots__ = ["tag", "val"]

class SymbolTableEntry(object):
  __slots__ = ["name", "value"]

class ELFParser(object):
  def __init__(self, addr, reader):
    self._reader = reader
    self._base = addr
    self._parse_header(addr)

  def _read_int(self, addr, size):
    ret = self._reader.read(addr, size)
    fmt = "<" if self.header.le else ">"
    if size == 8:
      fmt += "Q"
    elif size == 4:
      fmt += "I"
    elif size == 2:
      fmt += "H"
    elif size == 1:
      fmt += "B"
    else:
      assert False
    return struct.unpack(fmt, ret)[0]

  def _parse_header(self, addr):
    MAGIC = "\x7fELF"

    self.header = ELFHeader()

    if not self._reader.equal(addr, MAGIC):
      raise MagicByteException("Invalid magic bytes.")
    addr += 4

    elf64 = self._reader.read(addr, 1)
    if elf64 not in ["\x01","\x02"]:
      raise ParseException("Invalid format (32/64).")
    self.header.elf64 = elf64 == "\x02"
    addr += 1

    self.sizes = ELFSizes(self.header.elf64)

    endianness = self._reader.read(addr, 1)
    if endianness not in ["\x01","\x02"]:
      raise ParseException("Invalid endianness field.")
    self.header.le = endianness == "\x01"
    addr += 1

    #skip until entry point
    addr += 18

    #skip entry point
    addr += self.sizes.addr_sz

    self.header.prog_hdr_off = self._read_int(addr, self.sizes.addr_sz)
    addr += self.sizes.addr_sz

    #skip section header offset
    addr += self.sizes.addr_sz

    #skip flags
    addr += 4

    #skip elf header size
    addr += 2

    self.header.prog_hdr_sz = self._read_int(addr, 2)
    assert self.header.prog_hdr_sz == 2*4 + 6*self.sizes.addr_sz
    addr += 2

    self.header.prog_hdr_cnt = self._read_int(addr, 2)
    addr += 2

  def iterate_program_headers(self):
    addr = self._base + self.header.prog_hdr_off
    addr_sz = self.sizes.addr_sz

    for i in xrange(self.header.prog_hdr_cnt):
      hdr = ProgramHeader()
      hdr.type = self._read_int(addr, 4)
      hdr.offset = self._read_int(addr+addr_sz, addr_sz)
      hdr.vaddr = self._read_int(addr+2*addr_sz, addr_sz)
      hdr.f_size = self._read_int(addr+4*addr_sz, addr_sz)
      yield hdr
      addr += self.header.prog_hdr_sz

  def iterate_dynamic_section(self, addr):
    addr_sz = self.sizes.addr_sz
    while True:
      entry = DynamicEntry()
      entry.tag = self._read_int(addr, addr_sz)
      if entry.tag == 0:
        return
      addr += addr_sz
      entry.val = self._read_int(addr, addr_sz)
      addr += addr_sz
      yield entry

  def iterate_hash_section(self, addr, hash):
    nbucket = self._read_int(addr, 4)
    nchain = self._read_int(addr+4, 4)
    bucket_addr = addr+2*4
    chain_addr = bucket_addr + nbucket*4

    bucket_index = hash%nbucket
    index = self._read_int(bucket_addr+bucket_index*4, 4)
    while index != 0:
      yield index
      index = self._read_int(chain_addr+index*4, 4)

  def is_symbol(self, dynsym_addr, dynstr_addr, i, name):
    sym = self.get_symbol(dynsym_addr, i)
    return self._reader.equal(dynstr_addr+sym.name, name)

  def get_symbol(self, dynsym_addr, i):
    sym = SymbolTableEntry()
    if self.header.elf64:
      entry_size = 4 + 1 + 1 + 2 + 8 + 8
      value_offset = 4 + 1 + 1 + 2
    else:
      entry_size = 4 + 4 + 4 + 1 + 1 + 2
      value_offset = 4
    addr = dynsym_addr + i*entry_size
    sym.name = self._read_int(addr, 4)
    sym.value = self._read_int(addr+value_offset, self.sizes.addr_sz)
    return sym

