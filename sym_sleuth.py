#!/usr/bin/env python

from reader import ReadException
from elf_parser import ELFParser, MagicByteException
import constants

class MemoryELF(object):
  def __init__(self, reader, some_addr, page_sz=4096):
    self._reader = reader

    self.base, self._parser = self._find_base_addr(some_addr, page_sz)
    self.header = self._parser.header

    self._parse_program_headers()
    self._parse_dynamic_section()

  def _find_base_addr(self, some_addr, page_sz):
    page_start = some_addr - (some_addr % page_sz)

    while page_start >= 0:
      try:
        return page_start, ELFParser(page_start, self._reader)
      except (ReadException, MagicByteException):
        pass
      page_start -= page_sz

    raise Exception("ELF start not found!")

  def _parse_program_headers(self):
    self.load_segments = []

    for hdr in self._parser.iterate_program_headers():
      if hdr.type == constants.ProgramHeader.LOAD:
        self.load_segments.append(hdr)
        if hdr.offset == 0:
          self.base_vaddr = hdr.vaddr
      elif hdr.type == constants.ProgramHeader.DYNAMIC:
        dynamic = hdr

    for segment in self.load_segments:
      if segment.offset <= dynamic.offset < segment.offset + segment.f_size:
        self.dynamic_sec_addr = self.base + (segment.vaddr - self.base_vaddr) + (dynamic.offset - segment.offset)

  def _parse_dynamic_section(self):
    for entry in self._parser.iterate_dynamic_section(self.dynamic_sec_addr):
      if entry.tag == constants.DynamicEntry.HASH:
        self.hash_addr = self.base + entry.val - self.base_vaddr
      elif entry.tag == constants.DynamicEntry.STRTAB:
        self.dynstr_addr = self.base + entry.val - self.base_vaddr
      elif entry.tag == constants.DynamicEntry.SYMTAB:
        self.dynsym_addr = self.base + entry.val - self.base_vaddr

  def find_symbol(self, name):
    def elf_hash(name):
        h = 0
        for c in name:
          h = ((h << 4) + ord(c)) % 2**32;
          g = h & 0xf0000000
          if g != 0:
            h ^= g >> 24
          h &= (~g) % 2**32
        return h
    for i in self._parser.iterate_hash_section(self.hash_addr, elf_hash(name)):
      if self._parser.is_symbol(self.dynsym_addr, self.dynstr_addr, i, name):
        sym = self._parser.get_symbol(self.dynsym_addr, i)
        return sym.value
    return None

