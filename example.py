#!/usr/bin/env python

from sym_sleuth import MemoryELF, ReadException

if __name__ == "__main__":
  mem_dump = open("ls.libc.bin", "r").read()

  FAIL_MIN = 1794047
  FAIL_MAX = FAIL_MIN + 2097151 - 1

  total_read = 0

  def read_cb(addr, sz):
    if FAIL_MIN <= addr <= FAIL_MAX or addr >= len(mem_dump):
      raise ReadException("fail")

    global total_read

    ret = ""
    while sz > 0:
      if FAIL_MIN <= addr <= FAIL_MAX or addr >= len(mem_dump):
        break
      ret += mem_dump[addr]
      addr += 1
      sz -= 1
    total_read += len(ret)
    return ret

  elf = MemoryELF(read_cb, FAIL_MAX + 20)
  print "base: 0x{:x}".format(elf.base)
  print "dynstr: 0x{:x}".format(elf.dynstr_addr)
  print "dynsym: 0x{:x}".format(elf.dynsym_addr)

  print "total_read", total_read

  system_addr, _ =  elf.find_symbol("system")
  print "system: 0x{:x}".format(system_addr)

  print "total_read", total_read

  print "symbols:"
  for addr, name in elf.iterate_symbols():
    print "{}: 0x{:x}".format(name, addr)

  print "total_read", total_read

