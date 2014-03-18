#!/usr/bin/env python

from sym_sleuth import MemoryELF, ReadException

if __name__ == "__main__":
  mem_areas = [open("libc.mem{}".format(i), "r").read() for i in range(1,4)]

  total_read = 0

  def read_cb(addr, sz):
    if 0x38dbc00000 <= addr < 0x38dbdb6000:
      mem = mem_areas[0]
      addr -= 0x38dbc00000
    elif 0x38dbfb6000 <= addr < 0x38dbfba000:
      mem = mem_areas[1]
      addr -= 0x38dbfb6000
    elif 0x38dbfba000 <= addr < 0x38dbfbc000:
      mem = mem_areas[2]
      addr -= 0x38dbfba000
    else:
      raise ReadException("fail")

    global total_read

    ret = ""
    while sz > 0:
      if addr >= len(mem):
        break
      ret += mem[addr]
      addr += 1
      sz -= 1
    total_read += len(ret)
    return ret

  elf = MemoryELF(read_cb, 0x38dbfba000 + 20)
  print "base: 0x{:x}".format(elf.base)
  print "dynstr: 0x{:x}".format(elf.dynstr_addr)
  print "dynsym: 0x{:x}".format(elf.dynsym_addr)

  print "total_read", total_read

  system_addr =  elf.find_symbol("system")
  print "system: 0x{:x}".format(system_addr)

  print "total_read", total_read

