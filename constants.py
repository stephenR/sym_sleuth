#!/usr/bin/env python

def enum(**enums):
  return type('Enum', (), enums)

ProgramHeader = enum(LOAD=1, DYNAMIC=2)
DynamicEntry = enum(HASH = 4, STRTAB = 5, SYMTAB = 6)

