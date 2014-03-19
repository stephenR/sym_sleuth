#!/usr/bin/env python

class ReadException(Exception):
  def __init_(self, msg):
    super(ReadException, self).__init__(msg)

class Reader(object):
  def __init__(self, read_callback):
    self._read_cb = read_callback
  def read(self, addr, count):
    return self._read_cb(addr, count)
  def read_until(self, addr, c):
    ret = ""
    next = ""
    while next != c:
      next = self.read(addr, 1)
      addr += 1
      ret += next
    return ret
  def equal(self, addr, s):
    return self.read(addr, len(s)) == s

