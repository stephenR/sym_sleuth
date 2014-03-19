#!/usr/bin/env python

class ReadException(Exception):
  def __init_(self, msg):
    super(ReadException, self).__init__(msg)

class Reader(object):
  def __init__(self, read_callback):
    self._read_cb = read_callback
  def read(self, offset, count):
    return self._read_cb(offset, count)
  def read_until(self, offset, c):
    ret = ""
    next = ""
    while next != c:
      next = self.read(offset, 1)
      offset += 1
      ret += next
    return ret

