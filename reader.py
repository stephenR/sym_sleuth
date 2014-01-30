#!/usr/bin/env python

from memoizer import memoize
from array import array

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

class MemoizedReader(Reader):
  def __init__(self, read_callback):
    super(MemoizedReader, self).__init__(read_callback)

  @memoize
  def read(self, offset, count):
    return self._read_cb(offset, count)

class BufferArray(object):
  def __init__(self, offset, size):
    self._offset = offset
    self._size = size
    def null_iterator(size, type):
      for i in xrange(size):
        if type == "c":
          yield "\x00"
        elif type == "B":
          yield 0
        else:
          #not implemented
          assert False
    self._mem = array("c", null_iterator(size, "c"))
    self._avail = array("B", null_iterator(size, "B"))

  def __getitem__(self, index):
    index = index - self._offset
    if not 0 <= index < self._size:
      return None
    if self._avail[index] == 0:
      return None
    return self._mem[index]

  def __setitem__(self, index, c):
    index = index - self._offset
    if not 0 <= index < self._size:
      return
    self._avail[index] = 1
    self._mem[index] = c

  def set_range(self, index, data):
    for c in data:
      self[index] = c
      index += 1


class ArrayBufferedReader(Reader):
  #TODO support multiple array_offsets for multiple sections
  def __init__(self, read_callback, array_offset, size=2**20):
    super(ArrayBufferedReader, self).__init__(read_callback)
    self._mem = BufferArray(array_offset, size)

  def read(self, offset, count):
    ret = ""
    while len(ret) < count:
      data = self._mem[offset]
      if data == None:
        data = self._read_cb(offset, 1)
        self._mem.set_range(offset, data)
      ret += data
      offset += len(data)
    return ret[:count]

