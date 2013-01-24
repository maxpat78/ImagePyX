# -*- coding: mbcs -*-

'''
WIMArchive.PY - Part of Super Simple WIM Manager
'''

VERSION = '0.22'

COPYRIGHT = '''Copyright (C)2012-2013, by maxpat78. GNU GPL v2 applies.
This free software creates MS WIM Archives WITH ABSOLUTELY NO WARRANTY!'''

import copy
import datetime
import hashlib
import logging
import os
import struct
import sys
import tempfile
import time
import uuid
from ctypes import *
from cStringIO import StringIO

# Helper functions
def class2str(c, s):
	"Enumera in tabella nomi e valori dal layout di una classe"
	keys = c._kv.keys()
	keys.sort()
	for key in keys:
		o = c._kv[key][0]
		v = getattr(c, o)
		if type(v) in (type(0), type(0L)):
			v = hex(v)
		s += '%x: %s = %s\n' % (key, o, v)
	return s

def common_getattr(c, name):
	"Decodifica e salva un attributo in base al layout di classe"
	i = c._vk[name]
	fmt = c._kv[i][1]
	cnt = struct.unpack_from(fmt, c._buf, i+c._i) [0]
	setattr(c, name,  cnt)
	return cnt

def nt2uxtime(t):
	"Converte data e ora dal formato NT a Python (Unix)"
	# NT: lassi di 100 nanosecondi dalla mezzonotte dell'1/1/1601
	# Unix: secondi dall' 1/1/1970
	# La differenza è di 134774 giorni o 11.644.473.600 secondi
	return datetime.datetime.utcfromtimestamp(t/10000000 - 11644473600)

def ux2nttime(t):
	"Converte data e ora dal formato Python (Unix) a NT"
	return int((t+11644473600L)*10000000L)

def print_progress(start_time, totalBytes, totalBytesToDo):
	pct_done = 100*float(totalBytes)/float(totalBytesToDo)
	avg_secs_remaining = (time.time() - start_time) / pct_done * 100 - (time.time() - start_time)
	sys.stdout.write('%.02f%% done, %s left\r' % (pct_done, datetime.timedelta(seconds=int(avg_secs_remaining))))

class XpressHuffCodec:
	"Performs XPRESS Huffman (de)compression with Windows 8 NTDLL"
	def __init__(self):
		CompressBufferWorkSpaceSize, CompressFragmentWorkSpaceSize = c_uint(), c_uint()
		windll.ntdll.RtlGetCompressionWorkSpaceSize(0x104, byref(CompressBufferWorkSpaceSize), byref(CompressFragmentWorkSpaceSize))
		self.workspace = max(CompressBufferWorkSpaceSize.value, CompressFragmentWorkSpaceSize.value)
		self.workspace = create_string_buffer(self.workspace)
	
	def compress(self, ins, cbins, outs, cbouts):
		comp_len = c_int()
		assert not windll.ntdll.RtlCompressBuffer(4, ins, cbins, outs, cbouts, 4096, byref(comp_len), self.workspace)
		return comp_len.value
		
	def decompress(self, ins, cbins, outs, cbouts):
		uncomp_len = c_int()
		# Warning! cbouts (output buffer size) MUST be equal to the expected output size!
		assert not windll.ntdll.RtlDecompressBufferEx(4, outs, cbouts, ins, cbins, byref(uncomp_len), self.workspace)
		return uncomp_len.value

def wim_is_clean(wim, fp):
	"Ensures there's no garbage after XML data"
	if wim.dwFlags & 0x40 and wim.rhXmlData.liOffset + wim.rhXmlData.ullSize < os.stat(fp.name):
		print "A previous WIM updating failed, restoring the original size..."
		logging.debug("Previous WIM updating failed, restoring the original size (%d bytes)", wim.rhXmlData.liOffset + wim.rhXmlData.ullSize)
		fp.truncate(wim.rhXmlData.liOffset + wim.rhXmlData.ullSize)

		
class BadWim(Exception):
	pass


# WIM Archive structures

class WIMHeader:
	layout = { # 0xD0 (208) bytes
	0x00: ('ImageTag', '8s'), # MSWIM
	0x08: ('cbSize', '<I'), # WIM Header size (0xD0)
	0x0C: ('dwVersion', '<I'), # 0x00010D00, 1.13
	0x10: ('dwFlags', '<I'), # 0x2 Compression is on   0x20000 XPRESS   0x40000 LZX
	0x14: ('dwCompressionSize', '<I'), # 0x8000 uncompressed block size, if compression is active (it states "Size of compressed WIM"... sic!)
	0x18: ('gWIMGuid', '16s'), # 128-bit GUID
	0x28: ('usPartNumber', '<H'), # unit number (1 if it isn't a spanned WIM)
	0x2A: ('usTotalParts', '<H'), # total units (1 if not spanned)
	0x2C: ('dwImageCount', '<I'), # disk images inside the WIM
	0x30: ('rhOffsetTable', '24s'), # Lookup table description
	0x48: ('rhXmlData', '24s'), # XML data table description
	0x60: ('rhBootMetadata', '24s'), # Boot metadata table description
	0x78: ('dwBootIndex', '<I'), # Index for the bootable image (0 if none)
	0x7C: ('rhIntegrity', '24s'), # Integrity table description
	0x94: ('bUnused', '60s')
	}
	
	def __init__(self, s=None):
		self.size = 208
		self._i = 0 # posizione nel buffer
		self._pos = 0 # posizione nel buffer
		self._buf = s
		self._kv = WIMHeader.layout.copy()
		self._vk = {} # { nome: offset}
		for k, v in self._kv.items():
			self._vk[v[0]] = k
		self.rhOffsetTable = DiskResHdr(self.rhOffsetTable)
		self.rhXmlData = DiskResHdr(self.rhXmlData)
		self.rhBootMetadata = DiskResHdr(self.rhBootMetadata)
		self.rhIntegrity = DiskResHdr(self.rhIntegrity)

	__getattr__ = common_getattr
	
	def __str__ (self):
		return class2str(self, "WIM Header @%x\n" % self._pos)

	def test(self):
		if self.ImageTag != 'MSWIM\0\0\0' or self.cbSize != 208:
			raise BadWim
		if self.dwFlags & 0x40:
			logging.debug("FLAG_HEADER_WRITE_IN_PROGRESS set, WIM wasn't properly closed!")
		
	def tostr (self):
		s = ''
		keys = self._kv.keys()
		keys.sort()
		wim = copy.copy(self)
		# Some objects need to be string-ified during string conversion ONLY
		wim.rhOffsetTable = wim.rhOffsetTable.tostr()
		wim.rhXmlData = wim.rhXmlData.tostr()
		wim.rhBootMetadata = wim.rhBootMetadata.tostr()
		wim.rhIntegrity = wim.rhIntegrity.tostr()
		for k in keys:
			v = wim._kv[k]
			s += struct.pack(v[1], getattr(wim, v[0]))
		return s


class SecurityData:
	"Security descriptors associated to file resources. We provide an empty one."
	layout = {
	0x00: ('dwTotalLength', '<I'), # length of the SD resource
	0x04: ('dwNumEntries', '<I'), # Array of QWORDs with variable-length security descriptors follows
	}

	def __init__(self, s):
		self._i = 0 # posizione nel buffer
		self._pos = 0 # posizione nel buffer
		self._buf = s
		self._kv = SecurityData.layout.copy()
		self._vk = {} # { nome: offset}
		for k, v in self._kv.items():
			self._vk[v[0]] = k
		self.size = self.dwTotalLength
		self.liEntries = []
		if self.dwNumEntries:
			for i in range(self.dwNumEntries):
				sd_size = struct.unpack('<Q', s[8+i*8:16+i*8])
				self.liEntries += [sd_size]
			for i in range(len(self.liEntries)):
				self.liEntries[i] = s[8+self.dwNumEntries*8]
		
	__getattr__ = common_getattr
	
	def __str__ (self):
		return class2str(self, "SecurityData @%x\n" % self._pos)

	def tostr (self):
		s = ''
		keys = self._kv.keys()
		keys.sort()
		for k in keys:
			v = self._kv[k]
			s += struct.pack(v[1], getattr(self, v[0]))
		return s

	
class DirEntry:
	"Represents a file or folder captured inside an image"
	layout = { # 0x66 bytes
	0x00: ('liLength', '<Q'), # Length of this DIRENTRY
	0x08: ('dwAttributes', '<I'), # DOS file attributes (0x20=DIR)
	0x0C: ('dwSecurityId', '<i'), # Security Descriptor (-1 if not used)
	0x10: ('liSubdirOffset', '<Q'), # Offset of folder's childs inside the Metadata resource, or 0 if it is a file. Empty folder points to the end NULL.
	0x18: ('liUnused1', '<Q'),
	0x20: ('liUnused2', '<Q'),
	0x28: ('liCreationTime', '<Q'),
	0x30: ('liLastAccessTime', '<Q'),
	0x38: ('liLastWriteTime', '<Q'),
	0x40: ('bHash', '20s'), # SHA-1 hash (uncompressed data): match it with those in the Offset table to find files
	0x54: ('dwReparseTag', '<I'),
	0x58: ('dwReparseReserved', '<I'),
	0x5C: ('dwHardLink', '<I'), # spec says QWORD!
	0x60: ('wStreams', '<H'), # number of alternate streams (NTFS) following the DIRENTRY
	0x62: ('wShortNameLength', '<H'), # length of the DOS short name (if provided)
	0x64: ('wFileNameLength', '<H') # (regular) file name length
	}
	# Unicode UTF-16-LE entry name follows, terminated by a Unicode NULL (not mentioned in spec, nor counted in wFileNameLength),
	# QWORD aligned (spec says DWORD)
	def __init__(self, s):
		self._i = 0 # posizione nel buffer
		self._pos = 0 # posizione nel buffer
		self._buf = s
		self._kv = DirEntry.layout.copy()
		self._vk = {} # { nome: offset}
		for k, v in self._kv.items():
			self._vk[v[0]] = k
		self.size = 0
		if self.wFileNameLength:
			self.FileName = (self._buf[0x66:0x66+self.wFileNameLength]).decode('utf-16le')
		else:
			self.FileName = ''
		self.RefCount = 1 # reference count
		
	__getattr__ = common_getattr
	
	def __str__ (self):
		return class2str(self, "DirEntry @%x\n" % self._pos) + '66: sFileName = %s' % self.FileName

	def tostr (self):
		s = ''
		keys = self._kv.keys()
		keys.sort()
		for k in keys:
			v = self._kv[k]
			s += struct.pack(v[1], getattr(self, v[0]))
		s += self.FileName
		return s + (self.liLength-len(s))*'\0'


class DiskResHdr:
	"Represents size, position and type of a resource inside the WIM file"
	layout = { # 0x18 (24) bytes
	0x00: ('ullSize', '<Q'), # compressed size (56 bits) + 8-bit Flags
	0x07: ('bFlags', 'B'), # bFlags -- 1=free 2=metadata 4=compressed 8=spanned
	0x08: ('liOffset', '<Q'), # offset
	0x10: ('liOriginalSize', '<Q') # original uncompressed size
	}
	
	def __init__(self, s=None):
		self.size = 24
		self._i = 0 # posizione nel buffer
		self._pos = 0 # posizione nel buffer
		self._buf = s
		self._kv = DiskResHdr.layout.copy()
		self._vk = {} # { nome: offset}
		for k, v in self._kv.items():
			self._vk[v[0]] = k
		self.ullSize = self.ullSize & 0x00FFFFFFFFFFFFFF

	__getattr__ = common_getattr
	
	def __str__ (self):
		return class2str(self, "DiskRes Header @%x\n" % self._pos)

	def tostr (self):
		s = ''
		keys = self._kv.keys()
		keys.sort()
		self.ullSize = self.ullSize | (self.bFlags << 56)
		for k in keys:
			if k == 7: continue
			v = self._kv[k]
			s += struct.pack(v[1], getattr(self, v[0]))
		self.ullSize = self.ullSize & 0x00FFFFFFFFFFFFFF
		return s


class OffsetTableEntry:
	"Represents position, type, sizes, reference count and SHA-1 hashes of captured resources"
	layout = { # 0x32 (50) bytes
	0x00: ('rhOffsetEntry', '24s'),
	0x18: ('usPartNumber', '<H'),
	0x1A: ('dwRefCount', '<I'), # SPECS SAY A WORD!
	0x1E: ('bHash', '20s') # SHA-1 hash (uncompressed data)
	}
	
	def __init__(self, s=None):
		self.size = 50
		self._i = 0 # posizione nel buffer
		self._pos = 0 # posizione nel buffer
		self._buf = s
		self._kv = OffsetTableEntry.layout.copy()
		self._vk = {} # { nome: offset}
		for k, v in self._kv.items():
			self._vk[v[0]] = k
		self.rhOffsetEntry = DiskResHdr(self.rhOffsetEntry)

	__getattr__ = common_getattr
	
	def __str__ (self):
		return class2str(self, "OffsetTable @%x\n" % self._pos)

	def tostr (self):
		s = ''
		keys = self._kv.keys()
		keys.sort()
		s += struct.pack(self._kv[0][1], getattr(self, self._kv[0][0]).tostr())
		for k in keys[1:]:
			v = self._kv[k]
			s += struct.pack(v[1], getattr(self, v[0]))
		return s


class IntegrityTable:
	"Optional inegrity table"
	layout = {
	0x00: ('cbSize', '<I'), # length of the table
	0x04: ('dwNumElements', '<I'), # Chunks number
	0x08: ('dwChunkSize', '<I') # fixed to 10 MiB
	}

	def __init__(self, s):
		self._i = 0 # posizione nel buffer
		self._pos = 0 # posizione nel buffer
		self._buf = s
		self._kv = IntegrityTable.layout.copy()
		self._vk = {} # { nome: offset}
		self.Entries = [] # SHA-1 chunk hashes
		for k, v in self._kv.items():
			self._vk[v[0]] = k
		if self.dwNumElements:
			for i in range(self.dwNumElements):
				j = 12+i*20
				self.Entries.append(s[j:j+20])

	__getattr__ = common_getattr
	
	def __str__ (self):
		return class2str(self, "Integrity Table @%x\n" % self._pos)

	def tostr (self):
		s = ''
		keys = self._kv.keys()
		keys.sort()
		for k in keys:
			v = self._kv[k]
			s += struct.pack(v[1], getattr(self, v[0]))
		for k in self.Entries:
			s += k
		return s


class InputStream:
	def __init__ (self, fp, size, csize, compressionType=0):
		self.fp = fp # input file
		self._pos = fp.tell() # compressed stream start offset
		self.sha1 = hashlib.sha1() # SHA-1 of the uncompressed input
		self.size = size # total uncompressed data size
		self.compressionType = compressionType # 0=none, 1=XPRESS, 2=LZX
		logging.debug("New InputStream %d/%d/%d", size, csize, compressionType)
		if compressionType: self.__init_comp(csize, compressionType)

	def read(self, size=None):
		if size < 1: return ''
		if size == None or size > self.size: # read all
			size = self.size
		if self.fp.tell() >= self._pos + self.size:
			return ''
		if self.fp.tell() + size >= self._pos + self.size:
			size = self._pos + self.size - self.fp.tell()
			logging.debug("size adjusted to %d bytes", size)
		s = self.fp.read(size)
		self.sha1.update(s)
		logging.debug("Read %d bytes of %d", len(s), size)
		return s

	def __init_comp(self, csize, compressionType):
		self._ibuf = '' # 32K input buffer
		self._obuf = create_string_buffer(32768+6144) # output buffer
		#~ self._obuf = create_string_buffer(32768*4) # output buffer
		self._blks = (self.size+32767)/32768 - 1# number of input/output blocks
		self._iblk = 0 # current input block index
		self._ipos = 0 # current input block offset
		self._opos = 0 # current output stream offset
		self.csize = csize # total compressed data size (with chunk pointers)
		if self.compressionType == 1:
			if sys.platform == 'win32':
				V = sys.getwindowsversion()
				if V.major >= 6 and V.minor >= 2:
					self.decompress = XpressHuffCodec().decompress
					logging.debug("Using RTL XPRESS Huffman decompressor")
				else:
					self.decompress = cdll.MSCompression.xpress_huff_decompress
					logging.debug("Using MSCompression XPRESS Huffman decompressor")
			#~ self.decompress = cdll.MSCompression.xpress_huff_decompress
		elif self.compressionType == 2:
			self.decompress = cdll.MSCompression.lzx_wim_decompress
		self.read = self.__read_comp
		
	def __read_comp(self, size=None): # TODO: QWORD if source > 4GiB, DWORD else
		if size == None: # read all
			size = self.size
		if size < 1: return ''

		i, todo = 0, size
		s = '' # temp output buffer
		while todo > 0:
			if self._iblk < self._blks: # the last pointer is computed from original size
				self.fp.seek(self._pos + self._iblk*4) # current pointer
				logging.debug("Read chunk pointer @%08X", self._pos + self._iblk*4)
				prev_cb = 0
				if self._iblk > 0:
					self.fp.seek(self._pos + self._iblk*4 - 4) # prev chunk pointer
					prev_cb = struct.unpack('<I', self.fp.read(4))[0]
				cb = struct.unpack('<I', self.fp.read(4))[0] - prev_cb
			else:
				cb = self.csize - self._blks*4 - self._ipos
				#~ print self._opos, self.size
			assert cb < 32769
			logging.debug("Bytes requested: %d", cb)
			self.fp.seek(self._pos + self._blks*4 + self._ipos) # current input block offset
			self._ibuf = self.fp.read(cb)
			self._ipos += cb # next chunk offset
			if cb == 32768 or cb == self.size - self._opos:
				s += self._ibuf
				self._opos += len(self._ibuf)
				logging.debug("Read uncompressed chunk %d/%d @%08X", self._iblk, self._blks, self._pos + self._blks*4 + self._ipos)
			elif 0 < cb < 32768 and cb != self.size - self._opos:
				residual_uncompressed_bytes = self.size - self._opos
				try:
					# Rtl decompressor requires a buffer size equal to the requested output size!
					cbo = self.decompress(self._ibuf, cb, self._obuf, (32768, residual_uncompressed_bytes)[residual_uncompressed_bytes < 32768])
					#~ cbo = self.decompress(self._ibuf, cb, self._obuf, 32768*4)
				except:
					cbo = -1
					logging.debug("FATAL: decompressor exception!")
				if not cbo:
					logging.debug("FATAL: zero bytes decompressed!")
				elif self._iblk < self._blks and cbo < 32768:
					logging.debug("FATAL: expanded non-last chunk <32768 bytes!")
				s += self._obuf[:cbo]
				self._opos += cbo
				logging.debug("Read compressed chunk %d/%d @%08X, size %d expanded to %d", self._iblk, self._blks, self._pos + self._blks*4 + self._ipos, cb, cbo)
			self._iblk += 1
			todo -= 32768
			i += 32768
		self.sha1.update(s)
		return s
		
	def start(self): return self._pos # compressed stream start offset

	def csize(self):
		if self.compressionType:
			logging.debug("Compressed input stream size: %d (%d%%)", self._blks*4 + self._ipos, -1*(100-(self._blks*4 + self._ipos)*100/self.size))
			return self._blks*4 + self._ipos # compressed stream size
		else:
			return self.size


class OutputStream:
	"Creates a file resource, both compressed or uncompressed, computing sizes and SHA-1 checksum"
	def __init__ (self, fp, size, compressionType=0, takeSHA=True):
		self.fp = fp # output file
		self._pos = fp.tell() # compressed stream start offset
		self.sha1 = hashlib.sha1() # SHA-1 of the uncompressed input
		self.takeSHA = takeSHA
		self.size = size # total uncompressed data size
		self.compressionType = compressionType # 0=none, 1=XPRESS, 2=LZX
		logging.debug("New OutputStream %d/%d", size, compressionType)
		if compressionType: self.__init_comp(compressionType)

	def write(self, s):
		if self.takeSHA: self.sha1.update(s)
		self.fp.write(s)
		
	def flush(self):
		self.fp.flush()
		
	def __init_comp(self, compressionType):
		self._ibuf = StringIO() # 32K input buffer
		self._obuf = create_string_buffer(32768+6144) # output buffer
		self._blks = (self.size+32767)/32768 - 1# number of input/output blocks
		self._iblk = 0 # current output block index
		self._ipos = 0 # current output block offset
		if self.compressionType == 1:
			if sys.platform == 'win32':
				V = sys.getwindowsversion()
				if V.major >= 6 and V.minor >= 2:
					self.compress = XpressHuffCodec().compress
					logging.debug("Using RTL XPRESS Huffman compressor")
				else:
					self.compress = cdll.MSCompression.xpress_huff_compress
					logging.debug("Using RTL XPRESS Huffman compressor")
		elif self.compressionType == 2:
			self.compress = cdll.MSCompression.lzx_wim_compress
		self.write = self.__write_comp
		self.flush = self.__flush_comp

	def __check_zero_or_bust(self, cb):
		if cb == 0:
			logging.debug("WARNING: compressor failed, zero bytes returned!")
		else:
			logging.debug("WARNING: compressor returned too many (%d) bytes.", cb)
		
	def __write_comp(self, s): # TODO: QWORD if source > 4GiB, DWORD else
		if self.takeSHA: self.sha1.update(s)
		self._ibuf.write(s)
		if self._ibuf.tell() < 32768: return
		
		i, todo = 0, self._ibuf.tell()
		self._ibuf.seek(0)
		while todo >= 32768:
			u_chunk = self._ibuf.read(32768)
			cb = self.compress(u_chunk, 32768, self._obuf, 32768+6144)
			self.fp.seek(self._pos + self._blks*4 + self._ipos) # compressed block start
			if cb == 0 or cb >= 32768:
				self.__check_zero_or_bust(cb)
				logging.debug("Wrote uncompressed chunk %d/%d @%08X", self._iblk, self._blks, self._pos + self._blks*4 + self._ipos)
				self.fp.write(u_chunk)
				self._ipos += 32768
			else:
				logging.debug("Wrote compressed chunk %d/%d @%08X, size %d", self._iblk, self._blks, self._pos + self._blks*4 + self._ipos, cb)
				self.fp.write(self._obuf[:cb])
				self._ipos += cb
			if self._iblk < self._blks: # the last pointer is computed from original size
				self.fp.seek(self._pos + self._iblk*4) # chunk table item offset
				self.fp.write(struct.pack('<I', self._ipos))
				self.fp.seek(self._ipos) # check stream re-alignment!
				logging.debug("Wrote chunk pointer @%08X", self._pos + self._iblk*4)
			self._iblk += 1
			todo -= 32768
		rest = self._ibuf.read()
		self._ibuf.seek(0)
		self._ibuf.write(rest)
		self._ibuf.truncate()
		
	def __flush_comp(self): # merge into __write_comp with a flush flag?
		self._ibuf.seek(0)
		rest = self._ibuf.read()
		logging.debug("Flushing %d bytes", len(rest))
		if rest:
			cb = self.compress(rest, len(rest), self._obuf, 32768+6144)
			self.fp.seek(self._pos + self._blks*4 + self._ipos)
			if cb == 0 or cb >= len(rest):
				self.__check_zero_or_bust(cb)
				logging.debug("Last uncompressed chunk @%08X, size %d", self._pos + self._blks*4 + self._ipos, len(rest))
				self.fp.write(rest)
				self._ipos += len(rest)
			else:
				logging.debug("Last compressed chunk @%08X, size %d", self._pos + self._blks*4 + self._ipos, cb)
				self.fp.write(self._obuf[:cb])
				self._ipos += cb
			self.fp.flush()

	def start(self): return self._pos # compressed stream start offset

	def csize(self):
		if self.compressionType:
			logging.debug("Compressed output stream size: %d (%d%%)", self._blks*4 + self._ipos, -1*(100-(self._blks*4 + self._ipos)*100/self.size))
			return self._blks*4 + self._ipos # compressed stream size
		else:
			return self.size
