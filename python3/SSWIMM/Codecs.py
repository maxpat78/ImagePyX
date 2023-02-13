'''
Codecs.py - Part of Super Simple WIM Manager
MT codecs module for WIM resources (per-thread, plurichunk codec)
'''

import collections
import hashlib
import logging
import struct
import sys
import os
import threading
from ctypes import *
if os.name == 'nt':
	from ctypes.wintypes import *
from queue import *

import timeit

Codec = None

# Codecs to use with MT generic class: Copy, wimlib, Rtl
class BaseCodec:
	"Base codec"
	def __init__(self, compression=0): pass
	
	def compress(self, s, z, expanded_size): pass
		
	def decompress(self, s, z, expanded_size): pass
	
	def check(self, i, j, is_compressor=False):
		if i == 0:
			logging.debug("WARNING: codec failed, zero bytes returned!")
		elif i != j:
			if is_compressor:
				if i > j:
					logging.debug("WARNING: compressor returned too many (%d) bytes.", i)
			else:
				logging.debug("ERROR: decompressor returned %d bytes instead of %d!", i, j)

class CodecException():
	def __init__ (self, msg):
		print(msg)
		os._exit(1)
		
class CopyCodec(BaseCodec):
	"Copy codec"
	def __init__(self, compression=0):
		logging.debug("Using Copy codec")
		pass
	
	def compress(self, s, z, expanded_size): return s
		
	def decompress(self, s, z, expanded_size): return s


class WimlibCodec(BaseCodec):
	"Performs XPRESS or LZX (de)compression with wimlib"
	def __init__(self, codec=1):
		self.compressor = c_voidp()
		self.decompressor = c_voidp()
		try:
			if 'linux' in sys.platform:
				wimlib = cdll.LoadLibrary('wimlib.so') # we need to explicitly load
			else:
				# CAVE! It does NOT search %PATH% nor current directory!
				wimlib = CDLL("libwim-15.dll") # Windows, wimlib 1.13.6
			if codec != 2:
				logging.debug("Using wimlib XPRESS codec")
				wimlib.wimlib_create_compressor(1, 32768, 0, byref(self.compressor))
				wimlib.wimlib_create_decompressor(1, 32768, byref(self.decompressor))
			else:
				logging.debug("Using wimlib LZX codec")
				wimlib.wimlib_create_compressor(2, 32768, 0, byref(self.compressor))
				wimlib.wimlib_create_decompressor(2, 32768, byref(self.decompressor))
			self.co = wimlib.wimlib_compress
			self.dec = wimlib.wimlib_decompress
		except:
			raise CodecException("Can't load wimlib library!")
			
	def compress(self, s, z, expanded_size):
		cb = self.co(s, len(s), z, len(z), self.compressor)
		if not cb or cb >= len(s):
			self.check(cb, len(s), True)
			return s
		else:
			return z[:cb]
		
	def decompress(self, s, z, expanded_size):
		if len(s) == expanded_size:
			return s
		ret = self.dec(s, len(s), z, expanded_size, self.decompressor)
		#~ print('dbg', ret, len(s), expanded_size)
		if ret:
			self.check(0, expanded_size)
		return z[:expanded_size]


class RtlXpressCodec(BaseCodec):
	"Performs Xpress Huffman (de)compression with Windows 8+ NTDLL"
	def __init__(self, codec=1):
		if sys.platform not in ('cygwin', 'win32'):
			raise CodecException("Can't use NTDLL on non-Windows system!")
		logging.debug("Using NT Xpress codec")
		CompressBufferWorkSpaceSize, CompressFragmentWorkSpaceSize = c_uint(), c_uint()
		windll.ntdll.RtlGetCompressionWorkSpaceSize(0x104, byref(CompressBufferWorkSpaceSize), byref(CompressFragmentWorkSpaceSize))
		self.workspace = max(CompressBufferWorkSpaceSize.value, CompressFragmentWorkSpaceSize.value)
		self.workspace = create_string_buffer(self.workspace)
		windll.ntdll.RtlCompressBuffer.restype = UINT
		windll.ntdll.RtlCompressBuffer.argtypes = [USHORT,PCHAR,ULONG,PCHAR,ULONG,ULONG,PULONG,LPVOID]
	
	def compress(self, s, out, expanded_size):
		comp_len = c_int()
		assert not windll.ntdll.RtlCompressBuffer(4, s, len(s), out, len(out), 4096, byref(comp_len), self.workspace)
		cb = comp_len.value
		self.check(cb, len(s), True)
		if cb > 0 and cb < len(s):
			return out[:cb]
		else:
			return s
		
	def decompress(self, s, out, expanded_size):
		if len(s) == expanded_size:
			return s
		uncomp_len = c_int()
		# Warning! Passed output buffer size MUST be equal to the expected output size!
		ret = windll.ntdll.RtlDecompressBufferEx(4, out, expanded_size, s, len(s), byref(uncomp_len), self.workspace)
		if not ret:
			self.check(0, expanded_size)
		return out[:expanded_size]



class CodecMT():
	"Performs generic multithreaded WIM resources (de)compression or copy"
	def __init__ (self, num_threads=4, compression=1):
		self.num_threads = num_threads
		self.compression = compression
		self.q_in = Queue(-1)
		self.q_out = PriorityQueue(-1)
		self.chunk = 0
		self.compressions_skipped = 0
		
		if compression == 1: # XPRESS
			self.codec = WimlibCodec
			if sys.platform == 'win32':
				V = sys.getwindowsversion()
				if V.major >= 7:
					self.codec = RtlXpressCodec
			#~ self.codec = WimlibCodec # force WimlibCodec always
		elif compression == 2: # LZX
			self.codec = WimlibCodec
		else:
			self.codec = CopyCodec
			
		for i in range(num_threads):
			T = threading.Thread(target=self.worker_thread)
			T.daemon = True
			T.start()
	
	def worker_thread(self):
		output_buffer = create_string_buffer(32768+6144)
		codec = self.codec(self.compression)
		fu = [codec.compress, codec.decompress]
		
		while 1:
			action, input_buffer, i, expanded_size = self.q_in.get()
			# NOTE: passing a string buffer between threads can trash memory contents!	
			self.q_out.put( (i, fu[action](input_buffer, output_buffer, expanded_size)) )
			self.chunk += 1

	def _copy(self, src, dst):
		"Simple chunk by chunk copy"
		while 1:
			s = src.read(32768)
			dst.write(s)
			if len(s) < 32768: break

	def _copy2(self, src, src_size, chunks, dst):
		"Chunk by chunk copy with hash and size"
		while chunks:
			# The WIM can continue beyond the resource stream...
			chunk_size = (32768, src_size%32768)[chunks == 1] or 32768
			s = src.read(chunk_size)
			self.sha1.update(s)
			dst.write(s)
			chunks -= 1

	# 7 INF folder: 8" w/ MultiFile|wimlib|ImageX, 9" w/ MultiChunk-2T (11" w/ 1T)
	def compress(self, in_stream, out_stream, in_size, take_sha=False):
		self.take_sha = take_sha
		self.isize = in_size
		self.sha1 = hashlib.sha1()
		BLK = 32768
		fmt = ('<I', '<Q') [in_size > 4 * (1<<30)] # > 4 GiB
		chunks = (in_size + 32767)//32768
		in_start_pos = in_stream.tell()
		rsrc_start_pos = out_stream.tell()
		if self.codec != CopyCodec:
			out_stream.seek((chunks-1)*struct.calcsize(fmt), 1)
		start_pos = out_stream.tell()
		self.chunk = chunk = 0
		self.q_in.queue = collections.deque()
		self.q_out = PriorityQueue()
		if hasattr(self, 'threshold_size'):
			self.threshold = 1
		else:
			self.threshold = 0
		while chunks:
			# Note: increasing the input queue to 16 chunk per thread speeds up by 15%
			for i in range(self.num_threads*16):
				s = in_stream.read(BLK)
				if s:
					chunk += 1
					# (action, input_buffer, chunk_index)
					self.q_in.put((0, s, chunk, 0))
					if self.take_sha:
						self.sha1.update(s)
				else:
					break
			while self.chunk < chunk: # move the following to the working thread?
				continue
			while not self.q_out.empty():
				chunks -= 1
				i, s = self.q_out.get()
				out_stream.write(s)
				#~ logging.debug("Written chunk #%d, %d bytes", i, cb)
				if self.codec != CopyCodec and chunks:
					pos = out_stream.tell()
					out_stream.seek(start_pos-chunks*struct.calcsize(fmt))
					out_stream.write(struct.pack(fmt, pos - start_pos))
					out_stream.seek(pos)
				# Aborts compression if gain is < 1% after the first half input has been processed
				# AND stream is at least 10 MiB long
				if self.threshold:
					if chunks == ((in_size + 32767)//32768)//self.threshold_chunks and chunks > self.threshold_size:
						emitted = out_stream.tell() - rsrc_start_pos
						processed = in_stream.tell() - in_start_pos
						if 1 - emitted*1.0/processed < self.threshold_ratio:
							self.compressions_skipped += 1
							in_stream.seek(in_start_pos)
							out_stream.seek(rsrc_start_pos)
							# Restarts partial SHA-1 calculation
							self.sha1 = hashlib.sha1()
							self._copy2(in_stream, in_size, chunks, out_stream)
							self.osize = in_size
							return
		self.osize = out_stream.tell() - rsrc_start_pos # total size of the resource
		if self.osize >= in_size: # Simply (re)copies if there's no gain
			in_stream.seek(in_start_pos)
			out_stream.seek(rsrc_start_pos)
			self._copy(in_stream, out_stream)
			self.osize = in_size

	# 3 techniques to access chunk pointers:
	# 1) repeatedly seek back and forward (slowest?)
	# 2) open a new stream to read in pointers
	# 3) read and decode all pointers in one pass
	def decompress(self, in_stream, in_size, out_stream, out_size, take_sha=False):
		self.take_sha = take_sha
		self.sha1 = hashlib.sha1()
		BLK = 32768
		fmt = ('<I', '<Q') [out_size > 4 * (1<<30)] # > 4 GiB
		n = struct.calcsize(fmt)
		chunks = (out_size + 32767)//32768
		start_pos = in_stream.tell()
		if in_size == out_size: # copy only, 1 thread
			self._copy2(in_stream, in_size, chunks, out_stream)
			return
		if self.codec != CopyCodec:
			# Duplicating file handle to easily access chunk pointers: I/O penalties? 2ms each!
			#~ chunks_pos = in_stream.tell()
			cin = open(in_stream.name, 'rb')
			cin.seek(in_stream.tell())
			in_stream.seek((chunks-1)*n, 1)
			prev_offset = 0
		self.chunk = chunk = 0
		while chunks:
			# Multichunk approach seems faster!
			for i in range(min(self.num_threads*16, chunks)):
				if self.codec != CopyCodec:
					if chunks > 1:
						pos = in_stream.tell()
						#~ in_stream.seek(chunks_pos)
						new_offset = struct.unpack(fmt, cin.read(n))[0]
						#~ new_offset = struct.unpack(fmt, in_stream.read(n))[0]
						#~ chunks_pos += n
						in_stream.seek(pos)
						BLK = new_offset - prev_offset # next chunk length
						prev_offset = new_offset
					else:
						BLK = in_size - (in_stream.tell() - start_pos)
				s = in_stream.read(BLK)
				chunk += 1
				expanded_size = (32768, out_size%32768)[chunks == 1] or 32768
				self.q_in.put((1, s, chunk, expanded_size))
				chunks -= 1
				#~ print chunk, chunks, BLK, expanded_size
			while self.chunk < chunk:
				continue
			while not self.q_out.empty():
				#~ chunks -= 1
				i, s = self.q_out.get()
				out_stream.write(s)
				if self.take_sha:
					self.sha1.update(s)
