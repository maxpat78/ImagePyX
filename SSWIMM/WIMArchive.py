'''
WIMArchive.PY - Part of Super Simple WIM Manager
Common structures and functions
'''

VERSION = '0.28'

COPYRIGHT = '''Copyright (C)2012-2013, by maxpat78. GNU GPL v2 applies.
This free software creates MS WIM Archives WITH ABSOLUTELY NO WARRANTY!'''

import Codecs
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
from collections import OrderedDict
from ctypes import *
from cStringIO import StringIO

# Helper functions
def class2str(c, s):
	"Makes a table from keys:values in a class layout"
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
	"Decodes and stores an attribute according to the class layout"
	i = c._vk[name]
	fmt = c._kv[i][1]
	cnt = struct.unpack_from(fmt, c._buf, i+c._i) [0]
	setattr(c, name,  cnt)
	return cnt

def nt2uxtime(t):
	"Converts date/time from NT to Python format (Unix)"
	# NT: 100 nanoseconds intervals since midnight of 1/1/1601
	# Unix: seconds since 1/1/1970
	# Diff is 134.774 days or 11.644.473.600 seconds
	return datetime.datetime.utcfromtimestamp(t/10000000 - 11644473600)

def nt2uxtime(t):
	"Converts date/time from NT into Unix"
	return t/10000000 - 11644473600

def ux2nttime(t):
	"Converts date/time from Unix into NT"
	return int((t+11644473600L)*10000000L)

def take_sha(pathname, _blklen=32*1024, first_chunk=False):
	"Calculates the SHA-1 for file contents"
	pos = -1
	if type(pathname) in (type(''), type(u'')):
		fp = open(pathname, 'rb')
	else:
		fp = pathname
		pos = fp.tell()
	sha = hashlib.sha1()
	while 1:
		s = fp.read(_blklen)
		sha.update(s)
		if len(s) < _blklen or first_chunk: break
	if pos > -1:
		fp.seek(pos)
	if first_chunk or pos == -1:
		fp.seek(0)
	return fp, sha.digest()

def touch(pathname, WTime, CTime, ATime):
	if sys.platform not in ('win32', 'cygwin'):
		try:
			os.utime(pathname, (nt2uxtime(ATime), nt2uxtime(WTime)))
		except:
			logging.debug("Can't touch %s", pathname)
		return
	hFile = windll.kernel32.CreateFileW(pathname, 0x0100, 0, 0, 3, 0x02000000, 0)
	if hFile == -1:
		logging.debug("Can't open '%s' to touch it!", pathname)
		return
	CTime = c_ulonglong(CTime)
	ATime = c_ulonglong(ATime)
	WTime = c_ulonglong(WTime)
	if not windll.kernel32.SetFileTime(hFile, byref(CTime), byref(ATime), byref(WTime)):
		logging.debug("Can't apply datetimes to '%s'!", pathname)
	windll.kernel32.CloseHandle(hFile)

def IsReparsePoint(pathname):
	"Test if the object is a symbolic link or a junction point"
	if not pathname: return False
	if sys.platform in ('win32', 'cygwin'):
		ret = windll.kernel32.GetFileAttributesW(pathname)
	else:
		ret = (0, 0x400)[os.path.islink(pathname)]
	if ret > -1:
		return ret & 0x400 # FILE_ATTRIBUTE_REPARSE_POINT
	else:
		return False

class WIN32_FIND_STREAM_DATA(Structure):
	_fields_ = [("StreamSize", c_longlong), ("cStreamName", c_wchar*296)]

class WIN32_FIND_DATA(Structure):
	_pack_ = 1
	_fields_ = [("dwFileAttributes", c_uint), ("ftCreationTime", c_ulonglong), ("ftLastAccessTime", c_ulonglong),
	("ftLastWriteTime", c_ulonglong), ("dwnFileSizeHigh", c_uint), ("dwnFileSizeLow", c_uint), ("dwReserved0", c_uint),
	("dwReserved1", c_uint), ("cFileName", c_wchar*260), ("cAlternateFileName", c_wchar*14)]

class BY_HANDLE_FILE_INFORMATION(Structure):
	_pack_ = 1
	_fields_ = [("dwFileAttributes", c_uint), ("ftCreationTime", c_ulonglong), ("ftLastAccessTime", c_ulonglong),
	("ftLastWriteTime", c_ulonglong), ("dwVolumeSerialNumber", c_uint), ("nFileSizeHigh", c_uint), ("nFileSizeLow", c_uint),
	("nNumberOfLinks", c_uint), ("nFileIndexHigh", c_uint), ("nFileIndexLow", c_uint)]

def IsHardlinkedFile(pathname):
    "Test if a file has hard links"
    if not pathname: return False
    if sys.platform not in ('win32', 'cygwin'):
        if not os.path.islink(pathname) and os.stat(pathname).st_nlink > 1:
           return (0, os.stat(pathname).st_ino) # is inode a 32-bit number?
        else:
           return None
    hFile = windll.kernel32.CreateFileW(pathname, 0x80000100, 0, 0, 3, 0x02200000, 0)
    if hFile == -1:
        logging.debug("Can't open file %s with CreateFileW", pathname)
        return None
    hfi = BY_HANDLE_FILE_INFORMATION()
    if windll.kernel32.GetFileInformationByHandle(hFile, byref(hfi)):
        windll.kernel32.CloseHandle(hFile)
        if hfi.nNumberOfLinks > 1:
            return hfi.nFileIndexLow, hfi.nFileIndexHigh # FileIndex
    windll.kernel32.CloseHandle(hFile)
    return None

def GetReparsePointTag(pathname):
	"Retrieves the IO_REPARSE_TAG associated with a reparse point"
	#~ print pathname.encode('mbcs')
	if sys.platform in ('win32', 'cygwin'):
		wfd = WIN32_FIND_DATA()
		h = windll.kernel32.FindFirstFileW(pathname, byref(wfd))
		if h == -1:
			return None
		windll.kernel32.CloseHandle(h)
		#~ print hex(wfd.dwReserved0)
		logging.debug("Found %s on %s", {0xA000000C:'IO_REPARSE_TAG_SYMLINK',0xA0000003:'IO_REPARSE_TAG_MOUNT_POINT'}[wfd.dwReserved0], wfd.cFileName)
		return wfd.dwReserved0
	else:
		if os.path.islink(pathname): # Does it make sense distinguish in Linux?
			return 0xA000000C

def ParseReparseBuf(s, tag):
	"Parses a WIM reparse point buffer and returns the decoded paths"
	start = 8
	SubstNameOffs, SubstNameLen, PrintNameOffs, PrintNameLen = struct.unpack('<HHHH', s[0:8])
	flags = 0
	if tag == 0xA000000C:
		flags = struct.unpack('<I', s[8:12])[0]
		start += 4
	i = start+SubstNameOffs
	SubstName = s[i : i+SubstNameLen].decode('utf-16le')
	i = start+PrintNameOffs
	PrintName = s[i : i+PrintNameLen].decode('utf-16le')
	return flags, SubstName, PrintName

def MakeReparsePoint(tag, dst, target):
	# FILE_FLAG_OPEN_REPARSE_POINT=0x02200000
	hFile = windll.kernel32.CreateFileW(dst, 0x40000100, 0, 0, 3, 0x02200000, 0)
	if hFile != -1:
		sn = ('\\??\\'+target).encode('utf-16le') + '\0\0'
		pn = target.encode('utf-16le') + '\0\0'
		# REPARSE_DATA_BUFFER with MountPointReparseBuffer
		s = struct.pack('<IHHHHHH', tag, 8+len(sn)+len(pn), 0, 0, len(sn)-2, len(sn), len(pn)-2)
		s += sn + pn
		ret = 0
		# FSCTL_SET_REPARSE_POINT to set the REPARSE_DATA_BUFFER
		n = c_int() # This is not necessary with Win8/64-bit (?!?)
		if windll.kernel32.DeviceIoControl(hFile, 0x900A4, s, len(s), 0, 0, byref(n), 0): # Admin rights not required!
			ret = 1
		windll.kernel32.CloseHandle(hFile)
		return ret
	
def GetReparsePointData(pathname, srcdir):
	"Retrieves and fixes the REPARSE_DATA_BUFFER associated with a reparse point"
	if sys.platform not in ('win32', 'cygwin'):
		lk = os.readlink(pathname)
		Flags = not os.path.isabs(lk) # determines if it is relative
		if lk.find(os.path.abspath(srcdir)) == 0:
			SubstName = '\\??\\C:' + lk[len(os.path.abspath(srcdir)):]
			PrintName = 'C:' + lk[len(os.path.abspath(srcdir)):]
		else:
			SubstName = PrintName = lk
		logging.debug('Reparse point: subst="%s", print="%s"', SubstName, PrintName)
		SubstName = SubstName.replace('/', '\\')
		PrintName = PrintName.replace('/', '\\')
		SubstName = SubstName.encode('utf-16le')
		PrintName = PrintName.encode('utf-16le')
		if not Flags:
			inc = 2
		else:
			inc = 0
		s = struct.pack('<HHHH', 0, len(SubstName), len(SubstName)+inc, len(PrintName))
		s += struct.pack('<I', Flags) # always symlink
		if not Flags: # an absolute path gets NULL terminated
			SubstName += '\0\0'
			PrintName += '\0\0'
		s += SubstName + PrintName
		return Flags, s
	hFile = windll.kernel32.CreateFileW(pathname, 0x80000100, 0, 0, 3, 0x02200000, 0)
	if hFile != -1:
		s = create_string_buffer(1024)
		n = c_int()
		# FSCTL_GET_REPARSE_POINT to get the REPARSE_DATA_BUFFER
		if windll.kernel32.DeviceIoControl(hFile, 0x900A8, 0, 0, s, 1024, byref(n), 0):
			windll.kernel32.CloseHandle(hFile)
			#~ print s[:n.value]
			start = 16
			Tag, wLen, wResv, SubstNameOffs, SubstNameLen, PrintNameOffs, PrintNameLen = struct.unpack('<IHHHHHH', s[0:16])
			#~ print hex(Tag), wResv, SubstNameOffs, SubstNameLen, PrintNameOffs, PrintNameLen
			Flags = 0
			if Tag == 0xA000000C:
				Flags = struct.unpack('<I', s[16:20])[0]
				start += 4
			i = start+SubstNameOffs
			SubstName = s[i : i+SubstNameLen].decode('utf-16le')
			i = start+PrintNameOffs
			PrintName = s[i : i+PrintNameLen].decode('utf-16le')
			# Fix the abspath if it points inside the image root
			#~ print SubstName, '\n', os.path.abspath(srcdir)
			if SubstName.lower().find(os.path.abspath(srcdir).lower()) == 4:
				SubstName = SubstName[:6] + SubstName[4+len(os.path.abspath(srcdir)):]
				PrintName = PrintName[:2] + PrintName[len(os.path.abspath(srcdir)):]
			#~ print SubstName, PrintName
			logging.debug('Reparse point: tag=%08X, subst="%s", print="%s"', Tag, SubstName, PrintName)
			SubstName = SubstName.encode('utf-16le')
			PrintName = PrintName.encode('utf-16le')
			if not Flags:
				inc = 2
			else:
				inc = 0
			s = struct.pack('<HHHH', 0, len(SubstName), len(SubstName)+inc, len(PrintName))
			if Tag == 0xA000000C:
				s += struct.pack('<I', Flags)
			if not Flags: # an absolute path gets NULL terminated
				SubstName += '\0\0'
				PrintName += '\0\0'
			s += SubstName + PrintName
			return Flags, s
	return None

class myTokenPriv(Structure):
	_pack_ = 1
	_fields_ = [
	('dwCount', c_ulong),
	('luid', c_ulonglong),
	('dwAttributes', c_ulong)]

def AcquirePrivilege(privilege):
    "Acquires a privilege to the Python process"
    if sys.platform not in ('win32', 'cygwin'): return 0
    hToken = c_int()
    TOKEN_QUERY, TOKEN_ADJUST_PRIVILEGES = 0x8, 0x20
    ret = windll.advapi32.OpenProcessToken(windll.kernel32.GetCurrentProcess(),TOKEN_ADJUST_PRIVILEGES|TOKEN_QUERY, byref(hToken))
    if not ret: return ret
    LUID = c_ulonglong()
    ret = windll.advapi32.LookupPrivilegeValueA(0, privilege, byref(LUID))
    if not ret: return ret
    tkp = myTokenPriv()
    tkp.dwCount = 1
    tkp.luid = LUID
    tkp.dwAttributes = 2 # SE_PRIVILEGE_ENABLED
    ret = windll.advapi32.AdjustTokenPrivileges(hToken, 0, byref(tkp), sizeof(tkp), 0, 0)
    if ret == 0 or windll.kernel32.GetLastError() != 0:
        logging.debug("Privilege %s not acquired!", privilege)
        return False
    return True

def print_progress(start_time, totalBytes, totalBytesToDo):
	"Prints a progress string"
	pct_done = 100*float(totalBytes)/float(totalBytesToDo)
	# Limits console output to 1 print per second, beginning after 50% progress
	if pct_done < 50 or (time.time() - print_progress.last_print) < 1: return
	print_progress.last_print = time.time()
	avg_secs_remaining = (print_progress.last_print - start_time) / pct_done * 100 - (print_progress.last_print - start_time)
	avg_secs_remaining = int(avg_secs_remaining)
	if avg_secs_remaining < 61:
		s = '%d secs' % avg_secs_remaining
	else:
		s = '%d:%02d mins' % (avg_secs_remaining/60, avg_secs_remaining%60)
	print_progress.fu('%d%% done, %s left          \r' % (pct_done, s))

print_progress.last_print = 0
if 'linux' in sys.platform:
	def fu(s):
		sys.stdout.write(s)
		sys.stdout.flush()
	print_progress.fu = fu
else:
	print_progress.fu = sys.stdout.write


def print_timings(start, stop):
	print "Done. %s time elapsed." % datetime.timedelta(seconds=int(stop-start))

def wim_is_clean(wim, fp):
	"Ensures there's no garbage after XML data"
	if wim.dwFlags & 0x40 and wim.rhXmlData.liOffset + wim.rhXmlData.ullSize < os.stat(fp.name):
		print "A previous WIM updating failed, restoring the original size..."
		logging.debug("Previous WIM updating failed, restoring the original size (%d bytes)", wim.rhXmlData.liOffset + wim.rhXmlData.ullSize)
		fp.truncate(wim.rhXmlData.liOffset + wim.rhXmlData.ullSize)

def get_wim_comp(wim):
	COMPRESSION_TYPE = 0
	if wim.dwFlags & 0x20000:
		COMPRESSION_TYPE = 1
	elif wim.dwFlags & 0x40000:
		COMPRESSION_TYPE = 2
	print "Compression is", ('none', 'XPRESS', 'LZX')[COMPRESSION_TYPE]
	return COMPRESSION_TYPE


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

	def __repr__ (self):
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
	"Security descriptors associated to file resources."
	layout = {
	0x00: ('dwTotalLength', '<I'), # length of the SD resource
	0x04: ('dwNumEntries', '<I'), # Array of QWORDs with variable-length security descriptors follows
	}

	def __init__(self, s):
		self.SDS = OrderedDict() # Security Descriptors dictionary {hash: SD}
		self._i = 0 # posizione nel buffer
		self._pos = 0 # posizione nel buffer
		self._buf = s
		self._kv = SecurityData.layout.copy()
		self._vk = {} # { nome: offset}
		for k, v in self._kv.items():
			self._vk[v[0]] = k
		self.dwTotalLength = 8 # initial size (empty object)
		self.size = self.dwTotalLength
		if AcquirePrivilege("SeSecurityPrivilege"):
			self.SeSecurityPrivilege = True
		else:
			self.SeSecurityPrivilege = False
			logging.debug("SeSecurityPrivilege not held, can't handle SACL_SECURITY_INFORMATION nor restore SDs!")
		
	__getattr__ = common_getattr
	
	def __str__ (self):
		return class2str(self, "SecurityData @%x\n" % self._pos)

	def tostr (self):
		s = ''
		# Make the SDs lenghts table (QWORD)
		for sd in self.SDS:
			s += struct.pack('<Q', len(self.SDS[sd]))
		# Add the SDs themselves
		for sd in self.SDS:
			s += self.SDS[sd].raw
		pad = 8 - (len(s)%8) & 7
		s += (pad*'\0') # align to QWORD
		self.dwTotalLength = 8 + len(s)
		self.dwNumEntries = len(self.SDS)
		s1 = ''
		keys = self._kv.keys()
		keys.sort()
		for k in keys:
			v = self._kv[k]
			s1 += struct.pack(v[1], getattr(self, v[0]))
		return s1+s

	def addobject(self, pathname):
		"Adds a single instance of an object's SD into a table, returning its index"
		if sys.platform not in ('win32', 'cygwin'):
			return -1
		lpLenNeeded = c_int()
		# OWNER_SECURITY_INFORMATION=1 GROUP_SECURITY_INFORMATION=2 DACL_SECURITY_INFORMATION=4
		SecurityInfo = 7
		if self.SeSecurityPrivilege:
			SecurityInfo |= 8 # SACL_SECURITY_INFORMATION
		windll.advapi32.GetFileSecurityW(pathname, SecurityInfo, None, None, byref(lpLenNeeded))
		s = create_string_buffer(lpLenNeeded.value)
		ret = windll.advapi32.GetFileSecurityW(pathname, SecurityInfo, s, lpLenNeeded.value, byref(lpLenNeeded))
		ind = -1
		if ret and windll.advapi32.IsValidSecurityDescriptor(s):
			sha1 = hashlib.sha1(s).digest()
			if sha1 in self.SDS:
				ind = self.SDS.keys().index(sha1)
				logging.debug("SD already indexed as #%d", ind)
			else:
				self.SDS[sha1] = s
				ind = len(self.SDS) - 1
				logging.debug("Added new SD with index #%d", ind)
				self.dwTotalLength += 8 + len(s)
		else:
			logging.debug("GetFileSecurityW failed on '%s'", pathname)
		return ind

	def apply(self, index, pathname):
		"Applies a SD to an object"
		if sys.platform not in ('win32', 'cygwin'):
			return
		if index > -1 and index < len(self.SDS):
			sd = self.SDS.keys()[index]
			SecurityInfo = 7
			if self.SeSecurityPrivilege:
				SecurityInfo |= 8 # SACL_SECURITY_INFORMATION
			if not windll.advapi32.SetFileSecurityW(pathname, SecurityInfo, self.SDS[sd]):
				logging.debug("Error restoring SD on '%s'", pathname)

	def length(self):
		pad = 8 - (self.dwTotalLength%8) & 7
		return self.dwTotalLength + pad # QWORD aligned size


class DirEntry:
	"Represents a file or folder captured inside an image"
	layout = { # 0x66 bytes
	0x00: ('liLength', '<Q'), # Length of this DIRENTRY
	0x08: ('dwAttributes', '<I'), # DOS file attributes (0x20=DIR)
	0x0C: ('dwSecurityId', '<i'), # Security Descriptor (-1 if not used) index
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
		self._vk = {} # { name: offset}
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
		return class2str(self, "DirEntry @%x\n" % self._pos) + '66: sFileName = %s' % self.FileName.encode('utf8')

	def tostr (self):
		s = ''
		keys = self._kv.keys()
		keys.sort()
		for k in keys:
			v = self._kv[k]
			s += struct.pack(v[1], getattr(self, v[0]))
		s += self.FileName
		if hasattr(self, 'ShortFileName'):
			s += '\0\0' + self.ShortFileName
		return s + (self.liLength-len(s))*'\0'


class StreamEntry:
	"Represents an alternate stream entry"
	layout = { # 0x26 (38) bytes
	0x00: ('liLength', '<Q'), # Length of this STREAMENTRY
	0x08: ('liUnused', '<Q'),
	0x10: ('bHash', '20s'), # SHA-1 hash (uncompressed data)
	0x24: ('wStreamNameLength', '<H') # length of the ADS name (if provided)
	}
	# Unicode UTF-16-LE entry name follows, terminated by a Unicode NULL (not mentioned in spec, nor counted in wStreamNameLength),
	# QWORD aligned itself
	
	def __init__(self, s):
		self._i = 0
		self._pos = 0
		self._buf = s
		self._kv = StreamEntry.layout.copy()
		self._vk = {} # { name: offset}
		for k, v in self._kv.items():
			self._vk[v[0]] = k
		self.size = 0
		if self.wStreamNameLength:
			self.StreamName = (self._buf[0x26:0x26+self.wStreamNameLength]).decode('utf-16le')
		else:
			self.StreamName = ''
		self.FileName = self.StreamName
		
	__getattr__ = common_getattr
	
	def __str__ (self):
		return class2str(self, "StreamEntry @%x\n" % self._pos) + '26: sStreamName = %s' % self.StreamName

	def tostr (self):
		self.length()
		s = ''
		keys = self._kv.keys()
		keys.sort()
		for k in keys:
			v = self._kv[k]
			s += struct.pack(v[1], getattr(self, v[0]))
		s += self.StreamName + '\0\0'
		return s + (self.liLength-len(s))*'\0'

	def length(self):
		self.liLength = 0x26 + self.wStreamNameLength
		# Sum virtual ending NULL
		if self.wStreamNameLength: self.liLength += 2
		self.liLength += (8 - (self.liLength%8) & 7) # QWORD padding
		logging.debug("StreamEntry padded size=%x", self.liLength)
		return self.liLength

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

	def __repr__ (self):
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
	"Optional integrity table"
	layout = {
	0x00: ('cbSize', '<I'), # length of the table
	0x04: ('dwNumElements', '<I'), # Chunks number
	0x08: ('dwChunkSize', '<I') # fixed to 10 MiB
	}

	def __init__(self, s):
		self._i = 0
		self._pos = 0
		self._buf = s
		self._kv = IntegrityTable.layout.copy()
		self._vk = {}
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
