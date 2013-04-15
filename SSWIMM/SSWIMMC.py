'''
SSWIMMC.PY - Super Simple WIM Manager
Creator module - Multithreaded version
'''

VERSION = '0.29'

COPYRIGHT = '''Copyright (C)2012-2013, by maxpat78. GNU GPL v2 applies.
This free software manages MS WIM Archives WITH ABSOLUTELY NO WARRANTY!'''

import Codecs
import fnmatch
import w32_fnmatch
fnmatch.translate = w32_fnmatch.win32_translate
import optparse
import hashlib
import logging
import os
import Queue
import sys
import tempfile
import time
import threading
import uuid
from collections import OrderedDict
from ctypes import *
from datetime import datetime as dt
from xml.etree import ElementTree as ET
from WIMArchive import *
from StringIO import StringIO


def make_wimheader(compress=1):
	wim = WIMHeader(208*'\0')
	wim.ImageTag = 'MSWIM\0\0\0'
	wim.cbSize = 0xD0
	wim.dwVersion = 0x00010D00 # 1.13
	wim.dwCompressionSize = 0x8000
	if compress == 1:
		wim.dwFlags = 2 | 0x20000 # XPRESS compressed
	elif compress == 2:
		wim.dwFlags = 2 | 0x40000 # LZX compressed
	else:
		wim.dwFlags = 0 # Uncompressed
		wim.dwCompressionSize = 0
	wim.dwFlags |= 0x40 # set FLAG_HEADER_WRITE_IN_PROGRESS
	wim.dwFlags |= 0x80 # set FLAG_HEADER_RP_FIX
	wim.gWIMGuid = uuid.uuid4().bytes
	wim.usPartNumber = 1
	wim.usTotalParts = 1
	wim.dwImageCount = 1
	wim.rhOffsetTable = DiskResHdr(64*'\0')
	wim.rhXmlData = DiskResHdr(64*'\0')
	wim.rhBootMetadata = DiskResHdr(64*'\0')
	wim.rhIntegrity = DiskResHdr(64*'\0')
	wim.bUnused = 60*'\0'
	return wim

def make_direntry(pathname, security, isroot=0, srcdir=None):
	e = DirEntry(255*'\0')
	if len(pathname) < 255:
		# In Linux we don't want to follow broken links!
		st = os.lstat(pathname)
	else:
		st = os.lstat('\\\\?\\'+os.path.abspath(pathname))
	e.FileSize = st.st_size
	if sys.platform in ('win32', 'cygwin'):
		e.dwAttributes = windll.kernel32.GetFileAttributesW(pathname)
		if e.dwAttributes == -1:
			logging.debug("GetFileAttributesW returned -1 on %s", pathname)
			e.dwAttributes = 0x20
	e.dwSecurityId = security.addobject(pathname)
	if os.path.isfile(pathname):
		e.dwAttributes = 0x20
	else:
		e.dwAttributes |= 0x10
		if isroot: pathname = ''
	e.SrcPathname = pathname
	e.liCreationTime = ux2nttime(st.st_ctime)
	e.liLastWriteTime = ux2nttime(st.st_mtime)
	e.liLastAccessTime = ux2nttime(st.st_atime)
	base = os.path.basename(pathname)
	e.wFileNameLength = len(base) * 2
	e.FileName = base.encode('utf-16le')
	# Handles short file name on Windows
	if sys.platform in ('win32', 'cygwin'):
		i = windll.kernel32.GetShortPathNameW(pathname, 0, 0)
		short_pathname = create_string_buffer(2*i) # wchar_t
		i = windll.kernel32.GetShortPathNameW(pathname, short_pathname, i)
		u_short_pathname = short_pathname.raw.decode('utf-16le')[:i]
		short_base = os.path.basename(u_short_pathname)
		if base != short_base:
			e.wShortNameLength = len(short_base)*2
			e.ShortFileName = short_base.encode('utf-16le')
	e.liLength = 0x66 + e.wFileNameLength + e.wShortNameLength
	# Sum virtual ending NULL
	if e.wFileNameLength: e.liLength += 2
	if e.wShortNameLength: e.liLength += 2
	e.liLength += (8 - (e.liLength%8) & 7) # QWORD padding
	e.bHash = 0
	# Handles reparse points (directory junctions and symbolic links to files/dirs)
	if IsReparsePoint(pathname):
		e.dwAttributes |= 0x400
		e.dwReparseReserved = GetReparsePointTag(pathname)
		isRelative, e.sReparseData = GetReparsePointData(pathname, srcdir)
		if isRelative and e.dwReparseReserved == 0xA000000C: # Symlink
			e.dwHardLink = 0x10000
		e.FileSize = len(e.sReparseData)
		logging.debug("Parsed %s as Reparse point type %X", pathname, e.dwReparseReserved) 
	# Stores hard link (nFileIndex)
	tu = IsHardlinkedFile(pathname)
	if type(tu) == type(()):
		e.dwReparseReserved = tu[0] # nFileIndexLow
		e.dwHardLink = tu[1] # nFileIndexHigh
		logging.debug("Parsed hard linked file %s", pathname) 
	# Handles alternate data streams on Windows
	e.alt_data_streams = {}
	if not (e.dwAttributes & 0x10):
		e.alt_data_streams = get_ads(pathname)
		e.wStreams = len(e.alt_data_streams)
	return e

def make_securityblock():
	e = SecurityData(255*'\0')
	e.dwTotalLength = 8
	e.dwNumEntries = 0
	return e

def make_direntries(directory, security, excludes=None):
	def is_excluded(s, excludes):
		i_pname = s[s.find('\\'):] # pathname how it will be inside the image
		# if the excluded item is a dir, we want subcontents excluded also! (x+\*)
		return True in map(lambda x:fnmatch.fnmatch(i_pname, x) or fnmatch.fnmatch(i_pname, x+'\\*'), excludes)
	directory = os.path.normpath(unicode(directory))
	direntries = []
	total_input_bytes = 0

	# root DIRENTRY offset relative to Metadata resource start
	pos = 0 # relative offset of the next subdir content
	subdirs = OrderedDict() # {parent folder: childs offset}
	for root, dirs, files in os.walk(directory):
		logging.debug("root is now %s", root)
		if IsReparsePoint(root): # this isn't a true directory
			logging.debug("Stopped descending into reparse point '%s'", root)
			continue
		if excludes and is_excluded(root, excludes):
			logging.debug("Excluded root %s", root)
			continue
		if root == directory:
			direntries += [make_direntry(root,security,1,directory)]
			logging.debug("Made Root DIRENTRY %s", root)
			direntries += [DirEntry(255*'\0')] # a null QWORD marks the end of folder
			pos += direntries[-2].liLength + 8
			logging.debug("Made NULL QWORD (end of root)")
		for item in files:
			if root not in subdirs:
				subdirs[root] = pos
			pname = os.path.join(root, item)
			if excludes and is_excluded(pname, excludes):
				logging.debug("Excluded file %s", pname)
				continue
			if len(item) > 255 and '\\\\?\\' not in pname:
				pname = '\\\\?\\' + os.path.abspath(pname) # access pathnames > 255
			direntries += [make_direntry(pname, security, srcdir=directory)]
			pos += direntries[-1].liLength
			total_input_bytes += direntries[-1].FileSize
			if direntries[-1].alt_data_streams:
				for ads in direntries[-1].alt_data_streams:
					pos += ads.length()
					total_input_bytes += ads.FileSize
			logging.debug("Made File DIRENTRY %s", pname)
		for item in dirs:
			if root not in subdirs:
				subdirs[root] = pos
			pname = os.path.join(root, item)
			if excludes and is_excluded(pname, excludes):
				logging.debug("Excluded folder %s", pname)
				continue
			if len(item) > 255 and '\\\\?\\' not in pname:
				pname = '\\\\?\\' + os.path.abspath(pname) # access pathnames > 255
			direntries += [make_direntry(pname,security,srcdir=directory)]
			logging.debug("Made Folder DIRENTRY %s", item)
			pos += direntries[-1].liLength
			total_input_bytes += direntries[-1].FileSize
		if root not in subdirs: # an empty folder must point to the following NULL QWORD
			subdirs[root] = pos
		direntries += [DirEntry(255*'\0')]
		pos += 8
		logging.debug("Made NULL QWORD (end of folder)")
	for it in subdirs:
		subdirs[it] += security.length() # fix final offset relative to Security Data object
	return pos, direntries, subdirs, total_input_bytes

def make_fileresources(out, comp, entries, refcounts, total_input_bytes, start_time):
	"Packs the files content into the image, discarding duplicates according to their SHA-1"
	totalBytes = 0 # Total bytes for files uncompressed content, duplicates included

	comp_start_time = time.time()
	
	chunk_hash_table = {}
	
	for e in entries:
		# Skips folders, NULL entries and empty files. Reparse points are handled like files.
		if (e.dwAttributes & 0x10 and not e.dwAttributes & 0x400) or not e.liLength or not e.FileSize: continue
		e.bCompressed = comp
		# Handles a special case: reparse points
		if e.dwAttributes & 0x400:
			e.SrcPathname = StringIO(e.sReparseData)
			e.bCompressed = 0
			e.liSubdirOffset = 0
		try:
			fp, chunk_crc = take_sha(e.SrcPathname, first_chunk=1)
		except:
			logging.debug("Could not capture '%s', skipped.", e.SrcPathname)
			print "WARNING: could not capture '%s', skipped." % e.SrcPathname
			totalBytes += e.FileSize
			print_progress(comp_start_time, totalBytes, total_input_bytes)
			continue
		if chunk_crc in chunk_hash_table:
			fp, crc = take_sha(e.SrcPathname)
			if crc in refcounts:
				h = refcounts[crc]
				refcounts[crc] = (h[0], h[1], h[2], h[3]+1, h[4])
				logging.debug("Discarded %s (hash collision)", e.SrcPathname)
				e.Offset = h[0]
				e.bHash = crc
				totalBytes += e.FileSize
				print_progress(comp_start_time, totalBytes, total_input_bytes)
				continue
			calc_crc = False
		else:
			chunk_hash_table[chunk_crc] = 1
			calc_crc = True
		if e.dwAttributes & 0x400:
			e.SrcPathname = StringIO(e.sReparseData)
		e.Offset = out.tell() # Fileresource start offset inside WIM
		logging.debug("Starting new File resource @%08X", e.Offset)
		#~ logging.debug("fp=%s, out=%s, e.FileSize=%d, calc_crc=%s", fp, out, e.FileSize, calc_crc)
		Codecs.Codec.compress(fp, out, e.FileSize, calc_crc)
		if calc_crc:
			crc = Codecs.Codec.sha1.digest()
			if crc in refcounts: # This is required for proper append task!
				h = refcounts[crc]
				refcounts[crc] = (h[0], h[1], h[2], h[3]+1, h[4])
				logging.debug("Discarded %s (hash collision) - stream rewinded", e.SrcPathname)
				out.seek(e.Offset)
				e.Offset = h[0]
				e.bHash = crc
				totalBytes += e.FileSize
				print_progress(comp_start_time, totalBytes, total_input_bytes)
				continue
		logging.debug("Wrote content from %s", e.SrcPathname)
		e.cFileSize = Codecs.Codec.osize
		e.bHash = crc
		refcounts[e.bHash] = (e.Offset, e.FileSize, e.cFileSize, 1, e.bCompressed)
		totalBytes += e.FileSize
		print_progress(comp_start_time, totalBytes, total_input_bytes)
		fp.close() # check for ADS!!!
	return totalBytes, refcounts
	
def make_offsettable(hash, e, partnum=1):
	o = OffsetTableEntry(64*'\0')
	o.rhOffsetEntry = DiskResHdr(64*'\0')
	o.rhOffsetEntry.liOffset = e[0]
	o.rhOffsetEntry.liOriginalSize = e[1]
	o.rhOffsetEntry.ullSize = e[2]
	o.dwRefCount = e[3]
	if o.rhOffsetEntry.ullSize < o.rhOffsetEntry.liOriginalSize:
		o.rhOffsetEntry.bFlags |= 4 # mark as compressed
	o.usPartNumber = partnum
	o.bHash = hash
	logging.debug("Made offset entry for resource @0x%08X, size=%d, flags=%d", e[0], e[1], o.rhOffsetEntry.bFlags)
	return o

def make_offsetimage(codec, offset):
	o = OffsetTableEntry(64*'\0')
	o.rhOffsetEntry = DiskResHdr(64*'\0')
	o.rhOffsetEntry.ullSize = codec.osize
	o.rhOffsetEntry.bFlags = 2 # Flag as Metadata
	o.rhOffsetEntry.liOffset = offset
	o.rhOffsetEntry.liOriginalSize = Codecs.Codec.isize
	if o.rhOffsetEntry.ullSize < o.rhOffsetEntry.liOriginalSize:
		o.rhOffsetEntry.bFlags |= 4 # mark as compressed
	logging.debug("Metadata resource @%0X for %d bytes (%d original)",o.rhOffsetEntry.liOffset, o.rhOffsetEntry.ullSize, o.rhOffsetEntry.liOriginalSize)
	o.usPartNumber = 1
	o.dwRefCount = 1
	o.bHash = Codecs.Codec.sha1.digest()
	return o
	
def make_xmldata(wimTotBytes, dirCount, fileCount, totalBytes, hardlinkBytes, StartTime, StopTime, index=1, imgname='', xml=None, imgdsc=''):
	if xml:
		root = ET.XML(xml)
		# Bytes comprised between the WIM header start and the XML Data Unicode lead byte
		root.find('TOTALBYTES').text = str(wimTotBytes)
	else:
		root = ET.Element('WIM')
		ET.SubElement(root, 'TOTALBYTES').text = str(wimTotBytes)
	for node in root.iter('IMAGE'):
		if node.get('INDEX') == str(index):
			root.remove(node)
	img = ET.Element('IMAGE', INDEX=str(index))
	root.insert(index, img) # maintain <totalbytes> on top with index=1
	#~ img = ET.SubElement(root, 'IMAGE', INDEX=str(index))
	# Number of "real" directories captured, not counting the root
	ET.SubElement(img, 'DIRCOUNT').text = str(dirCount)
	# Number of captured file objects, including  junction points, hard links
	# and symbolic links (pointing to both files and directories)
	ET.SubElement(img, 'FILECOUNT').text = str(fileCount)
	# The amount of uncompressed file contents captured, including duplicates and hard linked files
	ET.SubElement(img, 'TOTALBYTES').text = str(totalBytes)
	# Total bytes for captured files represented by hard links
	ET.SubElement(img, 'HARDLINKBYTES').text = str(hardlinkBytes)
	c_time = ux2nttime(StartTime) # When image was started
	tm = ET.SubElement(img, 'CREATIONTIME')
	ET.SubElement(tm, 'HIGHPART').text = '0x%08X' % (c_time >> 32)
	ET.SubElement(tm, 'LOWPART').text = '0x%08X' % (c_time & 0x00000000FFFFFFFF)
	m_time = ux2nttime(StopTime) # When image Metadata was written
	tm = ET.SubElement(img, 'LASTMODIFICATIONTIME')
	ET.SubElement(tm, 'HIGHPART').text = '0x%08X' % (m_time >> 32)
	ET.SubElement(tm, 'LOWPART').text = '0x%08X' % (m_time & 0x00000000FFFFFFFF)
	if imgname:
		ET.SubElement(img, 'NAME').text = imgname
	if imgdsc:
		ET.SubElement(img, 'DESCRIPTION').text = imgdsc
	return ET.tostring(root).encode('utf16') # BOM required!

def make_integritytable(wim, fp):
	it = IntegrityTable(12*'\0')
	size = wim.rhOffsetTable.liOffset + wim.rhOffsetTable.ullSize - wim.cbSize
	chunk = 10 * (1 << 20)
	chunks = size / chunk
	if size%chunk: chunks += 1
	it.dwChunkSize = chunk
	it.dwNumElements = chunks
	it.cbSize = 12 + chunks*20
	for c in range(chunks):
		fp.seek(208+c*chunk)
		if c == chunks - 1:
			s = fp.read(size%chunk)
		else:
			s = fp.read(chunk)
		it.Entries += [hashlib.sha1(s).digest()]
	return it

def write_integrity_table(wim, fp):
	"Record the optional integrity table in WIM header"
	print "Building the (optional) integrity table..."
	pos = fp.tell()
	logging.debug("Writing Integrity table @0x%08X", pos)
	it = make_integritytable(wim, fp)
	fp.seek(pos)
	fp.write(it.tostr())
	wim.rhIntegrity.bFlags = 2
	wim.rhIntegrity.liOffset = pos
	wim.rhIntegrity.ullSize = wim.rhIntegrity.liOriginalSize = it.cbSize

def write_xmldata(wim, fp, xmldata):
	"Record the XMLData"
	logging.debug("Writing XML Data @0x%08X", wim.rhXmlData.liOffset)
	fp.write(xmldata)
	wim.rhXmlData.bFlags = 2 # bFlags as Metadata
	wim.rhXmlData.ullSize = fp.tell() - wim.rhXmlData.liOffset
	wim.rhXmlData.liOriginalSize = wim.rhXmlData.ullSize

def write_direntries(cout, entries, subdirs, srcdir):
	dirCount = -1 # root not counted!
	fileCount = 0
	hlinksCount = {}
	
	for e in entries:
		if not e.liLength:
			cout.write(struct.pack('<Q', 0))
			logging.debug("Wrote NULL QWORD")
			continue
		if e.dwAttributes & 0x10: # folder
			dirCount += 1
			key = e.SrcPathname
			if not key: key = srcdir
			if key in subdirs: # OR: empty folder
				e.liSubdirOffset = subdirs[key]
				logging.debug("liSubdirOffset updated to 0x%X for %s", e.liSubdirOffset, key)
		else:
			fileCount += 1
			# Tracks hard links bytes
			if e.dwReparseReserved and e.dwHardLink and e.dwReparseReserved not in (0xA000000C, 0xA000000C):
				k = e.dwReparseReserved, e.dwHardLink
				if k in hlinksCount:
					hlinksCount[k] += e.FileSize
				else:
					hlinksCount[k] = 0
		if not e.bHash: e.bHash = 20*'\0'
		cout.write(e.tostr())
		logging.debug("Wrote DIRENTRY %s", e.SrcPathname)
		for ads in e.alt_data_streams:
			cout.write(ads.tostr())
			logging.debug("Wrote STREAMENTRY %s", ads.SrcPathname)
	cout.flush()
	return dirCount, fileCount, sum(hlinksCount.values())

def finalize_wimheader(wim, fp):
	wim.dwFlags ^= 0x40 # unset FLAG_HEADER_WRITE_IN_PROGRESS
	# Rewrites the updated WIM Header
	fp.seek(0)
	fp.write(wim.tostr())
	fp.close()


def create(opts, args):
	# Note: writing to a new file is twice as faster than writing to a preexisting one!
	# It seems necessary to erase the previous file, or it becomes very slow on writing!
	if os.path.exists(args[1]):
		os.remove(args[1])
	out = open(args[1], 'wb')

	COMPRESSION_TYPE = {'none':0, 'xpress':1, 'lzx':2}[opts.compression_type.lower()]
	srcdir = args[0]

	Codecs.Codec = Codecs.CodecMT(opts.num_threads, COMPRESSION_TYPE)
	
	if opts.threshold:
		Codecs.Codec.threshold_size = opts.threshold.size
		Codecs.Codec.threshold_ratio = opts.threshold.ratio
		Codecs.Codec.threshold_ratio = opts.threshold.ratio
	
	# 1 - WIM Header
	wim = make_wimheader(COMPRESSION_TYPE)
	out.write(wim.tostr())

	AcquirePrivilege("SeBackupPrivilege")
	AcquirePrivilege("SeSecurityPrivilege")

	StartTime = time.time()

	security = make_securityblock()

	# Collects input files
	print "Collecting files..."
	direntries_size, entries, subdirs, total_input_bytes = make_direntries(srcdir, security, opts.exclude_list)
	
	# 2 - File contents
	print "Packing contents..."
	RefCounts = OrderedDict() # {sha-1: (offset, size, csize, count, flags)}
	imgTotalBytes, RefCounts = make_fileresources(out, COMPRESSION_TYPE, entries, RefCounts, total_input_bytes, StartTime)
	
	sd_raw = security.tostr()

	metadata_size = len(sd_raw) + direntries_size
		
	# 3 - Image Metadata
	image_start = out.tell()
	logging.debug("Image start @%08X", image_start)

	meta = tempfile.TemporaryFile()

	# 3.1 - Security block
	meta.write(sd_raw)

	# 3.2 - Direntries
	dirCount, fileCount, hardlinksBytes = write_direntries(meta, entries, subdirs, srcdir)

	meta_size = meta.tell() # uncomp/comp size
	meta.seek(0)
	Codecs.Codec.compress(meta, out, meta_size, True)
	
	StopTime = time.time()

	# 4 - Offset Table
	print "Building the Offsets table..."
	wim.rhOffsetTable.liOffset = out.tell()
	logging.debug("Writing Offset table @0x%08X", wim.rhOffsetTable.liOffset)
	oimg = make_offsetimage(Codecs.Codec, image_start)
	out.write(oimg.tostr())
	for e in RefCounts:
		out.write(make_offsettable(e, RefCounts[e]).tostr())
	wim.rhOffsetTable.bFlags = 2 # bFlags as Metadata
	wim.rhOffsetTable.ullSize = out.tell() - wim.rhOffsetTable.liOffset
	wim.rhOffsetTable.liOriginalSize = wim.rhOffsetTable.ullSize

	# 5 - XML Data
	print "Building the XML Data..."
	wim.rhXmlData.liOffset = out.tell()
	write_xmldata(wim, out, make_xmldata(wim.rhXmlData.liOffset, dirCount, fileCount, imgTotalBytes, hardlinksBytes, StartTime, StopTime, imgname=opts.image_name, imgdsc=opts.image_description))

	if opts.integrity_check:
		write_integrity_table(wim, out)
		
	finalize_wimheader(wim, out)

	print_timings(StartTime, StopTime)
