'''
SSWIMMC.PY - Super Simple WIM Manager
Creator module - Multithreaded version
'''

VERSION = '0.23'

COPYRIGHT = '''Copyright (C)2012-2013, by maxpat78. GNU GPL v2 applies.
This free software creates MS WIM Archives WITH ABSOLUTELY NO WARRANTY!'''

import fnmatch
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


def copy(pathname, stream, _blklen=32*1024):
	"Copies a file content to a previously opened output stream"
	if type(pathname) in (type(''), type(u'')):
		fp = open(pathname, 'rb')
	else:
		fp = pathname
	while 1:
		s = fp.read(_blklen)
		stream.write(s)
		if len(s) < _blklen: break

def take_sha(pathname, _blklen=32*1024):
	"Calculates the SHA-1 for file contents"
	if type(pathname) in (type(''), type(u'')):
		fp = open(pathname, 'rb')
	else:
		fp = pathname
	sha = hashlib.sha1()
	while 1:
		s = fp.read(_blklen)
		sha.update(s)
		if len(s) < _blklen: break
	fp.close()
	return sha

def make_wimheader(compress=1):
	wim = WIMHeader(208*'\0')
	wim.ImageTag = 'MSWIM\0\0\0'
	wim.cbSize = 0xD0
	wim.dwVersion = 0x00010D00 # 1.13
	if compress == 1:
		wim.dwFlags = 2 | 0x20000 # XPRESS compressed
		wim.dwCompressionSize = 0x8000
	elif compress == 2:
		wim.dwFlags = 2 | 0x40000 # LZX compressed
		wim.dwCompressionSize = 0x8000
	else:
		wim.dwFlags = 0 # Uncompressed
		wim.dwCompressionSize = 0
	wim.dwFlags |= 0x40 # set FLAG_HEADER_WRITE_IN_PROGRESS
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

def make_direntry(pathname, isroot=0):
	e = DirEntry(255*'\0')
	if len(pathname) < 255:
		st = os.stat(pathname)
	else:
		st = os.stat('\\\\?\\'+os.path.abspath(pathname))
	e.FileSize = st.st_size
	if sys.platform in ('win32', 'cygwin'):
		e.dwAttributes = windll.kernel32.GetFileAttributesW(pathname)
		if e.dwAttributes == -1:
			logging.debug("GetFileAttributesW returned -1 on %s", pathname)
			e.dwAttributes = 0x20
		#~ short_pathname = create_string_buffer(len(pathname)*2+2)
		#~ print windll.kernel32.GetShortPathNameW(pathname, short_pathname, 2*len(pathname)+2)
		#~ print short_pathname.raw
	if os.path.isfile(pathname):
		e.dwAttributes = 0x20
	else:
		e.dwAttributes |= 0x10
		if isroot: pathname = ''
	e.SrcPathname = pathname
	e.dwSecurityId = -1
	e.liCreationTime = ux2nttime(st.st_ctime)
	e.liLastWriteTime = ux2nttime(st.st_mtime)
	e.liLastAccessTime = ux2nttime(st.st_atime)
	base = os.path.basename(pathname)
	e.wFileNameLength = len(base) * 2
	e.FileName = base.encode('utf-16le')
	if e.wFileNameLength:
		addendum = 8
	else:
		addendum = 6
	e.liLength = (0x66+e.wFileNameLength+addendum) & -7
	e.bHash = 0
	return e

def make_securityblock():
	e = SecurityData(255*'\0')
	e.dwTotalLength = 8
	e.dwNumEntries = 0
	return e

def make_direntries(directory, excludes=None):
	def is_excluded(s, excludes):
		i_pname = s[s.find('\\'):] # pathname how it will be inside the image
		# if the excluded item is a dir, we want subcontents excluded also! (x+\*)
		return True in map(lambda x:fnmatch.fnmatch(i_pname, x) or fnmatch.fnmatch(i_pname, x+'\\*'), excludes)
	directory = os.path.normpath(unicode(directory))
	direntries = []
	total_input_bytes = 0

	# root DIRENTRY offset relative to Metadata resource start
	pos = 8 # relative offset of the next subdir content
	subdirs = OrderedDict() # {parent folder: childs offset}
	for root, dirs, files in os.walk(directory):
		logging.debug("root is now %s", root)
		if excludes and is_excluded(root, excludes):
			logging.debug("Excluded root %s", root)
			continue
		if root == directory:
			direntries += [make_direntry(root,1)]
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
			direntries += [make_direntry(pname)]
			pos += direntries[-1].liLength
			total_input_bytes += direntries[-1].FileSize
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
			direntries += [make_direntry(pname)]
			logging.debug("Made Folder DIRENTRY %s", item)
			pos += direntries[-1].liLength
			total_input_bytes += direntries[-1].FileSize
		if root not in subdirs: # an empty folder must point to the following NULL QWORD
			subdirs[root] = pos
		direntries += [DirEntry(255*'\0')]
		pos += 8
		logging.debug("Made NULL QWORD (end of folder)")
	return pos, direntries, subdirs, total_input_bytes

def compressor_thread(q, refcounts):
	while True:
		e, done = q.get()
		# Try to save compressor cost at the expense of read inputs twice.
		crc = take_sha(e.SrcPathname).digest()
		if crc in refcounts:
			e.bHash = crc
			done += [e]
			q.task_done()
			continue
		tmp = tempfile.SpooledTemporaryFile()
		cout = OutputStream(tmp, e.FileSize, e.bCompressed)
		copy(e.SrcPathname, cout) # how to treat locked/unaccessible files? truncate them to 0?
		cout.flush()
		cout.fp.seek(0)
		e.cFileSize = cout.csize()
		e.bHash = crc
		if e.cFileSize >= e.FileSize: # rewrites uncompressed, if shorter
			e.bCompressed = 0
			e.cFileSize = e.FileSize
			cout.fp = open(e.SrcPathname, 'rb')
			logging.debug("File not decreased (+%d bytes), storing uncompressed!", e.cFileSize - e.FileSize)
		e._stream = cout.fp
		done += [e]
		q.task_done()
		
def make_fileresources(out, comp, entries, refcounts, total_input_bytes, start_time):
	"Packs the files content into the image, discarding duplicates according to their SHA-1"
	totalBytes = 0 # Total bytes for files uncompressed content, duplicates included
	done = []
	
	q = Queue.Queue()
	
	if not comp:
		num_threads = 1 # or raises IOError: [Errno 24] Too many open files
	else:
		num_threads = 3
	
	for i in range(num_threads):
		T = threading.Thread(target=compressor_thread, args=(q, refcounts))
		T.daemon = True
		T.start()

	todo_entries = 0
	for entry in entries:
		# Skips folders, NULL entries and empty files
		if entry.dwAttributes & 0x10 or not entry.liLength or not entry.FileSize: continue
		entry.bCompressed = comp
		q.put((entry, done), False)
		todo_entries += 1
	
	done_entries = 0
	while done_entries < todo_entries:
		if not done:
			time.sleep(0.015)
			continue
		e = done.pop(0)
		done_entries += 1
		totalBytes += e.FileSize
		print_progress(start_time, totalBytes, total_input_bytes)
		if e.bHash in refcounts:
			h = refcounts[e.bHash]
			refcounts[e.bHash] = (h[0], h[1], h[2], h[3]+1, h[4])
			logging.debug("Discarded %s (hash collision)", e.SrcPathname)
			e.Offset = h[0]
		else:
			e.Offset = out.tell() # Fileresource start offset inside WIM
			logging.debug("Starting new File resource @%08X", e.Offset)
			refcounts[e.bHash] = (e.Offset, e.FileSize, e.cFileSize, 1, e.bCompressed)
			copy(e._stream, out)
			e._stream.close()
			logging.debug("Wrote content from %s", e.SrcPathname)
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

def make_offsetimage(cstream, offset):
	o = OffsetTableEntry(64*'\0')
	o.rhOffsetEntry = DiskResHdr(64*'\0')
	o.rhOffsetEntry.ullSize = cstream.csize()
	o.rhOffsetEntry.bFlags = 2 # Flag as Metadata
	o.rhOffsetEntry.liOffset = offset
	o.rhOffsetEntry.liOriginalSize = cstream.size
	if o.rhOffsetEntry.ullSize < o.rhOffsetEntry.liOriginalSize:
		o.rhOffsetEntry.bFlags |= 4 # mark as compressed
	logging.debug("Metadata resource @%0X for %d bytes (%d original)",o.rhOffsetEntry.liOffset, o.rhOffsetEntry.ullSize, o.rhOffsetEntry.liOriginalSize)
	o.usPartNumber = 1
	o.dwRefCount = 1
	o.bHash = cstream.sha1.digest()
	return o
	
def make_xmldata(wimTotBytes, dirCount, fileCount, totalBytes, StartTime, StopTime, index=1, imgname='', xml=None, imgdsc=''):
	if xml:
		root = ET.XML(xml)
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
	ET.SubElement(img, 'DIRCOUNT').text = str(dirCount)
	ET.SubElement(img, 'FILECOUNT').text = str(fileCount)
	ET.SubElement(img, 'TOTALBYTES').text = str(totalBytes)
	ET.SubElement(img, 'HARDLINKBYTES').text = str(0)
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
		if not e.bHash: e.bHash = 20*'\0'
		cout.write(e.tostr())
		logging.debug("Wrote DIRENTRY %s", e.SrcPathname)
	cout.flush()
	return dirCount, fileCount

def finalize_wimheader(wim, fp):
	wim.dwFlags ^= 0x40 # unset FLAG_HEADER_WRITE_IN_PROGRESS
	# Rewrites the updated WIM Header
	fp.seek(0)
	fp.write(wim.tostr())
	fp.close()
	
	
def create(opts, args):
	out = open(args[0], 'w+b')
	COMPRESSION_TYPE = {'none':0, 'xpress':1, 'lzx':2}[opts.compression_type.lower()]
	srcdir = args[1]
	
	# 1 - WIM Header
	wim = make_wimheader(COMPRESSION_TYPE)
	out.write(wim.tostr())

	StartTime = time.time()

	# Collects input files
	print "Collecting files..."
	direntries_size, entries, subdirs, total_input_bytes = make_direntries(srcdir, opts.exclude_list)
	
	# 2 - File contents
	print "Packing contents..."
	RefCounts = OrderedDict() # {sha-1: (offset, size, csize, count, flags)}
	imgTotalBytes, RefCounts = make_fileresources(out, COMPRESSION_TYPE, entries, RefCounts, total_input_bytes, StartTime)
	
	metadata_size = direntries_size # in fact should be: security_size + direntries_size
		
	# 3 - Image Metadata
	image_start = out.tell()
	logging.debug("Image start @%08X", image_start)

	meta = tempfile.TemporaryFile()
	cout = OutputStream(meta, metadata_size, COMPRESSION_TYPE)

	# 3.1 - Security block (empty)
	cout.write(make_securityblock().tostr())

	dirCount, fileCount = write_direntries(cout, entries, subdirs, srcdir)
	
	# Restores the uncompressed Metadata if it didn't get smaller
	meta.seek(0)
	if cout.csize() >= metadata_size:
		cinp = InputStream(meta, metadata_size, cout.csize(), COMPRESSION_TYPE)
		cout = OutputStream(out, metadata_size, 0)
		copy(cinp, cout)
		logging.debug("Restored the uncompressed Metadata")
	else:
		cout2 = OutputStream(out, metadata_size, 0)
		copy(meta, cout2)
		logging.debug("Copied the compressed Metadata")

	StopTime = time.time()

	# 5 - Offset Table
	print "Building the Offsets table..."
	wim.rhOffsetTable.liOffset = out.tell()
	logging.debug("Writing Offset table @0x%08X", wim.rhOffsetTable.liOffset)
	oimg = make_offsetimage(cout, image_start)
	out.write(oimg.tostr())
	for e in RefCounts:
		out.write(make_offsettable(e, RefCounts[e]).tostr())
	wim.rhOffsetTable.bFlags = 2 # bFlags as Metadata
	wim.rhOffsetTable.ullSize = out.tell() - wim.rhOffsetTable.liOffset
	wim.rhOffsetTable.liOriginalSize = wim.rhOffsetTable.ullSize

	print "Building the XML Data..."
	wim.rhXmlData.liOffset = out.tell()
	write_xmldata(wim, out, make_xmldata(wim.rhXmlData.liOffset, dirCount, fileCount, imgTotalBytes, StartTime, StopTime, imgname=opts.image_name, imgdsc=opts.image_description))

	if opts.integrity_check:
		write_integrity_table(wim, out)
		
	finalize_wimheader(wim, out)

	print_timings(StartTime, StopTime)
