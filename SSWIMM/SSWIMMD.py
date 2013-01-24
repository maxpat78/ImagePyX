'''
SWIMMD.PY - Part of Super Simple WIM Manager
Decompressor module
'''

VERSION = '0.22'

COPYRIGHT = '''Copyright (C)2012-2013, by maxpat78. GNU GPL v2 applies.
This free software creates MS WIM Archives WITH ABSOLUTELY NO WARRANTY!'''

import fnmatch
import hashlib
import logging
import optparse
import os
import struct
import sys
import time
import tempfile
from ctypes import *
from datetime import datetime as dt
from xml.etree import ElementTree as ET
from WIMArchive import *

def copy(src, dst):
	while 1:
		s = src.read(32768)
		if dst: dst.write(s)
		if len(s) < 32768: break

def get_wimheader(fp):
	fp.seek(0)
	wimh = WIMHeader(fp.read(208))
	wimh.test()
	logging.debug("WIM Header found:\n%s", wimh)
	return wimh

def check_integrity(wim, fp):
	if not wim.rhIntegrity.liOffset: return -1
	fp.seek(wim.rhIntegrity.liOffset)
	it = IntegrityTable(fp.read(wim.rhIntegrity.ullSize))
	logging.debug("Integrity table found @%08X, %d entries.", wim.rhIntegrity.liOffset, it.dwNumElements)
	size = wim.rhOffsetTable.liOffset + wim.rhOffsetTable.ullSize - wim.cbSize
	status = 0
	for c in range(it.dwNumElements):
		fp.seek(208+c*it.dwChunkSize)
		if c == it.dwNumElements - 1:
			s = fp.read(size%it.dwChunkSize)
		else:
			s = fp.read(it.dwChunkSize)
		if it.Entries[c] != hashlib.sha1(s).digest():
			status = 1
			logging.debug("Chunk %d failed integrity check", c)
		else:
			logging.debug("Chunk %d passed integrity check", c)
	return status

def get_xmldata(fp, wim):
	pos = fp.tell()
	fp.seek(wim.rhXmlData.liOffset)
	s = fp.read(wim.rhXmlData.liOriginalSize).decode('utf-16')
	fp.seek(pos)
	return s
	
def get_offsettable(fp, wim):
	"Build a dictionary from the offset table entries, ordered by hash"
	fp.seek(wim.rhOffsetTable.liOffset)
	otab = {}
	while fp.tell() < wim.rhOffsetTable.liOffset + wim.rhOffsetTable.liOriginalSize:
		ote = OffsetTableEntry(fp.read(50))
		otab[ote.bHash] = ote
	return otab

def get_images(fp, wim):
	"Retrieve the image resources from the offset table entries"
	# Image resources have to be ordered by offset in the Offset table
	images = [] # an image entry MAY be repeated if metadatas are equal!
	fp.seek(wim.rhOffsetTable.liOffset)
	while fp.tell() < wim.rhOffsetTable.liOffset + wim.rhOffsetTable.liOriginalSize:
		ote = OffsetTableEntry(fp.read(50))
		if ote.rhOffsetEntry.bFlags & 2: # Image resource
			logging.debug("Image Metadata resource found @%08X", ote.rhOffsetEntry.liOffset)
			images += [ote]
	if not images:
		logging.debug("FATAL: no image found!")
		raise BadWim
	return images

def get_resource(fp, ote, defaultcomp=0):
	fp.seek(ote.rhOffsetEntry.liOffset)
	if not ote.rhOffsetEntry.bFlags & 4:
		res_comp = 0
	else:
		res_comp = defaultcomp
	return InputStream(fp, ote.rhOffsetEntry.liOriginalSize, ote.rhOffsetEntry.ullSize, res_comp)

def get_direntries(fp):
	"Build the DIRENTRY table and reconstructs the original tree"
	fp.seek(0)
	sd_size = struct.unpack('<I', fp.read(4))[0]
	fp.seek(sd_size)
	direntries = {}
	directories = {}
	parent = -1 # parent's offset == key in directories dict
	while 1:
		pos = fp.tell()
		if pos in directories: parent = pos
		s = fp.read(8)
		if not s: break
		size = struct.unpack('<Q', s)[0] & 0x00FFFFFFFFFFFFFF
		if size:
			fp.seek(-8, 1)
			d = DirEntry(fp.read(size))
			d._pos = pos
			d._parent = parent
			if d.bHash in direntries:
				direntries[d.bHash] += (d,)
			else:
				direntries[d.bHash] = (d,)
			logging.debug("Parsed DIRENTRY @0x%08X:\n%s", pos, d)
			if d.dwAttributes & 0x10:
				if d.FileName == '':
					fname = '\\'
				else:
					fname = d.FileName
				fname = os.path.join(directories.get(parent,''), fname)
				directories[d.liSubdirOffset] = fname
				logging.debug("Directory '%s' @0x%08x, contents @0x%08x", fname, d._pos, d.liSubdirOffset)
		else:
			logging.debug("Parsed End of Directory NULL marker")
	return direntries, directories

def get_xmldata_root(wim, fp):
	pos = fp.tell()
	fp.seek(wim.rhXmlData.liOffset)
	xml = fp.read(wim.rhXmlData.ullSize)
	root = ET.XML(xml)
	fp.seek(pos)
	return root

def get_xmldata_imgname(xmlobj, index):
	for node in xmlobj.iter('IMAGE'):
		if node.get('INDEX') == str(index):
			return node.find('NAME').text

def get_xmldata_imgindex(xmlobj, name):
	for node in xmlobj.iter('IMAGE'):
		n = node.find('NAME')
		if n is not None and n.text.lower() == name.lower():
			return int(node.get('INDEX'))

def get_xmldata_imgctime(xmlobj, index):
	for node in xmlobj.iter('IMAGE'):
		if node.get('INDEX') == str(index):
			c_time = int(node.find('CREATIONTIME/HIGHPART').text, 16)
			c_time = (c_time << 32) | int(node.find('CREATIONTIME/LOWPART').text, 16)
			return nt2uxtime(c_time)

def get_xmldata_imgmtime(xmlobj, index):
	for node in xmlobj.iter('IMAGE'):
		if node.get('INDEX') == str(index):
			m_time = int(node.find('LASTMODIFICATIONTIME/HIGHPART').text, 16)
			m_time = (m_time << 32) | int(node.find('LASTMODIFICATIONTIME/LOWPART').text, 16)
			return nt2uxtime(m_time)

def get_image_from_id(wim, fp, id):
	try:
		img_index = int(id)
	except ValueError:
		logging.debug("Searching index for Image named '%s'...", id)
		root = get_xmldata_root(wim, fp)
		img_index = get_xmldata_imgindex(root, id)
		if not img_index:
			print "Image '%s' doesn't exist!" % id
			sys.exit(1)
	return img_index

def extract_test(opts, args, testmode=False):
	def make_dest(prefix, suffix, check=False):
		s = os.path.join(prefix, suffix[1:])
		if not os.path.exists(os.path.dirname(s)):
			os.makedirs(os.path.dirname(s))
		# Overwrite by default, like ImageX: provide an option to choose?
		return open(s, 'wb')

	def is_excluded(s, excludes):
		i_pname = s[s.find('\\'):] # pathname how it will be inside the image
		# if the excluded item is a dir, we want subcontents excluded also! (x+\*)
		return True in map(lambda x:fnmatch.fnmatch(i_pname, x) or fnmatch.fnmatch(i_pname, x+'\\*'), excludes)

	StartTime = time.time()

	fpi = open(args[0], 'rb')

	print "Opening WIM unit..."
	wim = get_wimheader(fpi)

	COMPRESSION_TYPE = 0
	if wim.dwFlags & 0x20000:
		COMPRESSION_TYPE = 1
	elif wim.dwFlags & 0x40000:
		COMPRESSION_TYPE = 2

	print "Compression is", ('none', 'XPRESS', 'LZX')[COMPRESSION_TYPE]

	offset_table = get_offsettable(fpi, wim)
	
	if len(args) > 1:
		img_index = get_image_from_id(wim, fpi, args[1])
	else:
		img_index = 0
		
	images = get_images(fpi, wim)
	
	if img_index > len(images):
		print "Image index doesn't exist!"
		sys.exit(1)
	img_index -= 1
	
	if img_index > -1:
		images = [images[img_index]]

	if not testmode:
		if not os.path.exists(args[2]):
			print "Destination directory '%s' does not exist: aborting!" % args[2]
			sys.exit(1)

	for image in images:
		img_index += 1
		
		print "Processing Image #%d" % (1, img_index)[img_index > 0]
		
		status = check_integrity(wim, fpi)
		if status == -1:
			print "Integrity table not present"
		elif status:
			print "Integrity verification failed"
		else:
			print "Integrity check passed!"

		print "Opening Metadata resource..."
		metadata_res = get_resource(fpi, image, COMPRESSION_TYPE)

		metadata = tempfile.TemporaryFile()
		copy(metadata_res, metadata)

		if metadata_res.sha1.digest() != image.bHash:
			logging.debug("FATAL: broken Metadata resource!")
			sys.exit(1)
		else:
			logging.debug("Metadata checked!")

		#~ sd = SecurityData(metadata.read(image.rhOffsetEntry.ullSize))
		#~ print "Security descriptors:", sd.liEntries

		print "Collecting DIRENTRY table..."
		direntries, directories = get_direntries(metadata)

		badfiles = 0
		total_restored_files = 1
		totalOutputBytes, totalBytes = 0, 0
		for ote in offset_table.values():
			totalOutputBytes +=ote.rhOffsetEntry.liOriginalSize
		
		if not testmode:
			print "Extracting File resources..."
			# calculates total bytes to extract
		else:
			print "Testing File resources..."
			
		for ote in offset_table.values():
			# Skip Images
			if ote.rhOffsetEntry.bFlags & 2: continue
			file_res = get_resource(fpi, ote, COMPRESSION_TYPE)
			if ote.bHash in direntries:
				fname = direntries[ote.bHash][0].FileName
			else:
				fname = '[Unnamed entry]'
				if not testmode:
					# Skips unnamed entry, not belonging to processed image
					continue
			if ote.bHash in direntries and direntries[ote.bHash][0]._parent in directories:
				fname = os.path.join(directories[direntries[ote.bHash][0]._parent],fname)
			else:
				fname = '[Unnamed entry]'
				
			if not testmode:
				if not opts.exclude_list or not is_excluded(fname, opts.exclude_list):
					dst = make_dest(args[2], fname)
					copy(file_res, dst)
					dst.close()
					os.utime(dst.name, (direntries[ote.bHash][0].liLastAccessTime/10000000 - 11644473600, direntries[ote.bHash][0].liLastWriteTime/10000000 - 11644473600))
					if sys.platform in ('win32', 'cygwin'):
						windll.kernel32.SetFileAttributesW(dst.name, direntries[ote.bHash][0].dwAttributes)
					total_restored_files += 1
				else:
					totalBytes += ote.rhOffsetEntry.liOriginalSize
					continue
			else:
				copy(file_res, None)
				
			totalBytes += ote.rhOffsetEntry.liOriginalSize
			print_progress(StartTime, totalBytes, totalOutputBytes)			
			if file_res.sha1.digest() != ote.bHash:
				badfiles += 1
				print "File '%s' corrupted!", fname
				logging.debug("CRC error for %s", fname)
			else:
				logging.debug("Good CRC for %s", fname)

		if badfiles:
			print "%d/%d corrupted files detected." % (badfiles,len(direntries))
		else:
			if not testmode:
				if total_restored_files == len(direntries):
					print "Successfully restored %d files."%len(direntries)
				else:
					print "Successfully restored %d files (%d excluded)." % (total_restored_files, len(direntries)-total_restored_files)
			else:
				print "All File resources (%d) are OK!"%len(direntries)

	StopTime = time.time()

	print "Done. %s time elapsed." % datetime.timedelta(seconds=int(StopTime-StartTime))
