'''
SWIMMD.PY - Part of Super Simple WIM Manager
Decompressor module
'''

VERSION = '0.26'

COPYRIGHT = '''Copyright (C)2012-2013, by maxpat78. GNU GPL v2 applies.
This free software creates MS WIM Archives WITH ABSOLUTELY NO WARRANTY!'''

import fnmatch
import hashlib
import logging
import optparse
import os
import shutil
import struct
import sys
import time
import tempfile
from ctypes import *
from collections import OrderedDict
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
	otab = OrderedDict()
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

def get_securitydata(fp):
	"Build the SecurityData hash table"
	sd = SecurityData(255*'\0')
	fp.seek(0)
	sd_size = struct.unpack('<I', fp.read(4))[0]
	sd_nument = struct.unpack('<I', fp.read(4))[0]
	sd_ent = []
	for i in range(sd_nument):
		sd_ent += [struct.unpack('<Q', fp.read(8))[0]]
	for i in sd_ent:
		s = fp.read(i)
		if windll.advapi32.IsValidSecurityDescriptor(s):
			sd.SDS[hashlib.sha1(s).digest()] = create_string_buffer(s)
			logging.debug("Retrieved valid SD with index #%d", len(sd.SDS)-1)
	return sd
	
def get_direntries(fp):
	"Build the DIRENTRY table and reconstructs the original tree"
	fp.seek(0)
	sd_size = struct.unpack('<I', fp.read(4))[0]
	sd_size += 8 - (sd_size%8) & 7 # it's QWORD aligned!
	fp.seek(sd_size)
	direntries = OrderedDict()
	directories = OrderedDict()
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
			d.alt_data_streams = [] # collects the ADS
			if d.bHash in direntries:
				direntries[d.bHash] += (d,)
			else:
				direntries[d.bHash] = (d,)
			logging.debug("Parsed DIRENTRY @0x%08X:\n%s", pos, d)
			# Parses the alternate data streams if present
			for i in range(d.wStreams):
				size = struct.unpack('<Q', fp.read(8))[0] & 0x00FFFFFFFFFFFFFF
				fp.seek(-8, 1)
				pos = fp.tell()
				se = StreamEntry(fp.read(size))
				se.parent = d # Parent DIRENTRY: hack for symlinks
				if se.FileName:
					se.FileName = d.FileName + ':' + se.FileName
				else: # the unnamed stream is the main one!
					se.FileName = d.FileName
				se._parent = parent
				d.alt_data_streams += [se]
				if se.bHash in direntries:
					direntries[se.bHash] += (se,)
				else:
					direntries[se.bHash] = (se,)
				logging.debug("Parsed STREAMENTRY @0x%08X:\n%s", pos, se)
			# A symlink to a directory isn't a real directory; a junction is
			if d.dwAttributes & 0x10 and d.dwReparseReserved != 0xA000000C:
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

def get_metadata(fpi, image, compType):
	"Returns a stream to the uncompressed Metadata resource"
	metadata_res = get_resource(fpi, image, compType)

	metadata = tempfile.TemporaryFile()
	copy(metadata_res, metadata)

	if metadata_res.sha1.digest() != image.bHash:
		logging.debug("FATAL: broken Metadata resource!")
		sys.exit(1)
	else:
		logging.debug("Metadata checked!")
	return metadata


def extract_test(opts, args, testmode=False):
	def make_dest(prefix, suffix, check=False, create=True):
		s = os.path.join(prefix, suffix[1:])
		if not os.path.exists(os.path.dirname(s)):
			os.makedirs(os.path.dirname(s))
		if create:
			# Overwrite by default, like ImageX: provide an option to choose?
			if os.path.exists(s) and os.path.isfile(s): os.remove(s)
			return open(s, 'wb')
		else:
			return s

	def is_excluded(s, excludes):
		i_pname = s[s.find('\\'):] # pathname how it will be inside the image
		# if the excluded item is a dir, we want subcontents excluded also! (x+\*)
		return True in map(lambda x:fnmatch.fnmatch(i_pname, x) or fnmatch.fnmatch(i_pname, x+'\\*'), excludes)

	StartTime = time.time()

	fpi = open(args[0], 'rb')

	print "Opening WIM unit..."
	wim = get_wimheader(fpi)

	COMPRESSION_TYPE = get_wim_comp(wim)

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
		metadata = get_metadata(fpi, image, COMPRESSION_TYPE)

		security = get_securitydata(metadata)

		print "Collecting DIRENTRY table..."
		direntries, directories = get_direntries(metadata)
		
		badfiles = 0
		total_restored_files = 0
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

			if ote.bHash not in direntries:
				continue # Skips unnamed entry, not belonging to processed image
				
			if not testmode:
				# Recreates the directories, included the empty ones
				for d in directories.values():
					make_dest(args[2], d+'/dummy', create=False)
				
			if not testmode:
				expanded_source = ''
				for fres in direntries[ote.bHash]:
					fname = os.path.join(directories[fres._parent], fres.FileName)
					if not opts.exclude_list or not is_excluded(fname, opts.exclude_list):
						# Expands the resource the first time, then duplicates or hardlinks it
						if expanded_source:
							dst = make_dest(args[2], fname)
							dst.close()
							if fres.dwReparseReserved and sys.platform in ('win32', 'cygwin'):
								os.remove(dst.name) # can't make the hard link if the file pre exists!
								if windll.kernel32.CreateHardLinkW(dst.name, expanded_source, 0): # no Admin required!
									logging.debug("Duplicate File resource: '%s' hard linked to '%s'", dst.name, expanded_source)
							else:
								shutil.copy(expanded_source, dst.name)
								logging.debug("Duplicate File resource: copied '%s' to '%s'", expanded_source, dst.name)
						else:
							# ImageX puts symlink data in the STREAMENTRY, but accepts them in the DIRENTRY, too!
							if isinstance(fres, StreamEntry):
								dwReparseReserved = fres.parent.dwReparseReserved
								dwAttributes = fres.parent.dwAttributes
							else:
								dwAttributes = fres.dwAttributes
								dwReparseReserved = fres.dwReparseReserved
							# Pre-processes symbolic links and junctions
							if dwAttributes & 0x400:
								dst = make_dest(args[2], fname, create=False)
								bRelative, sn, pn = ParseReparseBuf(file_res.read(32768), dwReparseReserved)
								if dwReparseReserved == 0xA000000C:
									dwFlags = bool(dwAttributes & 0x10)
									# Requires Admin privileges! Can't create if it pre-exists!
									if os.path.exists(dst) and os.path.isfile(dst): os.remove(dst)
									if not bRelative:
										sn = os.path.join(os.path.abspath(args[2]), sn[7:])
										logging.debug("Fixed absolute path string into %s", sn)
									if windll.kernel32.CreateSymbolicLinkW(dst, sn, dwFlags):
										logging.debug("Successfully created symbolic link %s => %s", dst, sn)
									else:
										logging.debug("Can't create symbolic link %s => %s", dst, sn)
								elif dwReparseReserved == 0xA0000003:
									sn = os.path.join(os.path.abspath(args[2]), sn[7:])
									if not os.path.exists(dst): os.makedirs(dst)
									# Admin rights not required!
									if MakeReparsePoint(dwReparseReserved, os.path.abspath(dst), sn):
										logging.debug("Successfully created junction %s => %s", dst, sn)
									else:
										logging.debug("Can't create junction %s => %s", dst, sn)
							else:
								dst = make_dest(args[2], fname)
								copy(file_res, dst)
								dst.close()
								expanded_source = dst.name
								logging.debug("File resource expanded to '%s'", expanded_source)
						if hasattr(fres, 'liLastWriteTime'): # ADS haven't all attributes
							touch(dst.name, fres.liLastWriteTime, fres.liCreationTime, fres.liLastAccessTime)
							if sys.platform in ('win32', 'cygwin'):
								windll.kernel32.SetFileAttributesW(dst.name, fres.dwAttributes)
								security.apply(fres.dwSecurityId, dst.name)
						total_restored_files += 1
					else:
						totalBytes += ote.rhOffsetEntry.liOriginalSize
						continue
			else:
				copy(file_res, None)
				fname = direntries[ote.bHash][0].FileName
				
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
				print "Successfully restored %d files."%total_restored_files
			else:
				print "All File resources (%d) are OK!"%len(direntries)

	StopTime = time.time()

	print_timings(StartTime, StopTime)
