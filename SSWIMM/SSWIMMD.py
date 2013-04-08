'''
SWIMMD.PY - Part of Super Simple WIM Manager
Decompressor module
'''

VERSION = '0.27'

COPYRIGHT = '''Copyright (C)2012-2013, by maxpat78. GNU GPL v2 applies.
This free software creates MS WIM Archives WITH ABSOLUTELY NO WARRANTY!'''

import fnmatch
import w32_fnmatch
fnmatch.translate = w32_fnmatch.win32_translate
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
from Codecs import CodecMT


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

def get_resource(fpi, ote, null=False, target=None):
	"Test a resource and returns a stream to it, eventually expanded"
	#~ if not ote.rhOffsetEntry.liOriginalSize:
		#~ return (True, open(target, 'wb'))
	pos = fpi.tell()
	fpi.seek(ote.rhOffsetEntry.liOffset)
	if null:
		tmpres = open(('/dev/null','NUL')[sys.platform in ('win32', 'cygwin')], 'wb')
	else:
		if target:
			tmpres = open(target, 'wb')
		else:
			tmpres = tempfile.TemporaryFile()
	Codecs.Codec.decompress(fpi, ote.rhOffsetEntry.ullSize, tmpres, ote.rhOffsetEntry.liOriginalSize, True)
	fpi.seek(pos)
	tmpres.seek(0)
	return (ote.bHash == Codecs.Codec.sha1.digest(), tmpres)

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
		else:
			logging.debug("Invalid SD found at index #%d", len(sd.SDS)-1)
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

def get_xmldata_imgsize(xmlobj, index):
	for node in xmlobj.iter('IMAGE'):
		if node.get('INDEX') == str(index):
			return int(node.find('TOTALBYTES').text)

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

def get_metadata(fpi, image):
	"Returns a stream to the uncompressed Metadata resource"
	is_good, metadata = get_resource(fpi, image)
	if not is_good:
		logging.debug("FATAL: broken Metadata resource!")
		sys.exit(1)
	else:
		logging.debug("Metadata checked!")
	return metadata


# INF folder
# test: 5" [2-open] vs 2" (7z)
# apply: 20"-14" vs 9"-14" (7z) (1st to empty dir, 2nd to full dir)
# XP.wim test: 45" [open] vs 31" (7-zip)
# XP.wim test: 60" [open] vs 31" (7-zip)
# Applying the INF folder: 1'17" vs 12/14" (wimlib-imagex/7-zip)
# Applying the INF folder: 18" vs 12/14" (wimlib-imagex/7-zip)
# BUGBUG! Eliminare una JUNCTION prima di ricrearla!
# XP.wim apply: 3:07 vs 2:12 (7-zip) vs 2:36 (wimlib)
# CON updating impacts for 20" on 62?
# Applying times, perms and SDs impacts for about 10"
# XP.wim apply: 3:11 even with console off!
# 2:40 to a preexistent tree
def test(opts, args):
	StartTime = time.time()

	fpi = open(args[0], 'rb')

	print "Opening WIM unit..."
	wim = get_wimheader(fpi)

	COMPRESSION_TYPE = get_wim_comp(wim)

	Codecs.Codec = CodecMT(opts.num_threads, COMPRESSION_TYPE)

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
		metadata = get_metadata(fpi, image)

		security = get_securitydata(metadata)

		print "Collecting DIRENTRY table..."
		direntries, directories = get_direntries(metadata)

		badfiles = 0
		total_restored_files = 0
		totalOutputBytes, totalBytes = 0, 0

		NULLK = 20*'\0'
		# Simply pick the TOTALBYTES field from XML?
		for ote in direntries:
			if ote == NULLK: continue # skips NULL keys
			totalOutputBytes += offset_table[ote].rhOffsetEntry.liOriginalSize * len(direntries[ote])

		application_start_time = time.time()

		print "Testing File resources..."
		
		for ote in direntries:
			if ote == NULLK: continue
			
			fres = direntries[ote][0]
			fname = os.path.join(directories[fres._parent][1:], fres.FileName)

			is_good, file_res = get_resource(fpi, offset_table[ote], 1, fname)
			logging.debug("File resource '%s' expanded", fres.FileName)

			if not is_good:
				badfiles += 1
				print "File '%s' corrupted!" % fname
				logging.debug("CRC error for %s", fname)

			totalBytes += offset_table[ote].rhOffsetEntry.liOriginalSize
			print_progress(application_start_time, totalBytes, totalOutputBytes)			

		if badfiles:
			print "%d/%d corrupted files detected." % (badfiles,len(direntries))
		else:
			print "All File resources (%d) are OK!"%len(direntries)

	StopTime = time.time()

	print_timings(StartTime, StopTime)


def extract(opts, args):
	def is_excluded(s, excludes):
		i_pname = s[s.find('\\'):] # pathname how it will be inside the image
		# if the excluded item is a dir, we want subcontents excluded also! (x+\*)
		return True in map(lambda x:fnmatch.fnmatch(i_pname, x) or fnmatch.fnmatch(i_pname, x+'\\*'), excludes)

	StartTime = time.time()

	fpi = open(args[0], 'rb')

	print "Opening WIM unit..."
	wim = get_wimheader(fpi)

	COMPRESSION_TYPE = get_wim_comp(wim)

	Codecs.Codec = CodecMT(opts.num_threads, COMPRESSION_TYPE)

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

	if not os.path.exists(args[2]):
		print "Destination directory '%s' does not exist: aborting!" % args[2]
		sys.exit(1)

	# This is required to properly restore SDs!
	# WARNING! If applying to a preexisting folder, one could need to take the ownership of the full tree!
	AcquirePrivilege("SeRestorePrivilege")
	AcquirePrivilege("SeSecurityPrivilege")
	AcquirePrivilege("SeTakeOwnershipPrivilege")

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
		metadata = get_metadata(fpi, image)

		security = get_securitydata(metadata)

		print "Collecting DIRENTRY table..."
		direntries, directories = get_direntries(metadata)

		badfiles = 0
		total_restored_files = 0
		totalOutputBytes, totalBytes = 0, 0

		NULLK = 20*'\0'
		# Simply pick the TOTALBYTES field from XML?
		for ote in direntries:
			if ote == NULLK: continue # skips NULL keys
			totalOutputBytes += offset_table[ote].rhOffsetEntry.liOriginalSize * len(direntries[ote])

		# Sorts by on-disk resource offset
		def direntries_sort(a, b):
			if a[0] == NULLK or b[0] == NULLK: return 0
			return cmp(offset_table[a[0]].rhOffsetEntry.liOffset, offset_table[b[0]].rhOffsetEntry.liOffset)
		direntries = OrderedDict(sorted(direntries.items(), direntries_sort))
		
		application_start_time = time.time()
		
		# Recreates the target directory tree and the empty files
		for fres in direntries[NULLK]:
			fname = os.path.join(args[2], directories.get(fres._parent, " ")[1:], fres.FileName)
			if opts.exclude_list and is_excluded(fname, opts.exclude_list):
				continue
			if fres.dwAttributes & 0x10: # creates the empty directory
				if os.path.exists(fname):
					if os.path.isfile(fname):
						os.remove(fname)
				else:
					os.mkdir(fname)
			else:
				open(fname, 'wb') # creates the empty file

		print "Extracting File resources..."
		
		for ote in direntries:
			if ote == NULLK: continue
			
			first_fname = ''
			for fres in direntries[ote]: # File Resources with the same hash (duplicates, links...)
				# target pathname
				fname = os.path.join(args[2], directories[fres._parent][1:], fres.FileName)

				if opts.exclude_list and is_excluded(fname, opts.exclude_list):
					totalBytes += offset_table[ote].rhOffsetEntry.liOriginalSize
					continue

				# Expands the resource the first time, then duplicates or hardlinks it
				if first_fname:
					if fres.dwReparseReserved:
						if sys.platform in ('win32', 'cygwin'):
							#~ os.remove(fname) # can't make the hard link if the file pre exists!
							if windll.kernel32.CreateHardLinkW(fname, first_fname, 0): # no Admin required!
								logging.debug("Duplicate File resource: '%s' hard linked to '%s'", fname, first_name)
						else:
							os.link(fname, first_fname)
					else:
						shutil.copy(first_fname, fname)
						logging.debug("Duplicate File resource: copied '%s' to '%s'", first_fname, fname)
				else:
					is_good, file_res = get_resource(fpi, offset_table[ote], 0, fname)
					logging.debug("File resource '%s' expanded", fres.FileName)

					if not is_good:
						badfiles += 1
						print "File '%s' corrupted!" % fname
						logging.debug("CRC error for %s", fname)
					# ImageX puts symlink data in the STREAMENTRY, but accepts them in the DIRENTRY, too!
					if isinstance(fres, StreamEntry):
						dwReparseReserved = fres.parent.dwReparseReserved
						dwAttributes = fres.parent.dwAttributes
					else:
						dwAttributes = fres.dwAttributes
						dwReparseReserved = fres.dwReparseReserved
					# Pre-processes symbolic links and junctions
					if dwAttributes & 0x400 and sys.platform in ('win32', 'cygwin'):
						bRelative, sn, pn = ParseReparseBuf(open(file_res.name,'rb').read(32768), dwReparseReserved)
						file_res.close()
						if dwReparseReserved == 0xA000000C:
							dwFlags = bool(dwAttributes & 0x10)
							# Requires Admin privileges! Can't create if it pre-exists!
							if os.path.exists(fname) and os.path.isfile(fname): os.remove(fname)
							if not bRelative:
								sn = os.path.join(os.path.abspath(args[2]), sn[7:])
								logging.debug("Fixed absolute path string into %s", sn)
							if windll.kernel32.CreateSymbolicLinkW(fname, sn, dwFlags):
								logging.debug("Successfully created symbolic link %s => %s", fname, sn)
							else:
								logging.debug("Can't create symbolic link %s => %s", fname, sn)
						elif dwReparseReserved == 0xA0000003:
							sn = os.path.join(os.path.abspath(args[2]), sn[7:])
							if os.path.exists(fname) and os.path.isfile(fname): os.remove(fname)
							if not os.path.exists(fname): os.makedirs(fname)
							#~ os.remove(fname)
							# Admin rights not required!
							if MakeReparsePoint(dwReparseReserved, os.path.abspath(fname), sn):
								logging.debug("Successfully created junction %s => %s", fname, sn)
							else:
								logging.debug("Can't create junction %s => %s", fname, sn)
					elif dwAttributes & 0x400:
						os.symlink(fname, first_fname)

				totalBytes += offset_table[ote].rhOffsetEntry.liOriginalSize
				print_progress(application_start_time, totalBytes, totalOutputBytes)			

				total_restored_files += 1
				first_fname = fname

		# Restores times, file and security attributes in one pass
		# It fails on the root: WHY?
		print "Restoring file attributes..."
		for ote in reversed(direntries): # touch DIRs last
			for fres in direntries[ote]:
				fname = os.path.join(args[2], directories.get(fres._parent, '')[1:], fres.FileName)
				if opts.exclude_list and is_excluded(fname, opts.exclude_list):
					continue
				if sys.platform in ('win32', 'cygwin'):
					windll.kernel32.SetFileAttributesW(fname, fres.dwAttributes)
					security.apply(fres.dwSecurityId, fname)
				if hasattr(fres, 'liLastWriteTime'): # ADS haven't all attributes
					touch(fname, fres.liLastWriteTime, fres.liCreationTime, fres.liLastAccessTime)

		if badfiles:
			print "%d/%d corrupted files detected." % (badfiles,len(direntries))
		else:
			print "Successfully restored %d files."%total_restored_files

	StopTime = time.time()

	print_timings(StartTime, StopTime)
