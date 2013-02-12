'''
SWIMMU.PY - Part of Super Simple WIM Manager
Updater module
'''

VERSION = '0.25'

COPYRIGHT = '''Copyright (C)2012-2013, by maxpat78. GNU GPL v2 applies.
This free software creates MS WIM Archives WITH ABSOLUTELY NO WARRANTY!'''

import hashlib
import logging
import os
import Queue
import struct
import sys
import tempfile
import threading
from ctypes import *
from collections import OrderedDict
from datetime import datetime as dt
from WIMArchive import *
from SSWIMMC import *
from SSWIMMD import *

def update(opts, args):
	srcdir = args[0]
	if not os.path.exists(srcdir):
		print "Source folder does not exist!"
		sys.exit(1)
		
	RefCounts = OrderedDict()
	
	StartTime = time.time()

	out = open(args[1], 'r+b')
	out.seek(0)
	
	wim = get_wimheader(out)
	wim_is_clean(wim, out)
	
	if wim.dwFlags & 4: #FLAG_HEADER_READONLY
		print "WIM header has READ-ONLY flag set, aborting update..."
		sys.exit(1)
		
	COMPRESSION_TYPE = get_wim_comp(wim)

	offset_table = get_offsettable(out, wim)
	images = get_images(out, wim)

	image_index_to_update = get_image_from_id(wim, out, args[2])

	if image_index_to_update > len(images):
		print "Image to update doesn't exist!"
		sys.exit(1)

	print "Opening WIM for update, image #%d..." % image_index_to_update
	image_index_to_update -= 1
	
	for o in offset_table.values():
		if o.rhOffsetEntry.bFlags & 2: # skips image resource
			continue
		RefCounts[o.bHash] = [o.rhOffsetEntry.liOffset, o.rhOffsetEntry.liOriginalSize, o.rhOffsetEntry.ullSize, o.dwRefCount, o.rhOffsetEntry.bFlags]

	print "Opening Metadata resource..."
	metadata = get_metadata(out, images[image_index_to_update], COMPRESSION_TYPE)

	direntries, directories = get_direntries(metadata)

	for e in direntries:
		if e in RefCounts:
			RefCounts[e][3] = RefCounts[e][3] - len(direntries[e]) # decrease dwRefCount by amount referred to this image

	security = make_securityblock()

	# Collects input files
	print "Collecting new files..."
	direntries_size, entries, subdirs, total_input_bytes = make_direntries(srcdir, security, opts.exclude_list)

	# Flags the header for writing in progress
	wim.dwFlags |= 0x40
	out.seek(0)
	out.write(wim.tostr())
	
	out.seek(0, 2)
	
	print "Packing contents..."
	totalBytes, RefCounts = make_fileresources(out, COMPRESSION_TYPE, entries, RefCounts, total_input_bytes, StartTime)

	sd_raw = security.tostr()

	metadata_size = len(sd_raw) + direntries_size
	
	image_start = out.tell()
	logging.debug("Image start @%08X", image_start)

	meta = tempfile.TemporaryFile()
	cout = OutputStream(meta, metadata_size, COMPRESSION_TYPE)

	cout.write(security.tostr())

	dirCount, fileCount = write_direntries(cout, entries, subdirs, srcdir)

	meta.seek(0)
	if cout.sha1.digest() in offset_table:
		print "No files to add, image is equal to another one!"
		logging.debug("Image already stored, merging the Metadata!")
		image_already_stored = True
	else:
		image_already_stored = False
		# Restores the uncompressed Metadata if it didn't get smaller
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

	print "Building the Offsets table..."
	wim.rhOffsetTable.liOffset = out.tell()
	logging.debug("Writing Offset table @0x%08X", wim.rhOffsetTable.liOffset)
	if not image_already_stored:
		images[image_index_to_update] = make_offsetimage(cout, image_start)
	else:
		crc = cout.sha1.digest()
		for i in range(len(images)):
			if images[i].bHash == crc:
				images[image_index_to_update] = images[i]
				break
	for img in images:
		logging.debug("Writing offset entry for image @0x%08X", img.rhOffsetEntry.liOffset)
		out.write(img.tostr())
	for e in RefCounts:
		out.write(make_offsettable(e, RefCounts[e]).tostr())
	wim.rhOffsetTable.bFlags = 2 # bFlags as Metadata
	wim.rhOffsetTable.ullSize = out.tell() - wim.rhOffsetTable.liOffset
	wim.rhOffsetTable.liOriginalSize = wim.rhOffsetTable.ullSize

	print "Updating the XML Data..."
	xml = get_xmldata(out, wim)
	wim.rhXmlData.liOffset = out.tell()
	xml = make_xmldata(wim.rhXmlData.liOffset, dirCount, fileCount, totalBytes, StartTime, StopTime, image_index_to_update+1, xml=xml, imgname=opts.image_name)
	write_xmldata(wim, out, xml)

	if opts.integrity_check:
		write_integrity_table(wim, out)
	
	finalize_wimheader(wim, out)

	print_timings(StartTime, StopTime)


def delete(opts, args):
	RefCounts = OrderedDict()
	
	StartTime = time.time()

	out = open(args[0], 'r+b')
	out.seek(0)
	
	wim = get_wimheader(out)
	wim_is_clean(wim, out)
	
	if wim.dwFlags & 4: #FLAG_HEADER_READONLY
		print "WIM header has READ-ONLY flag set, aborting delete..."
		sys.exit(1)
		
	COMPRESSION_TYPE = get_wim_comp(wim)

	offset_table = get_offsettable(out, wim)
	images = get_images(out, wim)
	
	image_index_to_update = get_image_from_id(wim, out, args[1])

	if image_index_to_update > len(images):
		print "Image to delete doesn't exist!"
		sys.exit(1)

	print "Opening WIM for delete, image #%d..." % image_index_to_update
	image_index_to_update -= 1
	
	for o in offset_table.values():
		if o.rhOffsetEntry.bFlags & 2: # skips image resource
			continue
		RefCounts[o.bHash] = [o.rhOffsetEntry.liOffset, o.rhOffsetEntry.liOriginalSize, o.rhOffsetEntry.ullSize, o.dwRefCount, o.rhOffsetEntry.bFlags]

	print "Opening Metadata resource..."
	metadata_res = get_resource(out, images[image_index_to_update], COMPRESSION_TYPE)

	metadata = tempfile.TemporaryFile()
	copy(metadata_res, metadata)

	if metadata_res.sha1.digest() != images[image_index_to_update].bHash:
		logging.debug("FATAL: broken Metadata resource!")
		sys.exit(1)
	else:
		logging.debug("Metadata checked!")

	direntries, directories = get_direntries(metadata)

	for e in direntries:
		if e in RefCounts:
			RefCounts[e][3] = RefCounts[e][3] - len(direntries[e]) # decrease dwRefCount by amount referred to this image

	# Flags the header for writing in progress
	wim.dwFlags |= 0x40
	out.seek(0)
	out.write(wim.tostr())
	
	out.seek(0, 2)
	
	image_start = out.tell()
	logging.debug("Image start @%08X", image_start)

	StopTime = time.time()

	print "Building the Offsets table..."
	wim.rhOffsetTable.liOffset = out.tell()
	logging.debug("Writing Offset table @0x%08X", wim.rhOffsetTable.liOffset)

	del images[image_index_to_update] 
	wim.dwImageCount -= 1 # decrease Image count
	
	for img in images:
		logging.debug("Writing offset entry for image @0x%08X", img.rhOffsetEntry.liOffset)
		out.write(img.tostr())
	for e in RefCounts:
		out.write(make_offsettable(e, RefCounts[e]).tostr())
	wim.rhOffsetTable.bFlags = 2 # bFlags as Metadata
	wim.rhOffsetTable.ullSize = out.tell() - wim.rhOffsetTable.liOffset
	wim.rhOffsetTable.liOriginalSize = wim.rhOffsetTable.ullSize

	print "Updating the XML Data..."
	xml = get_xmldata(out, wim)
	root = get_xmldata_root(wim, out)
	# remove deleted image entry
	for node in root.iter('IMAGE'):
		if node.get('INDEX') == str(image_index_to_update+1):
			root.remove(node)
	# update subsequent image indexes
	for node in root.iter('IMAGE'):
		if int(node.get('INDEX')) > image_index_to_update+1:
			i = int(node.get('INDEX')) - 1
			node.set('INDEX', str(i))
	wim.rhXmlData.liOffset = out.tell()
	root.find('TOTALBYTES').text = str(wim.rhXmlData.liOffset)
	write_xmldata(wim, out, ET.tostring(root).encode('utf16'))

	if opts.integrity_check:
		write_integrity_table(wim, out)
	
	finalize_wimheader(wim, out)

	print_timings(StartTime, StopTime)
