'''
SWIMMX.PY - Part of Super Simple WIM Manager
Exporter module
'''

VERSION = '0.23'

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
from datetime import datetime as dt
from WIMArchive import *
from SSWIMMC import *
from SSWIMMD import *

def copyres(offset, size, fp_in, fp_out):
	"Copy a file resource from WIM to SWM"
	fp_in.seek(offset)
	todo = size
	while todo:
		if todo > 32768:
			cb = 32768
		else:
			cb = todo
		fp_out.write(fp_in.read(cb))
		todo -= cb
	logging.debug("Copied resource @0x%08X for %d bytes", offset, size)


def export(opts, args):
	StartTime = time.time()

	fpi = open(args[0], 'rb')
	fpi.seek(0)
	
	print "Opening WIM unit..."
	wim = get_wimheader(fpi)

	COMPRESSION_TYPE = get_wim_comp(wim)

	offset_table = get_offsettable(fpi, wim)
	img_index = get_image_from_id(wim, fpi, args[1])
	images = get_images(fpi, wim)
	root = get_xmldata_root(wim, fpi)

	if img_index > len(images):
		print "Image index doesn't exist!"
		sys.exit(1)
	img_index -= 1
	
	image = images[img_index]

	img_index += 1
	
	print "Exporting Image #%d" % (1, img_index)[img_index > 0]

	print "Opening Metadata resource..."
	metadata = get_metadata(fpi, image, COMPRESSION_TYPE)

	print "Collecting DIRENTRY table..."
	direntries, directories = get_direntries(metadata)

	for node in root.iter('IMAGE'):
		if node.get('INDEX') == str(img_index):
			dirCount = int(node.find('DIRCOUNT').text)
			fileCount = int(node.find('FILECOUNT').text)
			imgTotalBytes = int(node.find('TOTALBYTES').text)
			if node.find('NAME'):
				opts.image_name = node.find('NAME').text
			if node.find('DESCRIPTION'):
				opts.image_description = node.find('DESCRIPTION').text

	# Create the new WIM unit
	fpo = open(args[2], 'wb')
	new_wim = make_wimheader(COMPRESSION_TYPE)
	fpo.write(new_wim.tostr())

	print "Exporting the resources..."
	
	# Export File resources
	total_done_bytes = 0
	for bHash in direntries:
		if bHash not in offset_table: continue
		ote = offset_table[bHash]
		liOffset = fpo.tell()
		copyres(ote.rhOffsetEntry.liOffset, ote.rhOffsetEntry.ullSize, fpi, fpo)
		offset_table[bHash].rhOffsetEntry.liOffset = liOffset # update resource offset
		total_done_bytes += ote.rhOffsetEntry.ullSize
		print_progress(StartTime, total_done_bytes, imgTotalBytes)
		
	# Exports Metadata
	print "Exporting the Metadata..."
	image_start = fpo.tell()
	logging.debug("Image start @%08X", image_start)
	copyres(image.rhOffsetEntry.liOffset, image.rhOffsetEntry.ullSize, fpi, fpo)

	StopTime = time.time()

	print "Building the Offsets table..."
	new_wim.rhOffsetTable.liOffset = fpo.tell()
	logging.debug("Writing Offset table @0x%08X", new_wim.rhOffsetTable.liOffset)
	
	image.rhOffsetEntry.liOffset = image_start
	fpo.write(image.tostr()) # Exported image entry
	logging.debug("Metadata resource @%0X for %d bytes (%d original)",image.rhOffsetEntry.liOffset, image.rhOffsetEntry.ullSize, image.rhOffsetEntry.liOriginalSize)
	
	for bHash in direntries:
		if bHash not in offset_table: continue
		ote = offset_table[bHash]
		ote.dwRefCount = len(direntries[bHash]) # dwRefCount referred to this image
		fpo.write(ote.tostr())

	new_wim.rhOffsetTable.bFlags = 2 # bFlags as Metadata
	new_wim.rhOffsetTable.ullSize = fpo.tell() - new_wim.rhOffsetTable.liOffset
	new_wim.rhOffsetTable.liOriginalSize = new_wim.rhOffsetTable.ullSize

	print "Building the XML Data..."
	new_wim.rhXmlData.liOffset = fpo.tell()

	write_xmldata(new_wim, fpo, make_xmldata(new_wim.rhXmlData.liOffset, dirCount, fileCount, imgTotalBytes, StartTime, StopTime, imgname=opts.image_name, imgdsc=opts.image_description))

	if opts.integrity_check:
		write_integrity_table(new_wim, out)

	finalize_wimheader(new_wim, fpo)

	print_timings(StartTime, StopTime)
