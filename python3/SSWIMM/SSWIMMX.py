'''
SWIMMX.PY - Part of Super Simple WIM Manager
Exporter module
'''
import hashlib
import logging
import os
import queue
import struct
import sys
import tempfile
import threading
from ctypes import *
from datetime import datetime as dt
from .WIMArchive import *
from .SSWIMMC import *
from .SSWIMMD import *


def copyres2(ote, fp_in, fp_out):
	"Copies a file resource, changing its compression"
	isGood, fp = get_resource(fp_in, ote, False)
	if not isGood:
		logging.debug("Corrupted resource @0x%08X, simply copied!", ote.rhOffsetEntry.liOffset)
		print("Corrupted resource @0x%08X, simply copied!" % ote.rhOffsetEntry.liOffset)
		copyres(ote.rhOffsetEntry.liOffset, ote.rhOffsetEntry.ullSize, fp_in, fp_out)
		fp.close()
		return
	Codecs.Codec2.compress(fp, fp_out, ote.rhOffsetEntry.liOriginalSize)
	if Codecs.Codec2.osize < ote.rhOffsetEntry.liOriginalSize:
		ote.rhOffsetEntry.bFlags |= 4 # compressed
	elif ote.rhOffsetEntry.bFlags & 4:
		ote.rhOffsetEntry.bFlags ^= 4 # uncompressed
	logging.debug("Recompressed resource @0x%08X from %d to %d bytes", ote.rhOffsetEntry.liOffset, ote.rhOffsetEntry.ullSize, Codecs.Codec2.osize)
	ote.rhOffsetEntry.ullSize = Codecs.Codec2.osize
	fp.close()


def export(opts, args):
	StartTime = time.time()

	fpi = open(args[0], 'rb')
	fpi.seek(0)
	
	print("Opening WIM unit...")
	wim = get_wimheader(fpi)

	NEW_COMPRESSION_TYPE = COMPRESSION_TYPE = get_wim_comp(wim)

	Codecs.Codec = CodecMT(opts.num_threads, COMPRESSION_TYPE)

	offset_table = get_offsettable(fpi, wim)
	
	if args[1] == '*': # special case: exports ALL
		img_index = 0
	else:
		img_index = get_image_from_id(wim, fpi, args[1])

	images = get_images(fpi, wim)
	
	if img_index > len(images):
		print("Image doesn't exist!")
		sys.exit(1)
	img_index -= 1

	if img_index > -1:
		images = [images[img_index]] # selects a single image
	
	root = get_xmldata_root(wim, fpi)

	if os.path.exists(args[2]):
		fpo = open(args[2], 'r+b')
		new_wim = get_wimheader(fpo)
		NEW_COMPRESSION_TYPE = get_wim_comp(new_wim)
		if COMPRESSION_TYPE != NEW_COMPRESSION_TYPE:
			Codecs.Codec2 = CodecMT(opts.num_threads, NEW_COMPRESSION_TYPE)
		new_images = get_images(fpo, new_wim)
		new_offset_table = get_offsettable(fpo, new_wim)
		xml_data = get_xmldata(fpo, new_wim)
		fpo.seek(0, 2) # SEEK_END
	else:	# Create the new WIM unit
		fpo = open(args[2], 'wb')
		new_wim = make_wimheader(COMPRESSION_TYPE)
		new_wim.dwImageCount = 0
		fpo.write(new_wim.tostr())
		new_images = []
		new_offset_table = OrderedDict()
		xml_data = ''
	
	for image in images:
		new_wim.dwImageCount += 1

		img_index += 1
		if not img_index:
			img_index += 1
		
		print("Exporting Image #%d to Image #%d" % (wim.dwImageCount, new_wim.dwImageCount))
		logging.debug("Exporting Image #%d to Image #%d", wim.dwImageCount, new_wim.dwImageCount)
		
		print("Opening Metadata resource...")
		metadata = get_metadata(fpi, image)

		print("Opening DIRENTRY table...")
		direntries, directories = get_direntries(metadata)

		for node in root.iter('IMAGE'):
			if node.get('INDEX') == str(img_index):
				dirCount = int(node.find('DIRCOUNT').text)
				fileCount = int(node.find('FILECOUNT').text)
				imgTotalBytes = int(node.find('TOTALBYTES').text)
				hardlinksBytes = int(node.find('HARDLINKBYTES').text)
				if node.find('NAME'):
					opts.image_name = node.find('NAME').text
				if node.find('DESCRIPTION'):
					opts.image_description = node.find('DESCRIPTION').text
		
		# Export the File resources
		print("Exporting the resources...")

		# Sorts by on-disk resource offset
		NULLK = 20*'\0'
		def direntries_sort(a, b):
			if a[0] == NULLK or b[0] == NULLK: return 0
			return cmp(offset_table[a[0]].rhOffsetEntry.liOffset, offset_table[b[0]].rhOffsetEntry.liOffset)
		direntries = OrderedDict(sorted(list(direntries.items()), direntries_sort))

		total_done_bytes = 0
		for bHash in direntries:
			if bHash not in offset_table: continue
			if bHash in new_offset_table:
				new_offset_table[bHash].dwRefCount += len(direntries[bHash])
				continue
			ote = offset_table[bHash]
			if not ote.dwRefCount: # skips unused resources
				continue
			liOffset = fpo.tell()
			if COMPRESSION_TYPE == NEW_COMPRESSION_TYPE:
				copyres(ote.rhOffsetEntry.liOffset, ote.rhOffsetEntry.ullSize, fpi, fpo)
			else:
				copyres2(ote, fpi, fpo)
			ote.rhOffsetEntry.liOffset = liOffset # update resource offset
			ote.dwRefCount = len(direntries[bHash])
			new_offset_table[bHash] = ote
			total_done_bytes += ote.rhOffsetEntry.ullSize
			print_progress(StartTime, total_done_bytes, imgTotalBytes)
		
		# Exports the Metadata
		print("Exporting the Metadata...")
		image_start = fpo.tell()
		logging.debug("Image start @%08X", image_start)
		if COMPRESSION_TYPE == NEW_COMPRESSION_TYPE:
			copyres(image.rhOffsetEntry.liOffset, image.rhOffsetEntry.ullSize, fpi, fpo)
		else:
			copyres2(image, fpi, fpo)

		StopTime = time.time()

		print("Building the Offsets table...")
		new_wim.rhOffsetTable.liOffset = fpo.tell()
		logging.debug("Writing Offset table @0x%08X", new_wim.rhOffsetTable.liOffset)
		
		image.rhOffsetEntry.liOffset = image_start
		new_images += [image]
		for img in new_images:
			logging.debug("Writing offset entry for image @0x%08X", img.rhOffsetEntry.liOffset)
			fpo.write(img.tostr())

		logging.debug("Metadata resource @%0X for %d bytes (%d original)",image.rhOffsetEntry.liOffset, image.rhOffsetEntry.ullSize, image.rhOffsetEntry.liOriginalSize)
		
		for bHash in new_offset_table:
			ote = new_offset_table[bHash]
			if ote.rhOffsetEntry.bFlags & 2: # skips image resources
				continue
			fpo.write(ote.tostr())

		new_wim.rhOffsetTable.bFlags = 2 # bFlags as Metadata
		new_wim.rhOffsetTable.ullSize = fpo.tell() - new_wim.rhOffsetTable.liOffset
		new_wim.rhOffsetTable.liOriginalSize = new_wim.rhOffsetTable.ullSize

		print("Building the XML Data...")
		new_wim.rhXmlData.liOffset = fpo.tell()

		xml_data = make_xmldata(new_wim.rhXmlData.liOffset, dirCount, fileCount, imgTotalBytes, hardlinksBytes, StartTime, StopTime, index=new_wim.dwImageCount, xml=xml_data, imgname=opts.image_name, imgdsc=opts.image_description)
		write_xmldata(new_wim, fpo, xml_data)

		logging.debug("Exporting of Image #%d finished...", new_wim.dwImageCount)

	if opts.integrity_check:
		write_integrity_table(new_wim, out)

	finalize_wimheader(new_wim, fpo)

	print_timings(StartTime, StopTime)
