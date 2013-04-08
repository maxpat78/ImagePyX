'''
SWIMMS.PY - Part of Super Simple WIM Manager
Splitter module
'''

VERSION = '0.27'

COPYRIGHT = '''Copyright (C)2012-2013, by maxpat78. GNU GPL v2 applies.
This free software creates MS WIM Archives WITH ABSOLUTELY NO WARRANTY!'''

import glob
import hashlib
import logging
import os
import re
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


def new_swm(wim, base_name, swm_index):
	if swm_index == 1:
		swm_name = base_name[:-4] + '.swm'
	else:
		swm_name = base_name[:-4] + '%d'%swm_index + '.swm'
	swm = open(swm_name, 'wb')
	swm.write(wim.tostr())
	logging.debug("Created new SWM unit %s", swm_name)
	wim.dwFlags |= 0x40 # FLAG_HEADER_WRITE_IN_PROGRESS
	return swm

	
def swm_open_set(pathname):
	base = os.path.basename(pathname).lower()
	for i in range(len(base)):
		if base[i].isdigit():
			base = base[:i]
			break
	if base.lower().endswith('.swm'):
		base = base[:-4]
	swm_set = {}
	found_comp = 0
	swm_set_GUID = 0
	swm_units = glob.glob(os.path.join(os.path.dirname(pathname), base+'*.swm'))
	for swm in swm_units:
		fp = open(swm, 'rb')
		logging.debug('Opened SWM unit %s', fp.name)
		wim = get_wimheader(fp)
		COMPRESSION_TYPE = get_wim_comp(wim)
		if found_comp and found_comp != COMPRESSION_TYPE:
			print "Can't have SWM units with different compression types!"
			sys.exit(1)
		if wim.usTotalParts > len(swm_units):
			print "Can't find all required SWM units"
		if swm_set_GUID and wim.gWIMGuid != swm_set_GUID:
			print "Bad GUID found for SWM unit %s!" % fp.name
			sys.exit(1)
		found_comp = COMPRESSION_TYPE
		swm_set_GUID = wim.gWIMGuid
		offset_table = get_offsettable(fp, wim)
		swm_set[fp] = (wim, offset_table)
		if fp.name == base+'.swm':
			swm_set['base'] = swm_set[fp]
	return swm_set

def split(opts, args):
	RefCounts = OrderedDict()
	
	StartTime = time.time()

	out = open(args[0], 'rb')
	out.seek(0)
	
	# Max SWM size, in MiB
	swm_unit_max_size = int(args[1]) << 20
	
	print "Opening WIM unit to split..."
	wim = get_wimheader(out)

	COMPRESSION_TYPE = get_wim_comp(wim)

	wim.dwFlags |= 0x8 # FLAG_HEADER_SPANNED

	offset_table = get_offsettable(out, wim)
	images = get_images(out, wim)
	xmldata = get_xmldata(out, wim)
	
	# sizeof(WIMHEADER) + sizeof(XMLDATA) + sizeof(1 offset table entry)
	min_swm_unit_expansion = 208 + (len(xmldata)+1)*2 + 50
	
	for o in offset_table.values():
		if o.rhOffsetEntry.bFlags & 2: # skips image resource
			continue
		RefCounts[o.bHash] = [o.rhOffsetEntry.liOffset, o.rhOffsetEntry.liOriginalSize, o.rhOffsetEntry.ullSize, o.dwRefCount, o.rhOffsetEntry.bFlags]
	
	# sorted by size
	items = sorted(RefCounts, lambda a, b:cmp(RefCounts[b][2], RefCounts[a][2]))

	if RefCounts[items[0]][2] + min_swm_unit_expansion > swm_unit_max_size:
		swm_unit_max_size = RefCounts[items[0]][2] + min_swm_unit_expansion
		logging.debug("WARNING: split size elevated to %d bytes (file resource found for %d bytes)", swm_unit_max_size, RefCounts[items[0]][2])
	elif os.stat(args[0]).st_size <= swm_unit_max_size:
		logging.debug("Won't split, WIM archive isn't greater than split size!")
		sys.exit(1)
	else:
		logging.debug("Biggest file resource is %d bytes, smallest %d", RefCounts[items[0]][2], RefCounts[items[-1]][2])

	logging.debug("Calculating required SWMs...")
	swm_size = min_swm_unit_expansion + 50*len(images) - 50
	swm_units_needed = 0
	for img in images:
		swm_size += img.rhOffsetEntry.ullSize
	items_to_do = len(items)
	items_done = []
	while items_to_do:
		for fileres in items:
			if fileres in items_done or swm_size + RefCounts[fileres][2] + 50 > swm_unit_max_size:
				continue
			swm_size += RefCounts[fileres][2] + 50
			items_to_do -= 1
			items_done += [fileres]
		logging.debug("SWM #%d will be %d bytes long", swm_units_needed, swm_size)
		swm_units_needed += 1
		swm_size = min_swm_unit_expansion - 50

	logging.debug("%d SWM units required", swm_units_needed)
	print "Splitting into %d SWM units..."% swm_units_needed
		
	# Base SWM only gets all Metadata resource(s)
	# Others SWM have Fileresources, own Offset table and common XML data
	swm_index, swm_size, swm = 0, min_swm_unit_expansion + 50*len(images) - 50, None
	swm_refcounts = OrderedDict()
	items.append(None) # trick to force last SWM closing
	items_to_do = len(items)
	items_done = [None]
	while items_to_do:
		for fileres in items:
			# Creates new SWM if needed
			if not swm:
				swm_index += 1
				swm = new_swm(wim, args[0], swm_index)
				# Copy Metadata resources to 1st SWM only
				if swm_index == 1:
					for img in images:
						new_pos = swm.tell()
						copyres(img.rhOffsetEntry.liOffset, img.rhOffsetEntry.ullSize, out, swm)
						img.rhOffsetEntry.liOffset = new_pos
						swm_size += img.rhOffsetEntry.ullSize
					logging.debug("Copied Image resource(s) into base SWM")
			# Take care to fit into unit size
			if fileres == None or swm_size + RefCounts[fileres][2] + 50 > swm_unit_max_size:
				if fileres != None: continue
				logging.debug("SWM grew to a maximum of %d bytes, closing...", swm_size-50)
				wim.rhOffsetTable.liOffset = swm.tell()
				if swm_index == 1:
					for img in images:
						logging.debug("Writing offset entry for image @0x%08X", img.rhOffsetEntry.liOffset)
						swm.write(img.tostr())
				# Offsets table
				logging.debug("Writing Offset table @0x%08X", wim.rhOffsetTable.liOffset)
				for e in swm_refcounts:
					swm.write(make_offsettable(e, swm_refcounts[e], swm_index).tostr())
				swm_refcounts = OrderedDict()
				wim.rhOffsetTable.bFlags = 2 # bFlags as Metadata
				wim.rhOffsetTable.ullSize = swm.tell() - wim.rhOffsetTable.liOffset
				wim.rhOffsetTable.liOriginalSize = wim.rhOffsetTable.ullSize
				# XMLData
				wim.rhXmlData.liOffset = swm.tell()
				write_xmldata(wim, swm, xmldata.encode('utf-16'))
				# Update WIM Header
				wim.usPartNumber = swm_index
				wim.usTotalParts = swm_units_needed
				finalize_wimheader(wim, swm) 
				swm_size = min_swm_unit_expansion - 50
				print "Created SWM unit #%d" % swm_index
				if items_to_do == 1:
					items_to_do = 0
					break
				swm_index += 1
				swm = new_swm(wim, args[0], swm_index)
			if fileres in items_done: continue
			swm_size += RefCounts[fileres][2] + 50
			new_offset = swm.tell()
			copyres(RefCounts[fileres][0], RefCounts[fileres][2], out, swm)
			RefCounts[fileres][0] = new_offset
			swm_refcounts[fileres] = RefCounts[fileres]
			items_to_do -= 1
			items_done += [fileres]

	StopTime = time.time()

	if opts.integrity_check:
		write_integrity_table(wim, out)
	
	print_timings(StartTime, StopTime)
