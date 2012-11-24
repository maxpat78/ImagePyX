'''
SWIMMI.PY - Part of Super Simple WIM Manager
Info module
'''

VERSION = '0.20'

COPYRIGHT = '''Copyright (C)2012, by maxpat78. GNU GPL v2 applies.
This free software creates MS WIM Archives WITH ABSOLUTELY NO WARRANTY!'''

import hashlib
import logging
import os
import sys
from WIMArchive import *
from SSWIMMD import *
from xml.etree import ElementTree as ET
import pprint

def list(opts, args):
	fpi = open(args[0], 'rb')

	wim = get_wimheader(fpi)

	COMPRESSION_TYPE = 0
	if wim.dwFlags & 0x20000:
		COMPRESSION_TYPE = 1
	elif wim.dwFlags & 0x40000:
		COMPRESSION_TYPE = 2

	offset_table = get_offsettable(fpi, wim)
	
	try:
		img_index = int(args[1])
	except ValueError:
		logging.debug("Searching index for Image name %s...", args[1])
		root = get_xmldata_root(wim, fpi)
		img_index = get_xmldata_imgindex(root, args[1])
		if not img_index:
			print "Image %s doesn't exist!" % args[1]
			sys.exit(1)

	images = get_images(fpi, wim)
	if img_index > len(images):
		print "There is no such Image in WIM!"
		sys.exit(1)
	img_index -= 1
	image = images[img_index]
	
	metadata_res = get_resource(fpi, image, COMPRESSION_TYPE)

	metadata = tempfile.TemporaryFile()
	copy(metadata_res, metadata)

	if metadata_res.sha1.digest() != image.bHash:
		print "FATAL: broken Metadata resource!"
		sys.exit(1)

	direntries, directories = get_direntries(metadata)
	
	for k in direntries:
		fname = direntries[k][0].FileName
		if not fname: continue
		fname = os.path.join(directories[direntries[k][0]._parent], fname)
		print fname


def info(opts, args):
	fp = open(args[0], 'rb')

	print "Opening WIM unit..."
	wim = get_wimheader(fp)

	COMPRESSION_TYPE = 0
	if wim.dwFlags & 0x20000:
		COMPRESSION_TYPE = 1
	elif wim.dwFlags & 0x40000:
		COMPRESSION_TYPE = 2

	print "Compression is", ('none', 'XPRESS', 'LZX')[COMPRESSION_TYPE]

	fp.seek(wim.rhXmlData.liOffset)

	xml = ET.parse(fp)
	pprint.PrettyPrinter().pprint(ET.dump(xml))
	#~ for i in xml.iter():
		#~ print i
