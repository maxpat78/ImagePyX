'''
SWIMMI.PY - Part of Super Simple WIM Manager
Info module
'''
import hashlib
import logging
import os
import sys
from .WIMArchive import *
from .SSWIMMD import *
import uuid
from xml.dom import minidom

def list(opts, args):
	fpi = open(args[0], 'rb')

	wim = get_wimheader(fpi)

	COMPRESSION_TYPE = get_wim_comp(wim)

	Codecs.Codec = CodecMT(opts.num_threads, COMPRESSION_TYPE)

	offset_table = get_offsettable(fpi, wim)

	if len(args) < 2:
		args += ['1'] # set default argument: first image
		
	try:
		img_index = int(args[1])
	except ValueError:
		logging.debug("Searching index for Image name %s...", args[1])
		root = get_xmldata_root(wim, fpi)
		img_index = get_xmldata_imgindex(root, args[1])
		if not img_index:
			print("Image %s doesn't exist!" % args[1])
			sys.exit(1)

	images = get_images(fpi, wim)
	if img_index > len(images):
		print("There is no such Image in WIM!")
		sys.exit(1)
	img_index -= 1
	image = images[img_index]
	
	print("Opening Metadata resource...")
	metadata = get_metadata(fpi, image)

	direntries, directories = get_direntries(metadata)
	
	for k in direntries:
		for fres in direntries[k]:
			if fres._parent == -1: continue # skips ROOT
			fname = os.path.join(directories[fres._parent], fres.FileName)
			print(fname)


def info(opts, args):
	fp = open(args[0], 'rb')

	print("Opening WIM unit...")
	wim = get_wimheader(fp)

	COMPRESSION_TYPE = get_wim_comp(wim)

	print("""
WIM Information:
----------------
Path:\t\t%s
GUID:\t\t{%s}
Image Count:\t%d
Compression:\t%s
Part Number:\t%d/%d
Attributes:\t%X\n""" % (args[0], uuid.UUID(bytes_le=wim.gWIMGuid), wim.dwImageCount,
('none', 'XPRESS', 'LZX')[COMPRESSION_TYPE],
wim.usPartNumber, wim.usTotalParts, wim.dwFlags))

	fp.seek(wim.rhXmlData.liOffset)
	data = fp.read(wim.rhXmlData.liOriginalSize)

	print("Available Image choices:\n------------------------")
	xml = minidom.parseString(data)
	print(xml.toprettyxml()[23:])
