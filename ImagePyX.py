#! /usr/bin/python2
'''
ImagePyX.py - Super Simple WIM Manager
Driver main module
'''

VERSION = '0.28'

COPYRIGHT = '''Copyright (C)2012-2013, by maxpat78. GNU GPL v2 applies.
This free software creates MS WIM Archives WITH ABSOLUTELY NO WARRANTY!'''

import optparse
import logging
import sys
from SSWIMM import *

if __name__ == '__main__':
	help_s = """
%prog [options] --capture <folder> <file.wim>
%prog [options] --append <folder> <file.wim> <image>
%prog [options] --update <folder> <file.wim> <image>
%prog [options] --delete <file.wim> <image>
%prog [options] --test <file.wim> <image>
%prog [options] --dir <file.wim> <image>
%prog [options] --info <file.wim>
%prog [options] --split <file.wim> <SWM max size MiB>
%prog [options] --apply <file.wim> <image> <target folder>
%prog [options] --export <source.wim> <image> <dest.wim>"""
	par = optparse.OptionParser(usage=help_s, version="%prog 0.26 (MT)", description="Manage WIM archives.")
	par.add_option("--capture", const=1, action="store_const", dest="sub_module", help="create a new WIM archive with folder's contents")
	par.add_option("--append", const=2, action="store_const", dest="sub_module", help="append to (or create) a WIM archive with folder's contents")
	par.add_option("--update", const=3, action="store_const", dest="sub_module", help="update (or create) a WIM archive with folder's contents")
	par.add_option("--test", const=4, action="store_const", dest="sub_module", help="test a WIM archive")
	par.add_option("--split", const=5, action="store_const", dest="sub_module", help="split a WIM archive into SWM units of a given maximum size")
	par.add_option("--apply", const=6, action="store_const", dest="sub_module", help="extract files from a WIM archive")
	par.add_option("--info", const=7, action="store_const", dest="sub_module", help="show XML information stored inside WIM image")
	par.add_option("--dir", const=8, action="store_const", dest="sub_module", help="list the image contents")
	par.add_option("--delete", const=9, action="store_const", dest="sub_module", help="delete an image from WIM archive")
	par.add_option("--export", const=10, action="store_const", dest="sub_module", help="export an image or all images to a WIM archive")
	par.add_option("-c", "--compress", dest="compression_type", help="select a compression type between none, XPRESS (default), LZX", metavar="COMPRESSION", default="xpress")
	par.add_option("-n", "--name", dest="image_name", help="set an Image name in XML data", metavar="NAME", default=None)
	par.add_option("-d", "--description", dest="image_description", help="set an Image description in XML data", metavar="DESC", default=None)
	par.add_option("-x", "--exclude", action="append", dest="exclude_list", help="set files and folders to exclude from capture (wildcards are accepted)", metavar="FILES", default=None)
	par.add_option("--xf", "--exclude-file", dest="exclude_file", help="read from a file a list of files and folders to exclude from capture (wildcards are accepted)", metavar="FILE", default=None)
	par.add_option("--debug", action="store_true", dest="debug", help="turn on debug logging to SSWIMM.log", metavar="DEBUG_LOG", default=False)
	par.add_option("--check", action="store_true", dest="integrity_check", help="add integrity check data to image", default=False)
	par.add_option("--threads", dest="num_threads", type="int", help="specify the number of threads used for the (de)compression", default=2)
	par.add_option("--threshold", dest="threshold", type="string", help="instructs to abort compression if gain is less than RATIO after a specified amount 1/N of input has been processed and stream is greater than SIZE chunks\n\ni.e.: '--threshold=320,2,0.01' aborts if gain is < 1% after the 1/2 of a stream of at least 320 chunks (10 MiB) has been processed", metavar="SIZE,N,RATIO")
	opts, args = par.parse_args()

	if not opts.sub_module:
		print "You must specify an operation to carry out!\n"
		par.print_help()
		sys.exit(1)

	if opts.threshold:
		size, chunks, ratio = opts.threshold.split(',')
		opts.threshold.size, opts.threshold.chunks, opts.threshold.ratio = int(size), int(chunks), float(ratio)

	if opts.debug:
		logging.basicConfig(level=logging.DEBUG, filename='SSWIMM.log', filemode='w')

	if opts.exclude_file:
		if not opts.exclude_list:
			opts.exclude_list = []
		for line in open(opts.exclude_file):
			opts.exclude_list += [line[:-1]]
		print "These items will be excluded from capture:\n", '\n'.join(opts.exclude_list)
			
	if opts.sub_module == 1:
		if len(args) < 2:
			print "You must specify a source folder to capture and a WIM file!\n"
			sys.exit(1)
		create(opts, args)
	elif opts.sub_module == 2:
		if len(args) < 2:
			print "You must specify a source folder and a WIM file to append to/create!\n"
			sys.exit(1)
		if os.path.exists(args[0]):
			append(opts, args)
		else:
			create(opts, args)
	elif opts.sub_module == 3:
		if len(args) < 3:
			print "You must specify a source folder, a WIM file and an image (by index or name) to update!\n"
			sys.exit(1)
		update(opts, args)
	elif opts.sub_module == 4:
		if len(args) < 1:
			print "You must specify a WIM file (and, optionally, an image index or name) to test!\n"
			sys.exit(1)
		test(opts, args)
	elif opts.sub_module == 5:
		if len(args) < 2:
			print "You must specify a WIM file to split and the maximum SWM unit size in megabytes!\n"
			sys.exit(1)
		split(opts, args)
	elif opts.sub_module == 6:
		if len(args) < 3:
			print "You must specify a WIM file and an image (by index or name) to apply, and a target folder!\n"
			sys.exit(1)
		extract(opts, args)
	elif opts.sub_module == 7:
		if len(args) < 1:
			print "You must specify a WIM file to show the XML data!\n"
			sys.exit(1)
		info(opts, args)
	elif opts.sub_module == 8:
		if len(args) < 1:
			print "You must specify a WIM file and an image (by index or name) to list contents!\n"
			sys.exit(1)
		list(opts, args)
	elif opts.sub_module == 9:
		if len(args) < 2:
			print "You must specify a WIM file and an image (by index or name) to delete!\n"
			sys.exit(1)
		delete(opts, args)
	elif opts.sub_module == 10:
		if len(args) < 3:
			print "You must specify a source WIM file, an image (by index or name) to export and a destination WIM file!\n"
			sys.exit(1)
		export(opts, args)
