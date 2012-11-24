ImagePyX.py and SSWIMM
====================

This is a Super Simple WIM Manager written entirely in Python (except for the compression code, found at
https://github.com/coderforlife/ms-compress: please note that while XPRESS compression seems to work well,
this is not completely true for LZX implementation).

It's able to create, append, update, extract and split WIM Images: look at
	http://en.wikipedia.org/wiki/Windows_Imaging_Format
and
	http://technet.microsoft.com/en-us/library/cc507842.aspx



FOLDER CONTENTS
===============

- ImagePyX.py				the main Python module (rev. 0.20), driver for the SSWIMM package
- SSWIMM					package directory containing the code for [C]reate WIM images, [U]pdate,
						[S]plit, [D]ecompress, [A]ppend and get [I]nformations.
- README.MD				this file
- gpl.txt					GPL v2 license file: it applies to this package



HISTORY
=======

- FEB 2012				Planning the WIM archive classes
- 16.09.12				WIM archive classes with indexing and self representation
						introduced on the behalf of NTFS/(ex)FAT parser
- 18.09.12				Reviewing the internals of 7-zip/ImageX made WIMs
						First protoype with creators for each WIM subsection
- 19.09.12 r.0.01			First prototype can assemble a very simple, uncompressed valid WIM
- 20.09.12 r.0.02			Appropriate XML Data; can store more files and dirs
- 21.09.12 r.0.03			Bugs with files and dirs order fixed
						Introduced (XPRESS) compression with MSCompression.dll
- 22.09.12				Using RtlCompressBuffer from NTDLL (Win 8)
						Many bugs fixed: can handle well thousands of files
- 23.09.12 r.0.04			halfed SHA-1 calculations
						simpler reference counting
						store always when comp == uncomp size
						store uncompressed chunks when cheaper
						use Python Unicode for scanning dirs
- 24.09.12 r.0.05 		made the input stream w/ temp file (like ImageX)
						testing capabilities
- 25.09.12 r.0.06 		fixed bugs in the InputStream read lengths
						rough mechanism to re-copy the Metadata uncompressed
- 26.09.12 r.0.07 		checked and fixed the problem with last chunk comp >= uncomp
- 04.10.12 r.0.08 		copy buffer decreased to 32K to speedup
						reorganized code in SSWIMMD
						timings
- 05.10.12 r.0.09 		InputStream now correctly detects if the last chunk is uncompressed
						report duplicates discarded in debug info
- 06.10.12 r.0.10 		working (and faster: 33%) compressor multithreaded version
						slightly improved with a 3rd thread
						additional 15% speedup by reorganizing code in make_fileresources
						rtl_xpress_huff_compress now uses c_int/byref
- 08.10.12 r.0.11			aborted ctypes variant due too many bugs (fields; str conversion)
						1 thread only w/ no compression (or too many open files exception)
						minor optimizations in OutputStream.__write_comp
						better reports decompressor errors in debugging log
- 09.10.12 r.0.12			cStringIO instead of str in OutputStream: but no speedup
						take SHA-1 AOT trying to save compressor work, at a cost of reading input twice
						(20% faster on a fresh XP installation -dllcache-)
- 11.10.12 r.0.13			integrity table creation & verification
- 13.10.12 r.0.14			can append new images
						can test multiple images in a WIM
						ElementTree to manage XmlData
						rough cmd line
						option to exclude files/folders from capture
- 16.10.12 r.0.15			can split WIM
						cmd line unified in SSWIMM main module
						can update images
						can list image contents
						set correct dwFlags in WIM header
- 22.10.12 r.0.16			fixed a bug with nesting excluded directory
						added description XML field
						better split algorithm to reach optimal unit fit
						access images by name
- 23.10.12 r.0.17			update correctly decreases dwRefCount for discarded files
						update merges again common file resources
						correctly extends/updates offset table when appending/updating an identical image
						always update TOTALBYTES field in XmlData
						can delete images
						keep IMAGE entries sorted by INDEX in XmlData (prevents 7-zip warnings)
						can read exclusion list from file
- 24.10.12 r.0.20			reorganized code in SSWIMM package with ImagePyX driver :)



TODO
====

- read items to test from DIRENTRY table instead of Offset Table; or
- general test, opening all DIRENTRY tables in WIM
- resolve conflict between images with the same name?
- set FLAG_HEADER_RESOURCE_ONLY, FLAG_HEADER_METADATA_ONLY in WIM header
- investigate around RESHDR_FLAG_FREE
- compare valid WIM size with xmldata?
- image exporting
- sort offset table entries?
- utility to pretty print XML info/convert times in human readable format
- change image name/description in XML data
- implement extractor in SSWIMMD
- merge/read from multiple SWM
- XML tools to represent path tree?
- linearize compressed resources logic (blocks first, pointers last)
- switch to ctypes structures to speedup? [ABORTED]
- multithreaded decompressor?
- short names
- ADS and hard/soft links
- add security descriptors (may require privileges!)
