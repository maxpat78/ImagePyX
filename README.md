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
- merge/read from multiple SWM
- XML tools to represent path tree?
- linearize compressed resources logic (blocks first, pointers last)
- switch to ctypes structures to speedup? [ABORTED]
- multithreaded decompressor?
- short names
- ADS and hard/soft links
- add security descriptors (may require privileges!)
