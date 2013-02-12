ImagePyX and SSWIMM
===================

This is a Super Simple WIM Manager written entirely in Python[1] (except for the compression code, found at
https://github.com/coderforlife/ms-compress: please note that only XPRESS compression works well, actually).

With ImagePyX you can:
- capture a directory tree to a WIM Image, eventually compressing it and excluding files/folders
- update or delete an image inside a WIM
- append new images to a WIM
- apply (extract) an image from WIM unit to a directory, optionally excluding files/folders
- split a WIM into more SWM units
- export one or all images to an old/new WIM
- list and test image contents

On Windows, it can use the native RTL Xpress codec (8 only) and provides complete handling of:
 - short names
 - security permissions
 - alternate data streams
 - hard links
 - directory junctions
 - symbolic links [2]


Useful links about WIM Images:
	http://en.wikipedia.org/wiki/Windows_Imaging_Format
	http://technet.microsoft.com/en-us/library/cc507842.aspx


FOLDER CONTENTS:
- ImagePyX.py		the main Python module (rev. 0.25), driver for the SSWIMM package
- SSWIMM		package directory containing the submodules
- README.MD		this file
- gpl.txt		GPL v2 license file: it applies to this package

Look at REVISIONS.TXT for details about developement history and things to do.





[1] Developed and tested with Python 2.7.3, 32-bit
[2] Administrator rights are required to restore (create) symbolic links
