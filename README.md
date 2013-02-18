ImagePyX and SSWIMM
===================

This is a Super Simple WIM Manager written entirely in Python[1].

Main compression support is provided by wimlib 1.2.5 (look at http://sourceforge.net/projects/wimlib)[2]:
optionally, the MSCompression library can be used (found at https://github.com/coderforlife/ms-compress), but
its LZX codec is quite unmature at this time.

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
 - symbolic links[3]


Useful links about WIM Images:
	http://en.wikipedia.org/wiki/Windows_Imaging_Format
	http://technet.microsoft.com/en-us/library/cc507842.aspx


FOLDER CONTENTS:
- ImagePyX.py		the main Python module (rev. 0.26), driver for the SSWIMM package
- SSWIMM		package directory containing the submodules
- README.MD		this file
- gpl.txt		GPL v2 license file: it applies to this package
- mingw_build.sh        script to help building a reduced wimlib under Windows

Look at REVISIONS.TXT for details about developement history and things to do.



[1] Developed and tested with Python 2.7.3, 32-bit
[2] A simplified version with the codecs only can be built with GCC 4.7 on Windows: look at mingw_build.sh
[3] Administrator rights are required to restore (create) symbolic links
