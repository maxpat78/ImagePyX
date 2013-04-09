#!/bin/bash
rm -rf ROOTDIR
mkdir ROOTDIR
mkdir ROOTDIR/DIR001
echo Contenuto del file 001 >ROOTDIR/DIR001/FILE001.TXT
echo Contenuto del file 002 >ROOTDIR/DIR001/FILE002.TXT
python ImagePyX.py --capture  ROOTDIR a.wim
rm -rf  ROOTDIR/DIR001

mkdir ROOTDIR/DIR002
echo Contenuto del file 001 in DIR002 >ROOTDIR/DIR002/FILE001.TXT
echo Contenuto del file 002 in DIR002 >ROOTDIR/DIR002/FILE002.TXT
python ImagePyX.py --append ROOTDIR a.wim
rm -rf  ROOTDIR/DIR002

mkdir ROOTDIR/DIR003
mkdir ROOTDIR/DIR003/SUBDIR001
echo Contenuto del file 001 in DIR003 >ROOTDIR/DIR003/FILE001.TXT
echo Contenuto del file 002 in DIR003 >ROOTDIR/DIR003/FILE002.TXT
echo Contenuto del file 001 in SUBDIR001 >ROOTDIR/DIR003/SUBDIR001/FILE001.TXT
echo Contenuto del file 002 in SUBDIR001 >ROOTDIR/DIR003/SUBDIR001/FILE002.TXT
echo Contenuto del file 001 >ROOTDIR/DIR003/SUBDIR001/FILE003.TXT
echo Contenuto del file 002 >ROOTDIR/DIR003/SUBDIR001/FILE004.TXT
python ImagePyX.py --append ROOTDIR a.wim
rm -rf  ROOTDIR/DIR003

mkdir ROOTDIR/DIR004
mkdir ROOTDIR/DIR004/SUBDIR001
echo Contenuto del file 001 >ROOTDIR/DIR004/FILE001.TXT
echo Contenuto del file 002 >ROOTDIR/DIR004/FILE002.TXT
echo Contenuto del file 001 >ROOTDIR/DIR004/SUBDIR001/FILE001.TXT
echo Contenuto del file 002 >ROOTDIR/DIR004/SUBDIR001/FILE002.TXT
python ImagePyX.py --append  ROOTDIR a.wim
rm -rf  ROOTDIR

rm a1.wim a2.wim a3.wim a4.wim aB.wim 
python ImagePyX.py --export a.wim 1 a1.wim
python ImagePyX.py --export a.wim 2 a2.wim
python ImagePyX.py --export a.wim 3 a3.wim
python ImagePyX.py --export a.wim 4 a4.wim
python ImagePyX.py --export a.wim * aB.wim
python ImagePyX.py --export a1.wim 1 aB.wim
python ImagePyX.py --export a3.wim 1 aB.wim
cp a.wim b.wim

rm -rf  OTHERROOT
mkdir OTHERROOT
echo Contenuto del file 001.TXT in OTHERROOT>OTHERROOT/001.TXT
python ImagePyX.py --update OTHERROOT a.wim 2
rm OTHERROOT/001.TXT
echo Contenuto del file 002.TXT in OTHERROOT>OTHERROOT/002.TXT
python ImagePyX.py --update OTHERROOT a.wim 3
python ImagePyX.py --update OTHERROOT a.wim 3
python ImagePyX.py --update OTHERROOT a.wim 3

python ImagePyX.py --delete a.wim 1
python ImagePyX.py --delete a.wim 3

rm -rf  TMPROOT
mkdir TMPROOT
python ImagePyX.py --apply a.wim 2 TMPROOT
diff -s OTHERROOT/002.TXT TMPROOT/002.TXT

rm -rf  OTHERROOT
rm -rf  TMPROOT
