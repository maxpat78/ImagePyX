# Simple script to compile under Windows with GCC 4.8 (MingW64)
# 1) copy here the required compression source code and headers from wimlib 1.3.x
# 2) create an empty CONFIG.H and 1) #define typeof __typeof__ 2) #define EXPORT_COMPRESSION_FUNCTIONS
# note: -O3 generates bad code (in lzx decompressor) with GCC 4.7
#~ gcc -mdll -mwin32 -std=c99 -march=native -O2 -flto -finline-functions -funswitch-loops -I. -Wl,-s -Wl,-o,wimlib.dll lzx-compress.c compress.c lzx-common.c lz77.c lzx-decompress.c decompress.c xpress-compress.c xpress-decompress.c
gcc -mdll -mwin32 -std=c99 -march=native -O3 -flto -I. -Wl,-s -Wl,-o,wimlib.dll lzx-compress.c compress.c lzx-common.c lz77.c lzx-decompress.c decompress.c xpress-compress.c xpress-decompress.c
