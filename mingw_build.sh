# Simple script to compile under Windows with GCC 4.7 (MingW64)
# 1) copy here the required compression source code from wimlib 1.2.5
# 2) declare the appropriate functions as __declspec(dllexport) in the source code
# 3) create an empty CONFIG.H and #define typeof __typeof__
# note: -O3 generates bad code (in lzx decompressor)
gcc -mdll -mwin32 -std=c99 -march=native -O2 -flto -finline-functions -funswitch-loops -I. -Wl,-s -Wl,-o,wimlib.dll lzx-compress.c compress.c lzx-common.c lz77.c lzx-decompress.c decompress.c xpress-compress.c xpress-decompress.c
