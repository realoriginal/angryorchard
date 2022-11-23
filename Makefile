CC_X64	:= x86_64-w64-mingw32-gcc
CC_X86	:= i686-w64-mingw32-gcc

CFLAGS	:= $(CFLAGS) -Os -fno-asynchronous-unwind-tables -nostdlib 
CFLAGS 	:= $(CFLAGS) -fno-ident -fpack-struct=8 -falign-functions=1
CFLAGS  := $(CFLAGS) -s -ffunction-sections -falign-jumps=1 -w -municode
CFLAGS	:= $(CFLAGS) -falign-labels=1 -fPIC -Wl,-TSectionLink.ld -shared
LFLAGS	:= $(LFLAGS) -Wl,-s,--no-seh,--enable-stdcall-fixup,-eDllMain

OUTX64	:= angryorchard.x64.dll
BINX64  := angryorchard.x64.bin

all:
	@ nasm -f win64 asm/x64/GetIp.asm -o GetIp.x64.o
	@ nasm -f win64 asm/x64/SystemCall.asm -o SystemCall.x64.o
	@ $(CC_X64) *.c GetIp.x64.o SystemCall.x64.o -o $(OUTX64) $(CFLAGS) $(LFLAGS) -I.
	@ python3 python3/extract.py -f $(OUTX64) -o $(BINX64)
	@ nasm -f bin asm/x64/Library.asm -i . -o $(OUTX64)

clean:
	@ rm -rf *.o
	@ rm -rf *.bin
	@ rm -rf *.dll
