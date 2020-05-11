CROSS_COMPILE = arm-none-eabi-

# Use our cross-compile prefix to set up our basic cross compile environment.
CC      = $(CROSS_COMPILE)gcc
LD      = $(CROSS_COMPILE)ld
OBJCOPY = $(CROSS_COMPILE)objcopy

CFLAGS = \
	-mtune=arm7tdmi \
	-mlittle-endian \
	-fno-stack-protector \
	-fno-common \
	-fno-builtin \
	-ffreestanding \
	-std=gnu99 \
	-Werror \
	-Wall \
	-Wno-error=unused-function \
	-fomit-frame-pointer \
	-g \
	-Os \

LDFLAGS =

all: shellcode.bin

# Where the shellcode is loaded
BOOTLOADER_ADDRESS := 0x0F800000

shellcode.elf: shellcode.o
	$(LD) -T shellcode.lds --defsym LOAD_ADDR=$(BOOTLOADER_ADDRESS) $(LDFLAGS) $^ -o $@

shellcode.o: shellcode.S
	$(CC) $(CFLAGS32) $(DEFINES) $< -c -o $@

%.bin: %.elf
	$(OBJCOPY) -v -O binary $< $@

clean:
	rm -f *.o *.elf *.bin

.PHONY: all clean
