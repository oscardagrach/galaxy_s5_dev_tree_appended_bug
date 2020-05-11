OUTPUT_FORMAT("elf32-littlearm")
OUTPUT_ARCH(arm)
ENTRY(_start)
SECTIONS
{
	. = LOAD_ADDR;
	PROVIDE(shellcode_start = .);

	.text : {
		*(.text)
	}

	/* always end on a word boundary for our copy */
	. = ALIGN(4);
	PROVIDE(shellcode_end = .);

	/DISCARD/ : { *(.dynstr*) }
	/DISCARD/ : { *(.dynamic*) }
	/DISCARD/ : { *(.plt*) }
	/DISCARD/ : { *(.interp*) }
	/DISCARD/ : { *(.gnu*) }
	/DISCARD/ : { *(.data*) }
	/DISCARD/ : { *(.rodata*) }
}
