.section ".text"
.global _start

exception_vectors:
	b	0x0F800020 /* reset */
	b	0x0F8182C8 /* undefined */
	b	0x0F8182E4 /* syscall */
	b	0x0F818300 /* prefetch abort */
	b	0x0F81831C /* data abort */
	b	0x0F818338 /* reserved */
	b	_start	   /* irq */
	b	0x0F81839C /* fiq */

_start:
/* save context */
	stmea	sp, {r4-r6}
	mov	r4, sp

/* set developer_mode flag */
	ldr	r5, developer_flag
	mov	r6, #0x1
	str	r6, [r5]

/* fixup IRQ vector */
	ldr	r5, irq_ptr
	ldr	r6, irq_func
	str	r6, [r5]

/* patch warranty bit set */
	ldr	r5, nop_ptr
	ldr	r6, nop
	str	r6, [r5]

/* lcd_print hack */
	ldr	r5, string_color_ptr
	ldr	r6, string_color
	str	r6, [r5]

/* string hax */
	ldr	r5, string_ptr
	ldr	r6, string1
	str	r6, [r5]
	add	r5, #0x4
	ldr	r6, string2
	str	r6, [r5]
	add	r5, #0x4
	ldr	r6, string3
	str	r6, [r5]
	add	r5, #0x4
	ldr	r6, string4
	str	r6, [r5]
	add	r5, #0x4
	ldr	r6, string5
	str	r6, [r5]
	add	r5, #0x4
	ldr	r6, string6
	str	r6, [r5]

/* check recovery_flag, !=0 recovery, ==0 boot */
	ldr	r5, recovery_flag
	ldr	r5, [r5]
	cmp	r5, #0
	bne	recovery

boot:
/* add 0xC to start sector (actual boot img offset into part) */
	ldr	r5, boot_part_ptr
	ldr	r6, [r5]
	add	r6, #0xC
	str	r6, [r5]
	b	done

recovery:
/* add 0xC to start sector (actual recovery img offset into part) */
	ldr	r5, recovery_part_ptr
	ldr	r6, [r5]
	add	r6, #0xC
	str	r6, [r5]

done:
/*	SVC mode, boot_linux_from_mmc, must use CPSR_c to leave condition flags alone */
	mrs	r6, CPSR
	orr	r5, r6, #3
	msr	CPSR_c, r5

	ldmia	r4, {r4-r6}
	b	boot_linux_from_mmc

boot_linux_from_mmc:
	.word	0x0F821254
recovery_part_ptr:
	.word	0x0F946644
boot_part_ptr:
	.word	0x0F9465AC
irq_func:
	.word	0xEA0060C7
irq_ptr:
	.word	0x0F800018
developer_flag:
	.word	0x0F93AC10
recovery_flag:
	.word 	0x0F93FFEC
nop_ptr:
	.word	0x0F8216B4
nop:
	.word	0xE320F000
string_ptr:
	.word	0x0F862264
string1:
	.word	0x454E5750
string2:
	.word	0x59422044
string3:
	.word	0x43534F20
string4:
	.word	0x41445241
string5:
	.word	0x43415247
string6:
	.word	0x00002148
string_color_ptr:
	.word	0x0F8212A8
string_color:
	.word	0xE3A00CFF
