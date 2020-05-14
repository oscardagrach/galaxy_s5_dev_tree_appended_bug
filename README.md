# galaxy_s5_dev_tree_appended_bug

## Vulnerability in the Samsung Galaxy S5 Bootloader

This is a bug I exploited in the Galaxy S5's bootloader to achieve arbitrary code execution at the application-bootloader level, which in this case is based on Little Kernel (LK). The vulnerability is in the dev_tree_appended function, which parses a Linux device tree blob that was appended to a zImage, as opposed to being packed as a separate image as this device's stock firmware does.

### Scope:
This vulnerability affects all Galaxy S5 variants, including Galaxy S5 Active variants, and possibly some early builds for the Galaxy Note 3 and 4. The bug has since been patched by both CodeAurora and Samsung. The device I exploited this on was the Verizon Galaxy S5 (G900V) on the G900VVRS2DQD1 firmware (Marshmallow, 6.0.1), which appears to be the more recent affected firmware.

### Summary:
Rewind the clock 7 years to the glory days of the XDA forums. The Galaxy S4 is released, with some variants bootloader locked, and the now famous exploit coined Loki is released by researcher Dan Rosenberg (djrbliss). This exploit effectively allowed the booting of unsigned boot and recovery images. 

##### How did he do it? 
During Dan's research, he discovered that the applications-bootloader doesn't apply any sanity checks to the boot image header, meaning you could pack up a proper Android boot image, or in our case, some shellcode, and load it to any arbitrary address in non-secure world memory. In this case, this was used to load shellcode over the applications-bootloader currently  being executed in memory. Not too long after its release, the vulnerability was patched, and Samsung placed much more focus on ensuring sane and safe parsing of boot image headers. 

##### Then what?
This resulted in several checks added to ensure that the kernel, ramdisk, and device tree don't overlap LK memory or anywhere else that would be problematic, like the scratch memory where the bootloader loads the boot image from eMMC.

##### What is a device tree?
Starting with the Galaxy S5, Samsung started using Linux kernel device trees, as many vendors opted to do in the Qualcomm msm8974 era.

It's essentially a small 'map, better known as a data structure, which the Linux kernel uses to determine what hardware is on-board, how it needs to be configured, etc. In Linux drivers that support device trees there is a phase coined "Probe", in which they search for a 'compatible node' in the device tree. This is in essence, a flag saying "Hey, please load the relevant driver for this hardware". Modern bootloaders often pass dynamic parameters to the device trees during boot, such as a reserved memory region like a framebuffer that the bootloader has already allocated. This was intended to help simplify bringing-up support for ARM, among other devices, and move away from the awful board files we were widely used in 3.10 kernels for ARM devices.

##### How does Samsung load their device trees?
There's a couple different methods to load a device tree. One such method used by Samsung and several other OEMs is to pack the device tree blob into the boot image. While it might be unknown to the public, often there are several hardware revisions of products, and in between these hardware revisions there may be different peripherals, minor design changes/fixes, etc.

In order to accomodate all these different revisions, Samsung concatenates all these different hardware revision's device trees into one blob so the kernel can then choose the best match for the hardware its booting on. 

##### Device tree header

Each device tree has the following header:

```C
struct fdt_header {
    uint32_t magic;
    uint32_t totalsize;
    uint32_t off_dt_struct;
    uint32_t off_dt_strings;
    uint32_t off_mem_rsvmap;
    uint32_t version;
    uint32_t last_comp_version;
    uint32_t boot_cpuid_phys;
    uint32_t size_dt_strings;
    uint32_t size_dt_struct;
};
```

Take note of totalsize, we will be coming back later to discuss it further...

```C
uint32_t totalsize;
```

Let's take a quick look at the Android boot image header v1 (prior to Android 9):

```C
struct boot_img_hdr
{
    uint8_t magic[BOOT_MAGIC_SIZE];
    uint32_t kernel_size;  /* size in bytes */
    uint32_t kernel_addr;  /* physical load addr */

    uint32_t ramdisk_size; /* size in bytes */
    uint32_t ramdisk_addr; /* physical load addr */

    uint32_t second_size;  /* size in bytes */
    uint32_t second_addr;  /* physical load addr */

    uint32_t tags_addr;    /* physical addr for kernel tags */
    uint32_t page_size;    /* flash page size we assume */
    uint32_t unused;
    uint32_t os_version;
    uint8_t name[BOOT_NAME_SIZE]; /* asciiz product name */
    uint8_t cmdline[BOOT_ARGS_SIZE];
    uint32_t id[8]; /* timestamp / checksum / sha1 / etc */
    uint8_t extra_cmdline[BOOT_EXTRA_ARGS_SIZE];
};
```

Let's pay particular attention to these two values:
```C
uint32_t tags_addr;    /* physical addr for kernel tags */
uint32_t unused;
```

The first member (tags_addr) is used to point where we want to load the device tree. The second member (unused) is used for the device tree blob size by Samsung. Yes, the bootloader checks that these are both sane values, and they are unsigned comparisons, so no integer overflows are possible... But did you know that LK also supports **another method** for loading a device tree?

##### Enter appended DTB
Many Android device OEMs opted to append the dtb to the end of the kernel (zImage) instead of pack it into its own image to simplify the requirements needed of the bootloader to load a device tree. The kernel and appended device tree are loaded together as a single blob. The bootloader will then parse an offset of 0x2C bytes into the zImage. Since it's a bit out of scope, 0x28 into the zImage is zimage_start and 0x2C is zimage_end, so zimage_end will have the size of the entire zImage. The bootloader will then take the value read from the zimage_end offset and add it to the kernel pointer, which theoretically would be where the device tree is appended.

For quick reference, this is what the zImage header looks like. Most of the other header info is unused, deprecated, or irrelevant. The information we care about starts here (magic is just there for reference):

```C
struct zImage_hdr {
	...
	uint32_t  magic      /* Magic number: 0x016f2818 */
	uint32_t  start      /* absolute load/run zImage address */
	uint32_t  end        /* zImage end address *
	...
};
```

##### How does the bootloader know which method to use? 
Easy. If you recall from earlier, the unused member of the boot image header is used for the size of the device tree blob. If the size is 0, the bootloader will attempt to load an appended DTB, if it is not zero, it will attempt the normal method.

##### A deeper look at loading appended DTBs

Now we know how to make the bootloader load an appended device tree, let's take a look at the beginning of the function that handles this:


```C
void *dev_tree_appended(void *kernel, uint32_t kernel_size, void *tags)
{
	void *kernel_end = kernel + kernel_size;
	uint32_t app_dtb_offset = 0;
	void *dtb;
	void *bestmatch_tag = NULL;
	uint32_t bestmatch_tag_size;
	uint32_t bestmatch_soc_rev_id = INVALID_SOC_REV_ID;

	memcpy((void*) &app_dtb_offset, (void*) (kernel + DTB_OFFSET), sizeof(uint32_t));

	dtb = kernel + app_dtb_offset;
	while (dtb + sizeof(struct fdt_header) < kernel_end) {
		uint32_t dtb_soc_rev_id;
		struct fdt_header dtb_hdr;
		uint32_t dtb_size;

		/* the DTB could be unaligned, so extract the header,
		 * and operate on it separately */
		memcpy(&dtb_hdr, dtb, sizeof(struct fdt_header));
		if (fdt_check_header((const void *)&dtb_hdr) != 0 ||
		    (dtb + fdt_totalsize((const void *)&dtb_hdr) > kernel_end))
			break;
		dtb_size = fdt_totalsize(&dtb_hdr);

		/* now that we know we have a valid DTB, we need to copy
		 * it somewhere aligned, like tags */
		memcpy(tags, dtb, dtb_size);
```



Almost immediately, the keen eye will notice a couple issues right off the bat.
```C
void *dev_tree_appended(void *kernel, uint32_t kernel_size, void *tags)
```

We see that both kernel and tags (where we load the device tree) are void, not unsigned. Both values point to their respective loading addresses from the boot image header. The first line of code in the function presents us with part of our vulnerability:

```C
[...]
void *kernel_end = kernel + kernel_size)
uint32_t app_dtb_offset = 0;
[...]

memcpy((void *) &app_dtb_offset, (void *)kernel + 0x2C), sizeof(uint32_t));
dtb = kernel + app_dtb_offset;
```

Here the function calculates kernel_end by adding the kernel ptr to the kernel_size find from the boot image header. The zImage header offset for zimage_end I talked about earlier is known to LK as the "app_dtb_offset", and we can see that is copies the 4-byte length to that variable. The dtb pointer is then calculated by adding the kernel pointer to the offset.

Next, we run into a couple of sanity checks. First, they verify that the dtb pointer + the size of the dtb header (0x28) is not larger than the end of the kernel, meaning we can't wrap the signed integer and set the dtb pointer somewhere over the kernel. Next the device tree header is copied to a buffer. 

From there, the device tree header is run through checks to ensure it is sane, valid (checking the FDT magic, len != 0, etc..) and that the dtb pointer + totalsize (the one I told you to remember from earlier) from the dtb header is not larger than kernel_end again, making sure we don't wrap that integer and end up pointing somewhere over the kernel.

##### The vulnerability

If the check is successful, the dtb_size is then stored from the header. Immediately after this, we can see our lovely little vulnerability...

```C
memcpy(tags, dtb, dtb_size);
```

Let's circle back to earlier, where we discussed Samsung's improved parsing of the boot image headers after the release of Loki. Surely we can't just point the tags_addr/dtb wherever we want. Let's look at some of Samsung's custom checks on header sanity:


![dev_tree_appended](/images/checks.png)


I couldn't fit as much disassembly in IDA as I could pseudocode from the GHIDRA decompiler into a screenshot, so I chose the latter for reference. Some checks are Samsung specific, and some are generic to LK.

We can conclude the following conditions need to be met:
1. None of the header addresses can overlap with LK's region (0x0F800000 - 0x0FA00000)
2. None of the header addresses + respective sizes (i.e, ramdisk + ramdisk_addr) can overlap LK's region
3. None of the header addresses can overlap OR be greater the scratch memory region (0x11000000), which is used to load boot image from eMMC
4. None of the header addresses + respective sizes can be greater than the scratch memory region
5. Assertion on second_size is unused by Samsung so we can't use any second_image (Notably not used in most cases)
6. tags_addr (dtb loading address) + total boot image length must not overlap LK region
7. No integers overflowing because of the unsigned comparison (BLS)

With that information, it's clear the only memory regions we have available for us available to load our ramdisk, kernel, and dtb, 0x0 - 0x0F800000 and 0x0FA00000 - 0x11000000.

Now that we know our conditions that must be met to be reach the vulnerable memcpy in dev_tree_appended, let's talk about how we can exploit this.

##### Well, how do we exploit this?

Remember the zImage header and the FDT (DTB) header, both of which contained their respective size?

We can arbitrarily change both kernel_end and app_dtb_offset without any checks up until this point. Really there's only three checks we need to satisfy in order to reach that vulnerable memcpy:

```C
while (dtb + sizeof(struct fdt_header) < kernel_end) {
```

```C
if (fdt_check_header((const void *)&dtb_hdr != 0 ||
  (dtb + fdt_totalsize(const void *) &dtb_hdr) > kernel_end)
    break;
```

1. dtb + dtb_header must be less than than kernel_end
2. dtb must have a valid header (FDT magic, etc...)
3. dtb + totalsize must be less than than kernel_end

##### How did you exploit this?

Now that we know the conditions that need to be met, we can overflow the dtb pointer via app_dtb_offset (from the zImage header) and we can control dtb_size via totalsize from the dtb header. Remember, even though we can overflow the dtb pointer, it still expects a valid dtb header at whatever location we point it to, and it still must be less than kernel_end. I'm sure there is more than one way to exploit this, but here's how I chose to:

##### Working backwards and doing "quick maths"
I first realized that I will need tags_addr as close as possible to 0x0F800000 without violating any of the sanity checks.

I settled on 0x0E000000, since even a rather large boot image *shouldn't* overlap with LK area, yet it's still rather close. This will be the destination for our vulnerable memcpy in dev_tree_appended, ideally overwriting the bootloader.

With our memcpy destination set to 0x0E000000, we have to figure out the size of our memcpy operation so that we overlap into LK region, which begins at 0x0F800000.

0x0F800000 - 0x0E000000 = 0x1800000

We know we need a malicious totalsize in the dtb header that is at least 0x1800000 to hit 0x0F800000. All that's required from the kernel image is that we have our valid zImage header and appended dtb. Since we need a valid dtb header at the address we want dtb to point to, we can replace the ramdisk with a malicious dtb header that includes our required memcpy size. This means though that we will need to have my payload at ramdisk_addr + 0x1800000. The default address Samsung uses for ramdisk is 0x02000000, which works fine for this scenario.

0x02000000 + 0x1800000 = 0x3800000

How will we get our payload to 0x3800000? Well, we still haven't decided where we will load the malicious kernel... we will need to account for the zImage header, since we don't want that overwriting LK memory, and instead we only want our payload being copied to 0x0F800000. The zImage header is 0x30 bytes, so we'll subtract that from where we'll load the kernel to account for it, and simply append our payload to the zImage header. We will want our zImage header length long enough to overflow

0x3800000 - 0x30 = 0x37FFFD0.

Now we need to overflow the dtb pointer to the ramdisk region where our malicious dtb header resides. This will be simple, we need 0x37FFFD0 to overflow to 0x02000000 (technically 0x102000000 if the highest bit wasn't knocked off)

0x102000000 - 0x37FFFD0 = 0xFE800030

![graph](/images/graph.png)

Our zImage header length will be 0xFE800030.

Here's what our memcpy looks like now:
```C
memcpy(tags_addr, dtb, dtb_size)

or for better visualization

memcpy(0x0E000000, 0x02000000, 0x1800000 + payload)
```

Let's look at what we need in our boot image header again (I removed irrelevant headers):
```C
struct boot_img_hdr
{
    uint8_t magic[BOOT_MAGIC_SIZE];
    uint32_t kernel_size = zImage_hdr + payload
    uint32_t kernel_addr = 0x37FFFD0

    uint32_t ramdisk_size = malicious_dtb_hdr (just long enough to pass checks, I just copied the first 0x110 bytes)
    uint32_t ramdisk_addr = 0x02000000
    
    uint32_t tags_addr = 0x0E000000

    uint32_t unused = 0x0 to trigger dev_tree_appended
};
```
Then we'd add our malicious zImage size to 0x2C into the zImage header, which will be 0xFE800030 as calculated later.

Finally, we'll add our malicious dtb totalsize of 0x1800000 + payload to the header with an offset of 0x4 into it. I created a fake boot image that's only 0x1800 bytes and simply appended a real boot image. From there, my shellcode will modify the partition table that LK loads into memory after reading the GPT, check if you are booting into recovery or boot, and add 0xC to the start sector of the respective partition. My shellcode overwrites the excetion vector table and hijacks the IRQ handler, and then executes boot_linux_from_mmc, which loads our boot image with the fixed partition table after restoring the original IRQ handler.

A proof of concept for the G900V (on the afformentioned firmware *only*) will be uploaded in the coming days.
