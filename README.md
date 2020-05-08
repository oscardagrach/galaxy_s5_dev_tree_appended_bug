# s5_dev_tree_appended_bug
## Vulnerability in the Samsung Galaxy S5 Bootloader

This is a bug I exploited in the Galaxy S5 bootloader to achieve arbitrary code execution in LK. The vulnerability is in the function dev_tree_appended, which parses a device tree blob that's appended to a zImage, as opposed to packed as a separate image in an Android boot image like stock.

### Scope:
This vulnerability affects all Galaxy S5, Galaxy S5 Active, and possibly some early builds for the Note 3 and 4. The bug has since been patched by CodeAurora and Samsung. The device I am using is the Verizon Galaxy S5 (G900V) and I am using the G900VVRS2DQD1 (Marshmallow, 6.0.1), which appears to be the last firmware affected.

### Summary:
Rewind the clock 7 years to the glory days of XDA. The Galaxy S4 is released, and the famous exploit Loki is released by researcher Dan Rosenberg/djrbliss. This effectively allowed the booting of unsigned boot and recovery images. So how did he do it? During Dan's research, he discovered that the bootloader doesn't apply any sanity checks to the boot image headers, meaning you could pack up a kernel, ramdisk, or shellcode, and load it to any arbitrary address in non-secure world, including over the bootloader being executed in memory. Not too long after, the vulnerability was patched, and Samsung placed much more focus on ensuring sane and safe parsing of boot image headers. 

This resulted in several checks added to ensure that the kernel, ramdisk, and device tree don't overlap LK memory or anywhere else that would be problematic, like the scratch memory where the bootloader loads the boot image from eMMC.

Starting with the Galaxy S5 (I believe the S4 used ATAGS but correct me if I'm wrong...), Samsung started using device trees. 

##### What is a device tree?

It's essentially a small 'map' or data structure for the Linux kernel to determine what hardware is on-board, how it's configured, etc... During the probe phase of Linux drivers that support device trees, they search for a 'comaptible node' in the device tree, a flag saying "hey, please load this driver, we have this hardware." This was meant to help simplify bringing-up and supporting ARM (and other) devices, and move away from the awful board files we were so used to in the 3.10 kernel.

##### How does Samsung load their device trees?

There's a couple different ways to load a device tree. One such method used by Samsung  and several other OEMs is to pack the device tree blob into the boot image. While it might be unknown to the public, often there are several hardware revisions of products, and in between these hardware revisions there may be different peripherals, minor design changes/fixes, etc... In order to accomodate all these different revisions, Samsung concatenates all these different hardware revision's device trees into one blob so the kernel can choose the best match.

Let's take a quick look at the Android boot image header (prior to Android 9):

```
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
```
uint32_t tags_addr;    /* physical addr for kernel tags */
uint32_t unused;
```

The first member (tags_addr) is used to point where we want to load the device tree. The second member (unused) is used for the device tree blob size by Samsung. Yes, the bootloader checks that these are both sane values, and they are unsigned comparisons, so no integer overflows for us... But did you know that LK also supports **another method** for loading a device tree?

##### Enter appended DTB
We append the dtb to the end of our kernel (zImage). The bootloader will then parse an offset of 0x2C bytes into the zImage. Since it's a bit out of scope, 0x28 into the zImage is zimage_start and 0x2C is zimage_end, so zimage_end will have the size of the entire zImage. The bootloader will then take the value read from the zimage_end offset and add it to the kernel pointer, which theoretically would be where the device tree is appended.

##### How does the bootloader know which method to use? 
Easy. If you recall from earlier, the unused member of the boot image header is used for the size of the device tree blob. If the size is 0, the bootloader will attempt to load an appended DTB, if it is not zero, it will attempt the normal method.

##### A deeper look at loading appended DTBs

Now we know how to make the bootloader load an appended device tree, let's take a look at the beginning of the function that handles this:


![dev_tree_appended](/images/dev_tree_appended.png)



Almost immediately, the keen eye will notice a couple issues right off the bat.
```
void * dev_tree_appended(void *kernel, uint32_t kernel_size, void *tags)
```

We see that both kernel and tags (where we load the device tree) are void, not unsigned. Both values point to their respective loading addresses from the boot image header. The first line of code in the function already presents us with part of our vulnerability:

```
[...]
void *kernel_end = kernel + kernel_size)
uint32_t app_dtb_offset = 0;
[...]

app_dtb_offset = 0;
memcpy(&app_dtb_offset, kernel + 0x2C), 4);
dtb = kernel + app_dtb_offset;
```

Here the function calculates the kernel_end by adding the kernel ptr to the kernel_size find from the boot image header. The zImage header offset for zimage_end I talked about earlier is known as the "app_dtb_offset" according to LK, and we can see they copy the 4-byte length to that variable. Then the dtb pointer is calculated by adding the kernel pointer to the offset.

Next, we run into a couple of sanity checks. First, they verify that the dtb pointer + the size of the dtb header is not larger than the end of the kernel, meaning we can't wrap the signed integer and set the dtb pointer somewhere over the kernel. Next the device tree header is copied to a buffer. 

From there, the device tree header is checked that it is sane and valid (checking the FDT magic, len != 0, etc..) and that the dtb pointer + dtb_size from the dtb header is not larger than kernel_end again, making sure we don't wrap that integer and end up pointing somewhere over the kernel.

##### The vulnerability

If the check is successful, the dtb_size is then stored from the header. Immediately after this, we can see our lovely little vulnerability...

```
memcpy(tags, dtb, dtb_size);
```

Let's circle back to earlier, where we discussed Samsung's improved parsing of the boot image headers after the release of Loki. Surely we can't just point the tags_addr/dtb wherever we want. Let's look at some of Samsung's custom checks on header sanity:


![dev_tree_appended](/images/checks.png)


I couldn't fit as much disassembly in IDA as I could pseudocode for the GHIDRA decompiler into a screenshot, so I chose the latter for reference. Some checks are Samsung specific, and some are generic to LK.

We can conclude the following conditions need to be met:
1. None of the header addresses can overlap with LK area (0x0F800000 - 0x0FA00000)
2. None of the header addresses + respective sizes (i.e, ramdisk + ramdisk_addr) can overlap LK area
3. None of the headder addresses can overlap OR be greater the scratch memory region (0x11000000) (used to load boot image from eMMC)
4. None of the header addresses + respective sizes can be greater than the scratch memory region
5. Assertion on second_size (unused by Samsung) so we can't use any second_image (not used much anyways)
6. tags_addr (dtb loading address) + total boot image length must not overlap LK area

With that information, it's clear the only memory regions we have available for us available to load our ramdisk, kernel, and dtb, 0x0 - 0x0F800000 and 0x0FA00000 - 0x11000000.

Now that we know our conditions that must be met to be reach the vulnerable memcpy in dev_tree_appended, let's talk about how we can exploit this.

##### Well, how do we exploit this?

Remember the zImage header and the FDT (DTB) header, both of which contained their respective size?

We can arbitrarily change both kernel_end and app_dtb_offset without any checks up until this point. Really there's only three checks we need to satisfy in order to reach that vulnerable memcpy:

```
while (dtb + sizeof(struct fdt_header) < kernel_end) {
```

```
if (fdt_check_header((const void *)&dtb_hdr != 0 ||
  (dtb + fdt_totalsize(const void *) &dtb_hdr) > kernel_end)
    break;
dtb_size = fdt_totalsize(&dtb_hdr);
```

1. dtb + dtb_header must be less than than kernel_end
2. dtb has a valid header (FDT magic, etc...)
3. dtb + dtb_size must be lower than kernel_end

##### How did you exploit this?

Now that we know the conditions that need to be met, we can overflow the dtb pointer via app_dtb_offset (from the zImage header) and we can control dtb_size via the dtb length from the dtb header. Remember, even though we can overflow the dtb pointer, it still expects a valid dtb header at whatever location we point it to, and it still must be less than kernel_end. I'm sure there is more than one way to exploit this, but here's what I did...

##### Working backwards and doing maths
First thing I realized was that I will need tags_addr as close as possible to 0x0F800000 without violating any of the sanity checks

I settled on 0x0E000000, since even a rather large boot image *shouldn't* overlap with LK area, yet it's still rather close. This will be the destination for our vulnerable memcpy in dev_tree_appended, ideally overwriting the bootloader.

With our memcpy destination set to 0x0E000000, we have to figure out the size of our memcpy operation so that we overlap into LK area, which begins at 0x0F800000.

0x0F800000 - 0x0E000000 = 0x1800000

We know we need a malicious dtb size in the dtb header that is at least 0x1800000 to hit 0x0F800000. All that's required from the kernel image is that we have our valid zImage header and appended dtb. Since we need a valid dtb header at the address I want dtb to point to, I can replace the ramdisk with a malicious dtb header that includes our required memcpy size. This means though that I will need to have my payload at ramdisk_addr + 0x1800000. The default address Samsung uses for ramdisk is 0x02000000, which works fine for this scenario.

0x02000000 + 0x1800000 = 0x3800000

How will we get our payload to 0x3800000? Well, we still haven't decided where we will load the malicious kernel... We will need to account for the zImage header, since we don't want that overwriting LK memory, and instead we only want our payload being copied @ 0x0F800000. The zImage header is 0x30 bytes, so we'll subtract that from where we'll load the kernel to account for it, and simply append our payload to the zImage header. We will want our zImage header length long enough to overflow

0x3800000 - 0x30 = 0x37FFFD0.

Now we need to overflow the dtb pointer to the ramdisk region where our malicious dtb header resides. This will be simple, we need 0x37FFFD0 to overflow to 0x02000000 (technically 0x102000000 if the highest bit wasn't knocked off)

0x102000000 - 0x37FFFD0 = 0xFE800030

Our zImage header length will be 0xFE800030.

Here's what our memcpy looks like now:
```
memcpy(tags_addr, dtb, dtb_size
memcpy(0x0E000000, 0x02000000, 0x1800000 + payload)
```

Let's look at what we need in our boot image header again (I removed irrelevant headers):
```
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

Finally, we'll add our malicious device tree header length of 0x1800000 + payload to the header with an offset of 0x4 into it. What I did was create a fake boot image that's only 0x1800 bytes and simply appended a real boot image. From there, my shellcode will modify the partition table that LK loads into memory after reading the GPT, check if you are booting into recovery or boot, and add 0xC to the start sector of the respective partition. My shellcode overwrites the excetion vector table and hijacks the IRQ handler, and then executes boot_linux_from_mmc, which loads our boot image with the fixed partition table after restoring the original IRQ handler.

My proof of concept for the G900V will be uploaded in the coming days.

