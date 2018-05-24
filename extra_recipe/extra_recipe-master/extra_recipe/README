// ianbeer

kernel arbitrary read/write exploit for CVE-2017-2370 for iOS 10.2

Only tested on iPod Touch 6G 14C92 - other devices/firmwares will not work out of the box!

*** the bug ***
mach_voucher_extract_attr_recipe_trap is a mach trap which can be called from any context. It's brand new code, added in iOS 10.

  kern_return_t
  mach_voucher_extract_attr_recipe_trap(struct mach_voucher_extract_attr_recipe_args *args)
  {
    ipc_voucher_t voucher = IV_NULL;
    kern_return_t kr = KERN_SUCCESS;
    mach_msg_type_number_t sz = 0;

    if (copyin(args->recipe_size, (void *)&sz, sizeof(sz)))              <---------- (a)
      return KERN_MEMORY_ERROR;

    if (sz > MACH_VOUCHER_ATTR_MAX_RAW_RECIPE_ARRAY_SIZE)
      return MIG_ARRAY_TOO_LARGE;

    voucher = convert_port_name_to_voucher(args->voucher_name);
    if (voucher == IV_NULL)
      return MACH_SEND_INVALID_DEST;

    mach_msg_type_number_t __assert_only max_sz = sz;

    if (sz < MACH_VOUCHER_TRAP_STACK_LIMIT) {
      /* keep small recipes on the stack for speed */
      uint8_t krecipe[sz];
      if (copyin(args->recipe, (void *)krecipe, sz)) {
        kr = KERN_MEMORY_ERROR;
        goto done;
      }
      kr = mach_voucher_extract_attr_recipe(voucher, args->key,
          (mach_voucher_attr_raw_recipe_t)krecipe, &sz);
      assert(sz <= max_sz);

      if (kr == KERN_SUCCESS && sz > 0)
        kr = copyout(krecipe, (void *)args->recipe, sz);
    } else {
      uint8_t *krecipe = kalloc((vm_size_t)sz);                          <---------- (b)
      if (!krecipe) {
        kr = KERN_RESOURCE_SHORTAGE;
        goto done;
      }

      if (copyin(args->recipe, (void *)krecipe, args->recipe_size)) {    <----------- (c)
        kfree(krecipe, (vm_size_t)sz);
        kr = KERN_MEMORY_ERROR;
        goto done;
      }

      kr = mach_voucher_extract_attr_recipe(voucher, args->key,
            (mach_voucher_attr_raw_recipe_t)krecipe, &sz);
      assert(sz <= max_sz);

      if (kr == KERN_SUCCESS && sz > 0)
        kr = copyout(krecipe, (void *)args->recipe, sz);
      kfree(krecipe, (vm_size_t)sz);
    }

    kr = copyout(&sz, args->recipe_size, sizeof(sz));

    done:
    ipc_voucher_release(voucher);
    return kr;
  }


Here's the argument structure (controlled from userspace)

struct mach_voucher_extract_attr_recipe_args {
PAD_ARG_(mach_port_name_t, voucher_name);
PAD_ARG_(mach_voucher_attr_key_t, key);
PAD_ARG_(mach_voucher_attr_raw_recipe_t, recipe);
PAD_ARG_(user_addr_t, recipe_size);
};

recipe and recipe_size are userspace pointers.

At point (a) four bytes are read from the userspace pointer recipe_size into sz.

At point (b) if sz was less than MACH_VOUCHER_ATTR_MAX_RAW_RECIPE_ARRAY_SIZE (5120) and greater than MACH_VOUCHER_TRAP_STACK_LIMIT (256)
sz is used to allocate a kernel heap buffer.

At point (c) copyin is called again to copy userspace memory into that buffer which was just allocated, but rather than passing sz (the
validate size which was allocated) args->recipe_size is passed as the size. This is the userspace pointer *to* the size, not the size!

This leads to a completely controlled kernel heap overflow. Note that the code actually can't work properly :)

*** the exploit ***

I target preallocated mach message buffers which are allocated via kalloc. The first 4 bytes are a size field which is used to determine
where in the buffer to read and write a message. By corrupting this field we can cause mach messages to be read and written outside the bounds of
the kalloc allocation backing the kmsg.

There is a slight complication in that a port's preallocated kmsg will only be used for actual mach_msg sends by the kernel (not for replies
to MIG methods for example.) This makes it a bit trickier to get enough controlled content in them.

One type of mach message which the kernel sends with a lot of user-controlled data is an exception message, sent when a thread crashes.

The file load_regs_and_crash.s contains ARM64 assembly which loads the ARM64 general purpose registers with the contents of a buffer
such that when it crashes the exception message contains that data buffer (about 0x70 bytes are controlled.)

By overwriting the port's ikm_size field to point to the header of another port we can read and write another port's header and learn where it is
in memory. We can then free that second port and reallocate a user client in its place which we can also read and write.

I read the userclients vtable pointer then use the OSSerializer::serialize gadget technique as detailed in
[https://info.lookout.com/rs/051-ESQ-475/images/pegasus-exploits-technical-details.pdf] to call an arbitrary function with two controlled arguments.

I call uuid_copy which calls memmove(arg0, arg1, 0x10). By pointing either arg0 or arg1 into the userclient itself (which we can read by receiving the
exception message) we can read and write arbitrary kernel memory in 16 byte chunks.
