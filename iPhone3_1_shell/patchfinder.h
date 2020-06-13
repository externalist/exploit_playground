#ifndef PATCHFINDER_H
#define PATCHFINDER_H

#include <stdint.h>
#include <string.h>

// Helper gadget.
uint32_t find_memmove(uint32_t region, uint8_t* kdata, size_t ksize);

// Use for write-anywhere gadget.
uint32_t find_str_r1_r2_bx_lr(uint32_t region, uint8_t* kdata, size_t ksize);

// Helper gadget for changing page tables / patching.
uint32_t find_flush_dcache(uint32_t region, uint8_t* kdata, size_t ksize);

// Helper gadget for changing page tables.
uint32_t find_invalidate_tlb(uint32_t region, uint8_t* kdata, size_t ksize);

// This points to kernel_pmap. Use that to change the page tables if necessary.
uint32_t find_pmap_location(uint32_t region, uint8_t* kdata, size_t ksize);

// Write 0 here.
uint32_t find_proc_enforce(uint32_t region, uint8_t* kdata, size_t ksize);

// Write 1 here.
uint32_t find_cs_enforcement_disable_amfi(uint32_t region, uint8_t* kdata, size_t ksize);

// Write 1 here.
uint32_t find_cs_enforcement_disable_kernel(uint32_t region, uint8_t* kdata, size_t ksize);

// Change this to non-zero.
uint32_t find_i_can_has_debugger_1(uint32_t region, uint8_t* kdata, size_t ksize);

// Change this to what you want the value to be (non-zero appears to work).
uint32_t find_i_can_has_debugger_2(uint32_t region, uint8_t* kdata, size_t ksize);

// NOP out the conditional branch here.
uint32_t find_vm_map_enter_patch(uint32_t region, uint8_t* kdata, size_t ksize);

// Change the conditional branch here to an unconditional branch.
uint32_t find_vm_map_protect_patch(uint32_t region, uint8_t* kdata, size_t ksize);

// Change the conditional branch here to an unconditional branch.
uint32_t find_tfp0_patch(uint32_t region, uint8_t* kdata, size_t ksize);

// Write this with a jump to the sandbox hook, then write a trampoline back to just after the jump you wrote here. Sandbox hook should look at the path in *(r3 + 0x14) and force
// it to be allowed if it is outside of /private/var/mobile, or inside of /private/var/mobile/Library/Preferences but not /private/var/mobile/Library/Preferences/com.apple*
// To force it to allow, *r0 = 0 and *(r0 + 0x4) = 0x18. If not, just call the original function via the trampoline.
uint32_t find_sb_patch(uint32_t region, uint8_t* kdata, size_t ksize);

// Utility function, necessary for the sandbox hook.
uint32_t find_vn_getpath(uint32_t region, uint8_t* kdata, size_t ksize);

// Utility function, necessary for the sandbox hook.
uint32_t find_memcmp(uint32_t region, uint8_t* kdata, size_t ksize);

// Dereference this, add 0x38 to the resulting pointer, and write whatever boot-args are suitable to affect kern.bootargs.
uint32_t find_p_bootargs(uint32_t region, uint8_t* kdata, size_t ksize);

// This gets the zone_page_table array in osfmk/kern/zalloc.c. Useful for diagnosing problems with the zone allocator.
uint32_t find_zone_page_table(uint32_t region, uint8_t* kdata, size_t ksize);

// Function to free leaked ipc_kmsg objects
uint32_t find_ipc_kmsg_destroy(uint32_t region, uint8_t* kdata, size_t ksize);

// Function to find the syscall 0 function pointer. Used to modify the syscall table to call our own code.
uint32_t find_syscall0(uint32_t region, uint8_t* kdata, size_t ksize);

// Function used to free any dead ports we find to clean up after memory leak.
uint32_t find_io_free(uint32_t region, uint8_t* kdata, size_t ksize);

// Function used to find IOLog for printing debug messages
uint32_t find_IOLog(uint32_t region, uint8_t* kdata, size_t ksize);

#endif
