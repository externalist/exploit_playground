.text
.globl  _load_regs_and_crash
.align  2
_load_regs_and_crash:
mov x30, x0
ldp x0, x1, [x30, 0]
ldp x2, x3, [x30, 0x10]
ldp x4, x5, [x30, 0x20]
ldp x6, x7, [x30, 0x30]
ldp x8, x9, [x30, 0x40]
ldp x10, x11, [x30, 0x50]
ldp x12, x13, [x30, 0x60]
ldp x14, x15, [x30, 0x70]
ldp x16, x17, [x30, 0x80]
ldp x18, x19, [x30, 0x90]
ldp x20, x21, [x30, 0xa0]
ldp x22, x23, [x30, 0xb0]
ldp x24, x25, [x30, 0xc0]
ldp x26, x27, [x30, 0xd0]
ldp x28, x29, [x30, 0xe0]
brk 0
.align  3
