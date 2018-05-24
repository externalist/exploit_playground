//
//  unjail.h
//  extra_recipe
//
//  Created by xerub on 16/05/2017.
//  Copyright © 2017 xerub. All rights reserved.
//

#ifndef unjail_h
#define unjail_h

#include <dlfcn.h>
#include <copyfile.h>
#include <stdio.h>
#include <spawn.h>
#include <unistd.h>
#include <mach/mach.h>
#include <mach-o/dyld.h>
#include <sys/stat.h>
#include <sys/mount.h>
#include <sys/utsname.h>
#include <Foundation/Foundation.h>

extern mach_port_t tfp0;
extern uint64_t kaslr_shift;
extern uint64_t kernel_base;

vm_size_t kread(vm_address_t where, uint8_t *p, vm_size_t size);
uint64_t kread_uint64(vm_address_t where);
uint32_t kread_uint32(vm_address_t where);
vm_size_t kwrite(vm_address_t where, const uint8_t *p, vm_size_t size);
vm_size_t kwrite_uint64(vm_address_t where, uint64_t value);
vm_size_t kwrite_uint32(vm_address_t where, uint32_t value);

void kx2(uint64_t fptr, uint64_t arg1, uint64_t arg2);
uint32_t kx5(uint64_t fptr, uint64_t arg1, uint64_t arg2, uint64_t arg3, uint64_t arg4, uint64_t arg5);

#endif /* unjail_h */
