//
//  offsets.h
//  extra_recipe
//
//  Created by xerub on 28/05/2017.
//  Copyright © 2017 xerub. All rights reserved.
//

#ifndef offsets_h
#define offsets_h

enum {
    ERR_NOERR = 0,
    ERR_INTERNAL = 1,
    ERR_UNSUPPORTED = 2,
    ERR_UNSUPPORTED_YET = 3,
};

extern unsigned offsetof_p_pid;
extern unsigned offsetof_task;
extern unsigned offsetof_p_ucred;
extern unsigned offsetof_p_csflags;
extern unsigned offsetof_itk_self;
extern unsigned offsetof_itk_sself;
extern unsigned offsetof_itk_bootstrap;
extern unsigned offsetof_ip_mscount;
extern unsigned offsetof_ip_srights;
extern unsigned offsetof_special;

extern const char *mp;

extern uint64_t AGXCommandQueue_vtable;
extern uint64_t OSData_getMetaClass; // +8 == ret
extern uint64_t OSSerializer_serialize;
extern uint64_t k_uuid_copy;

extern uint64_t allproc;
extern uint64_t realhost;
extern uint64_t call5;

extern int nports;

int init_offsets(void);
uint64_t constget(int idx);

#endif /* offsets_h */
