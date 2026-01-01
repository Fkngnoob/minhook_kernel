/*
 *  MinHook Kernel - Kernel Mode API Hooking Library for x64
 *  Based on MinHook by Tsuda Kageyu
 *
 *  Simplified for x64 only - uses 14-byte absolute JMP for everything
 */

#pragma once

#include <ntddk.h>

/* Size of each memory slot for trampoline */
#define MEMORY_SLOT_SIZE 64

/* Size of 14-byte absolute JMP: FF 25 00 00 00 00 [8-byte address] */
#define JMP_ABS_SIZE 14

/* Maximum bytes we can copy from target function */
#define MAX_PROLOGUE_SIZE 32

#pragma pack(push, 1)

/*
 * 14-byte absolute JMP (x64)
 * FF 25 00 00 00 00    JMP [RIP+0]
 * XX XX XX XX XX XX XX XX   8-byte absolute address
 */
typedef struct _JMP_ABS
{
    UINT8  opcode0;     /* 0xFF */
    UINT8  opcode1;     /* 0x25 */
    UINT32 dummy;       /* 0x00000000 */
    UINT64 address;     /* Absolute destination address */
} JMP_ABS, *PJMP_ABS;

#pragma pack(pop)

typedef struct _TRAMPOLINE
{
    PVOID pTarget;          /* [In] Address of the target function */
    PVOID pDetour;          /* [In] Address of the detour function */
    PVOID pTrampoline;      /* [In] Buffer address for trampoline */
    SIZE_T copiedSize;      /* [Out] Number of bytes copied from target */
} TRAMPOLINE, *PTRAMPOLINE;

/*
 * Create a trampoline function.
 * Copies at least 16 bytes from target (for atomic cmpxchg16b), then appends JMP.
 *
 * Returns: TRUE on success, FALSE on failure
 */
BOOLEAN CreateTrampolineFunction(PTRAMPOLINE ct);

/*
 * Check if address is executable/valid
 */
BOOLEAN IsExecutableAddress(PVOID pAddress);
