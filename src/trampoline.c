/*
 *  MinHook Kernel - Kernel Mode API Hooking Library for x64
 *  Based on MinHook by Tsuda Kageyu
 *
 *  Simplified for x64 only - uses 14-byte absolute JMP
 */

#pragma warning(push)
#pragma warning(disable: 4996) /* ExAllocatePoolWithTag deprecated */

#include <ntddk.h>
#include <minwindef.h>
#include "hde64.h"
#include "trampoline.h"

#define MHK_POOL_TAG 'kHhM'

/* Page size for safe copy */
#define PAGE_COPY_SIZE 0x1000

/*-------------------------------------------------------------------------*/
BOOLEAN IsExecutableAddress(PVOID pAddress)
{
    if (pAddress == NULL)
        return FALSE;

    return MmIsAddressValid(pAddress);
}

/*-------------------------------------------------------------------------*/
/*
 * Check if instruction uses RIP-relative addressing.
 * ModR/M byte with mod=00 and r/m=101 indicates RIP-relative.
 */
static BOOLEAN IsRipRelativeInstruction(hde64s* hs)
{
    /* Check ModR/M for RIP-relative (mod=00, r/m=101) */
    if ((hs->modrm & 0xC7) == 0x05)
        return TRUE;

    return FALSE;
}

/*-------------------------------------------------------------------------*/
/*
 * Build the 14-byte absolute JMP instruction
 */
static VOID BuildAbsoluteJmp(PUINT8 pDest, ULONG_PTR address)
{
    PJMP_ABS pJmp = (PJMP_ABS)pDest;
    pJmp->opcode0 = 0xFF;
    pJmp->opcode1 = 0x25;
    pJmp->dummy   = 0x00000000;
    pJmp->address = address;
}

/*-------------------------------------------------------------------------*/
BOOLEAN CreateTrampolineFunction(PTRAMPOLINE ct)
{
    PUINT8 pSafeCopy = NULL;
    SIZE_T oldPos = 0;
    SIZE_T newPos = 0;
    BOOLEAN result = FALSE;

    if (ct == NULL || ct->pTarget == NULL ||
        ct->pDetour == NULL || ct->pTrampoline == NULL)
    {
        return FALSE;
    }

    if (!IsExecutableAddress(ct->pTarget))
        return FALSE;

    /*
     * Allocate a safe copy of the target page.
     * This prevents issues if the page becomes invalid during disassembly.
     */
    pSafeCopy = (PUINT8)ExAllocatePoolWithTag(NonPagedPoolNx, PAGE_COPY_SIZE, MHK_POOL_TAG);
    if (pSafeCopy == NULL)
        return FALSE;

    /* Copy the target area to our safe buffer */
    RtlCopyMemory(pSafeCopy, ct->pTarget, MAX_PROLOGUE_SIZE + JMP_ABS_SIZE);

    /* Zero the trampoline buffer */
    RtlZeroMemory(ct->pTrampoline, MEMORY_SLOT_SIZE);

    /*
     * Disassemble instructions until we have at least 16 bytes.
     * (16 bytes for atomic InterlockedCompareExchange128)
     * Copy each complete instruction to the trampoline.
     */
    while (oldPos < 16)
    {
        hde64s hs;
        UINT len;

        if (oldPos >= MAX_PROLOGUE_SIZE)
        {
            /* Prologue too long */
            goto cleanup;
        }

        len = hde64_disasm(pSafeCopy + oldPos, &hs);
        if (hs.flags & F_ERROR)
        {
            /* Disassembly error */
            goto cleanup;
        }

        /*
         * Check for unsupported instructions:
         * - RIP-relative addressing: would need recalculation
         * - Short/near jumps within the patch area: would break
         * - RET: function too short
         */
        if (IsRipRelativeInstruction(&hs))
        {
            /* RIP-relative instruction in prologue - not supported */
            goto cleanup;
        }

        /* Check for relative jumps/calls */
        if ((hs.opcode & 0xFD) == 0xE9 ||    /* JMP rel8/rel32 */
            hs.opcode == 0xE8 ||              /* CALL rel32 */
            (hs.opcode & 0xF0) == 0x70 ||     /* Jcc rel8 */
            (hs.opcode == 0x0F && (hs.opcode2 & 0xF0) == 0x80) || /* Jcc rel32 */
            (hs.opcode & 0xFC) == 0xE0)       /* LOOP/LOOPZ/LOOPNZ/JCXZ */
        {
            /* Relative branch in prologue - not supported */
            goto cleanup;
        }

        /* RET in prologue means function is too short */
        if ((hs.opcode & 0xFE) == 0xC2)
        {
            goto cleanup;
        }

        /* Copy the instruction to trampoline */
        RtlCopyMemory((PUINT8)ct->pTrampoline + newPos, pSafeCopy + oldPos, len);

        oldPos += len;
        newPos += len;
    }

    /*
     * Append 14-byte absolute JMP to continue execution after the patch area.
     * This jumps to: pTarget + oldPos (the first uncopied instruction)
     */
    if (newPos + JMP_ABS_SIZE > MEMORY_SLOT_SIZE)
    {
        /* Trampoline buffer overflow */
        goto cleanup;
    }

    BuildAbsoluteJmp((PUINT8)ct->pTrampoline + newPos, (ULONG_PTR)ct->pTarget + oldPos);

    ct->copiedSize = oldPos;
    result = TRUE;

cleanup:
    if (pSafeCopy != NULL)
    {
        ExFreePoolWithTag(pSafeCopy, MHK_POOL_TAG);
    }

    return result;
}

#pragma warning(pop)
