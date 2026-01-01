/*
 *  MinHook Kernel - Kernel Mode API Hooking Library for x64
 *  Based on MinHook by Tsuda Kageyu
 *
 *  Simplified for x64 only - uses 14-byte absolute JMP
 *  Uses InterlockedCompareExchange128 for atomic patching (hk.c style)
 */

#pragma warning(push)
#pragma warning(disable: 4996) /* ExAllocatePoolWithTag deprecated */

#include <ntddk.h>
#include <intrin.h>
#include <minwindef.h>
#include "../include/minhook_kernel.h"
#include "trampoline.h"

/* Memory pool tag */
#define MHK_POOL_TAG 'kHhM'

/* Initial capacity of hook entries */
#define INITIAL_HOOK_CAPACITY 32

/* Sizes */
#define INTERLOCKED_SIZE 16

/*-------------------------------------------------------------------------*/
/* Hook entry structure */
/*-------------------------------------------------------------------------*/
typedef struct _HOOK_ENTRY
{
    PVOID pTarget;              /* Address of target function */
    PVOID pDetour;              /* Address of detour function */
    PVOID pTrampoline;          /* Address of trampoline function */
    SIZE_T copiedSize;          /* Number of bytes copied to trampoline */
    UINT8 backup[INTERLOCKED_SIZE]; /* Original 16 bytes backup */
    BOOLEAN isEnabled;          /* Currently enabled */
} HOOK_ENTRY, *PHOOK_ENTRY;

/*-------------------------------------------------------------------------*/
/* Global variables */
/*-------------------------------------------------------------------------*/
static volatile LONG g_isLocked = FALSE;
static BOOLEAN g_isInitialized = FALSE;

/* Hook entries */
static struct
{
    PHOOK_ENTRY pItems;
    UINT capacity;
    UINT size;
} g_hooks = { NULL, 0, 0 };

/*-------------------------------------------------------------------------*/
/* Forward declarations */
/*-------------------------------------------------------------------------*/
static UINT FindHookEntry(PVOID pTarget);
static PHOOK_ENTRY AddHookEntry(VOID);
static VOID DeleteHookEntry(UINT pos);
static NTSTATUS ReplaceCode16Bytes(PVOID pAddress, PUINT8 pReplacement);
static MHK_STATUS EnableHookLL(UINT pos, BOOLEAN enable);

/*-------------------------------------------------------------------------*/
/* Spin lock implementation */
/*-------------------------------------------------------------------------*/
static VOID EnterSpinLock(VOID)
{
    SIZE_T spinCount = 0;

    while (InterlockedCompareExchange(&g_isLocked, TRUE, FALSE) != FALSE)
    {
        if (spinCount < 32)
            YieldProcessor();
        else
            KeStallExecutionProcessor(1);

        spinCount++;
    }
}

static VOID LeaveSpinLock(VOID)
{
    InterlockedExchange(&g_isLocked, FALSE);
}

/*-------------------------------------------------------------------------*/
/* Atomic 16-byte code replacement using MDL (hk.c style) */
/*-------------------------------------------------------------------------*/
static NTSTATUS ReplaceCode16Bytes(PVOID pAddress, PUINT8 pReplacement)
{
    PMDL pMdl;
    PLONG64 pMapping;
    LONG64 previous[2];
    NTSTATUS status;

    /* Check for 16-byte alignment (required for cmpxchg16b) */
    if (((ULONG_PTR)pAddress & 0xF) != 0)
        return STATUS_DATATYPE_MISALIGNMENT;

    /* Allocate MDL */
    pMdl = IoAllocateMdl(pAddress, INTERLOCKED_SIZE, FALSE, FALSE, NULL);
    if (pMdl == NULL)
        return STATUS_INSUFFICIENT_RESOURCES;

    /* Lock pages - may bugcheck if invalid, user accepts this risk */
    MmProbeAndLockPages(pMdl, KernelMode, IoReadAccess);

    /* Map to new VA */
    pMapping = (PLONG64)MmMapLockedPagesSpecifyCache(
        pMdl,
        KernelMode,
        MmNonCached,
        NULL,
        FALSE,
        NormalPagePriority
    );

    if (pMapping == NULL)
    {
        MmUnlockPages(pMdl);
        IoFreeMdl(pMdl);
        return STATUS_INTERNAL_ERROR;
    }

    /* Set page protection to read-write */
    status = MmProtectMdlSystemAddress(pMdl, PAGE_READWRITE);
    if (!NT_SUCCESS(status))
    {
        MmUnmapLockedPages(pMapping, pMdl);
        MmUnlockPages(pMdl);
        IoFreeMdl(pMdl);
        return status;
    }

    /* Read current content */
    previous[0] = pMapping[0];
    previous[1] = pMapping[1];

    /* Atomic 16-byte replacement using cmpxchg16b */
    InterlockedCompareExchange128(
        pMapping,
        ((PLONG64)pReplacement)[1],
        ((PLONG64)pReplacement)[0],
        previous
    );

    /* Cleanup */
    MmUnmapLockedPages(pMapping, pMdl);
    MmUnlockPages(pMdl);
    IoFreeMdl(pMdl);

    return STATUS_SUCCESS;
}

/*-------------------------------------------------------------------------*/
/* Build 14-byte absolute JMP: FF 25 00 00 00 00 [8-byte addr] */
/*-------------------------------------------------------------------------*/
static VOID BuildAbsoluteJmp(PUINT8 pDest, ULONG_PTR address)
{
    pDest[0] = 0xFF;
    pDest[1] = 0x25;
    pDest[2] = 0x00;
    pDest[3] = 0x00;
    pDest[4] = 0x00;
    pDest[5] = 0x00;
    *(PULONG_PTR)(pDest + 6) = address;
}

/*-------------------------------------------------------------------------*/
/* Hook entry management */
/*-------------------------------------------------------------------------*/
static UINT FindHookEntry(PVOID pTarget)
{
    UINT i;
    for (i = 0; i < g_hooks.size; ++i)
    {
        if ((ULONG_PTR)pTarget == (ULONG_PTR)g_hooks.pItems[i].pTarget)
            return i;
    }
    return MAXUINT32;
}

static PHOOK_ENTRY AddHookEntry(VOID)
{
    if (g_hooks.pItems == NULL)
    {
        g_hooks.capacity = INITIAL_HOOK_CAPACITY;
        g_hooks.pItems = (PHOOK_ENTRY)ExAllocatePoolWithTag(
            NonPagedPoolNx,
            g_hooks.capacity * sizeof(HOOK_ENTRY),
            MHK_POOL_TAG
        );
        if (g_hooks.pItems == NULL)
            return NULL;
    }
    else if (g_hooks.size >= g_hooks.capacity)
    {
        PHOOK_ENTRY pNew;
        UINT newCapacity = g_hooks.capacity * 2;

        pNew = (PHOOK_ENTRY)ExAllocatePoolWithTag(
            NonPagedPoolNx,
            newCapacity * sizeof(HOOK_ENTRY),
            MHK_POOL_TAG
        );
        if (pNew == NULL)
            return NULL;

        RtlCopyMemory(pNew, g_hooks.pItems, g_hooks.size * sizeof(HOOK_ENTRY));
        ExFreePoolWithTag(g_hooks.pItems, MHK_POOL_TAG);

        g_hooks.capacity = newCapacity;
        g_hooks.pItems = pNew;
    }

    return &g_hooks.pItems[g_hooks.size++];
}

static VOID DeleteHookEntry(UINT pos)
{
    if (pos < g_hooks.size - 1)
        g_hooks.pItems[pos] = g_hooks.pItems[g_hooks.size - 1];

    g_hooks.size--;
}

/*-------------------------------------------------------------------------*/
/* Trampoline buffer allocation */
/*-------------------------------------------------------------------------*/
static PVOID AllocateTrampolineBuffer(VOID)
{
    return ExAllocatePoolWithTag(
        NonPagedPoolExecute,
        MEMORY_SLOT_SIZE,
        MHK_POOL_TAG
    );
}

static VOID FreeTrampolineBuffer(PVOID pBuffer)
{
    if (pBuffer != NULL)
        ExFreePoolWithTag(pBuffer, MHK_POOL_TAG);
}

/*-------------------------------------------------------------------------*/
/* Low-level hook enable/disable */
/*-------------------------------------------------------------------------*/
static MHK_STATUS EnableHookLL(UINT pos, BOOLEAN enable)
{
    PHOOK_ENTRY pHook = &g_hooks.pItems[pos];
    UINT8 patchBytes[INTERLOCKED_SIZE];
    NTSTATUS status;

    if (enable)
    {
        /* Build 14-byte JMP to detour */
        BuildAbsoluteJmp(patchBytes, (ULONG_PTR)pHook->pDetour);
        /* NOP padding - never executed, just for clarity */
        patchBytes[14] = 0x90;
        patchBytes[15] = 0x90;
    }
    else
    {
        /* Restore original 16 bytes */
        RtlCopyMemory(patchBytes, pHook->backup, INTERLOCKED_SIZE);
    }

    status = ReplaceCode16Bytes(pHook->pTarget, patchBytes);
    if (!NT_SUCCESS(status))
        return MHK_ERROR_MEMORY_PROTECT;

    pHook->isEnabled = enable;
    return MHK_OK;
}

/*-------------------------------------------------------------------------*/
/* Public API implementation */
/*-------------------------------------------------------------------------*/
MHK_STATUS MHK_Initialize(VOID)
{
    MHK_STATUS status = MHK_OK;

    EnterSpinLock();

    if (!g_isInitialized)
    {
        g_hooks.pItems = NULL;
        g_hooks.capacity = 0;
        g_hooks.size = 0;
        g_isInitialized = TRUE;
    }
    else
    {
        status = MHK_ERROR_ALREADY_INITIALIZED;
    }

    LeaveSpinLock();

    return status;
}

MHK_STATUS MHK_Uninitialize(VOID)
{
    MHK_STATUS status = MHK_OK;
    UINT i;

    EnterSpinLock();

    if (g_isInitialized)
    {
        /* Disable all hooks first */
        for (i = 0; i < g_hooks.size; ++i)
        {
            if (g_hooks.pItems[i].isEnabled)
            {
                EnableHookLL(i, FALSE);
            }
        }

        /* Free all trampolines */
        for (i = 0; i < g_hooks.size; ++i)
        {
            FreeTrampolineBuffer(g_hooks.pItems[i].pTrampoline);
        }

        /* Free hook entries */
        if (g_hooks.pItems != NULL)
        {
            ExFreePoolWithTag(g_hooks.pItems, MHK_POOL_TAG);
            g_hooks.pItems = NULL;
        }

        g_hooks.capacity = 0;
        g_hooks.size = 0;
        g_isInitialized = FALSE;
    }
    else
    {
        status = MHK_ERROR_NOT_INITIALIZED;
    }

    LeaveSpinLock();

    return status;
}

MHK_STATUS MHK_CreateHook(PVOID pTarget, PVOID pDetour, PVOID* ppOriginal)
{
    MHK_STATUS status = MHK_OK;

    EnterSpinLock();

    if (!g_isInitialized)
    {
        status = MHK_ERROR_NOT_INITIALIZED;
        goto cleanup;
    }

    if (pTarget == NULL || pDetour == NULL)
    {
        status = MHK_ERROR_INVALID_PARAMETER;
        goto cleanup;
    }

    /* Check 16-byte alignment */
    if (((ULONG_PTR)pTarget & 0xF) != 0)
    {
        status = MHK_ERROR_UNSUPPORTED_FUNCTION;
        goto cleanup;
    }

    if (!IsExecutableAddress(pTarget) || !IsExecutableAddress(pDetour))
    {
        status = MHK_ERROR_NOT_EXECUTABLE;
        goto cleanup;
    }

    if (FindHookEntry(pTarget) != MAXUINT32)
    {
        status = MHK_ERROR_ALREADY_CREATED;
        goto cleanup;
    }

    {
        PVOID pBuffer = AllocateTrampolineBuffer();
        if (pBuffer != NULL)
        {
            TRAMPOLINE ct;

            ct.pTarget = pTarget;
            ct.pDetour = pDetour;
            ct.pTrampoline = pBuffer;

            if (CreateTrampolineFunction(&ct))
            {
                PHOOK_ENTRY pHook = AddHookEntry();
                if (pHook != NULL)
                {
                    pHook->pTarget = ct.pTarget;
                    pHook->pDetour = pDetour;
                    pHook->pTrampoline = ct.pTrampoline;
                    pHook->copiedSize = ct.copiedSize;
                    pHook->isEnabled = FALSE;

                    /* Backup original 16 bytes */
                    RtlCopyMemory(pHook->backup, pTarget, INTERLOCKED_SIZE);

                    if (ppOriginal != NULL)
                        *ppOriginal = pHook->pTrampoline;
                }
                else
                {
                    status = MHK_ERROR_MEMORY_ALLOC;
                }
            }
            else
            {
                status = MHK_ERROR_UNSUPPORTED_FUNCTION;
            }

            if (status != MHK_OK)
            {
                FreeTrampolineBuffer(pBuffer);
            }
        }
        else
        {
            status = MHK_ERROR_MEMORY_ALLOC;
        }
    }

cleanup:
    LeaveSpinLock();
    return status;
}

MHK_STATUS MHK_RemoveHook(PVOID pTarget)
{
    MHK_STATUS status = MHK_OK;

    EnterSpinLock();

    if (!g_isInitialized)
    {
        status = MHK_ERROR_NOT_INITIALIZED;
        goto cleanup;
    }

    {
        UINT pos = FindHookEntry(pTarget);
        if (pos != MAXUINT32)
        {
            if (g_hooks.pItems[pos].isEnabled)
            {
                status = EnableHookLL(pos, FALSE);
            }

            if (status == MHK_OK)
            {
                FreeTrampolineBuffer(g_hooks.pItems[pos].pTrampoline);
                DeleteHookEntry(pos);
            }
        }
        else
        {
            status = MHK_ERROR_NOT_CREATED;
        }
    }

cleanup:
    LeaveSpinLock();
    return status;
}

MHK_STATUS MHK_EnableHook(PVOID pTarget)
{
    MHK_STATUS status = MHK_OK;

    EnterSpinLock();

    if (!g_isInitialized)
    {
        status = MHK_ERROR_NOT_INITIALIZED;
        goto cleanup;
    }

    if (pTarget == MHK_ALL_HOOKS)
    {
        UINT i;
        for (i = 0; i < g_hooks.size; ++i)
        {
            if (!g_hooks.pItems[i].isEnabled)
            {
                status = EnableHookLL(i, TRUE);
                if (status != MHK_OK)
                    break;
            }
        }
    }
    else
    {
        UINT pos = FindHookEntry(pTarget);
        if (pos != MAXUINT32)
        {
            if (!g_hooks.pItems[pos].isEnabled)
            {
                status = EnableHookLL(pos, TRUE);
            }
            else
            {
                status = MHK_ERROR_ENABLED;
            }
        }
        else
        {
            status = MHK_ERROR_NOT_CREATED;
        }
    }

cleanup:
    LeaveSpinLock();
    return status;
}

MHK_STATUS MHK_DisableHook(PVOID pTarget)
{
    MHK_STATUS status = MHK_OK;

    EnterSpinLock();

    if (!g_isInitialized)
    {
        status = MHK_ERROR_NOT_INITIALIZED;
        goto cleanup;
    }

    if (pTarget == MHK_ALL_HOOKS)
    {
        UINT i;
        for (i = 0; i < g_hooks.size; ++i)
        {
            if (g_hooks.pItems[i].isEnabled)
            {
                status = EnableHookLL(i, FALSE);
                if (status != MHK_OK)
                    break;
            }
        }
    }
    else
    {
        UINT pos = FindHookEntry(pTarget);
        if (pos != MAXUINT32)
        {
            if (g_hooks.pItems[pos].isEnabled)
            {
                status = EnableHookLL(pos, FALSE);
            }
            else
            {
                status = MHK_ERROR_DISABLED;
            }
        }
        else
        {
            status = MHK_ERROR_NOT_CREATED;
        }
    }

cleanup:
    LeaveSpinLock();
    return status;
}

const char* MHK_StatusToString(MHK_STATUS status)
{
    switch (status)
    {
    case MHK_OK:                        return "MHK_OK";
    case MHK_ERROR_ALREADY_INITIALIZED: return "MHK_ERROR_ALREADY_INITIALIZED";
    case MHK_ERROR_NOT_INITIALIZED:     return "MHK_ERROR_NOT_INITIALIZED";
    case MHK_ERROR_ALREADY_CREATED:     return "MHK_ERROR_ALREADY_CREATED";
    case MHK_ERROR_NOT_CREATED:         return "MHK_ERROR_NOT_CREATED";
    case MHK_ERROR_ENABLED:             return "MHK_ERROR_ENABLED";
    case MHK_ERROR_DISABLED:            return "MHK_ERROR_DISABLED";
    case MHK_ERROR_NOT_EXECUTABLE:      return "MHK_ERROR_NOT_EXECUTABLE";
    case MHK_ERROR_UNSUPPORTED_FUNCTION: return "MHK_ERROR_UNSUPPORTED_FUNCTION";
    case MHK_ERROR_MEMORY_ALLOC:        return "MHK_ERROR_MEMORY_ALLOC";
    case MHK_ERROR_MEMORY_PROTECT:      return "MHK_ERROR_MEMORY_PROTECT";
    case MHK_ERROR_INVALID_PARAMETER:   return "MHK_ERROR_INVALID_PARAMETER";
    case MHK_UNKNOWN:
    default:                            return "MHK_UNKNOWN";
    }
}

#pragma warning(pop)
