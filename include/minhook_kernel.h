/*
 *  MinHook Kernel - Kernel Mode API Hooking Library for x64
 *  Based on MinHook by Tsuda Kageyu
 *
 *  Ported for Windows Kernel Driver use
 *  Uses 14-byte absolute JMP (FF 25) for maximum compatibility
 */

#pragma once

#include <ntddk.h>

#ifdef __cplusplus
extern "C" {
#endif

/* MinHook Kernel Error Codes */
typedef enum _MHK_STATUS
{
    MHK_OK = 0,
    MHK_ERROR_ALREADY_INITIALIZED,
    MHK_ERROR_NOT_INITIALIZED,
    MHK_ERROR_ALREADY_CREATED,
    MHK_ERROR_NOT_CREATED,
    MHK_ERROR_ENABLED,
    MHK_ERROR_DISABLED,
    MHK_ERROR_NOT_EXECUTABLE,
    MHK_ERROR_UNSUPPORTED_FUNCTION,
    MHK_ERROR_MEMORY_ALLOC,
    MHK_ERROR_MEMORY_PROTECT,
    MHK_ERROR_INVALID_PARAMETER,
    MHK_UNKNOWN = -1
} MHK_STATUS;

/* Special hook target value */
#define MHK_ALL_HOOKS ((PVOID)(ULONG_PTR)-1)

/*
 * Initialize the MinHook Kernel library.
 * Must be called before any other MHK functions.
 *
 * Returns: MHK_OK on success
 *          MHK_ERROR_ALREADY_INITIALIZED if already initialized
 *          MHK_ERROR_MEMORY_ALLOC on memory allocation failure
 */
MHK_STATUS MHK_Initialize(VOID);

/*
 * Uninitialize the MinHook Kernel library.
 * Disables and removes all hooks.
 *
 * Returns: MHK_OK on success
 *          MHK_ERROR_NOT_INITIALIZED if not initialized
 */
MHK_STATUS MHK_Uninitialize(VOID);

/*
 * Create a hook for the specified target function.
 *
 * pTarget:    Address of the target function to hook
 * pDetour:    Address of the detour function
 * ppOriginal: [out] Receives the trampoline address (call this to invoke original)
 *
 * Returns: MHK_OK on success
 *          MHK_ERROR_NOT_INITIALIZED if not initialized
 *          MHK_ERROR_INVALID_PARAMETER if parameters are invalid
 *          MHK_ERROR_NOT_EXECUTABLE if addresses are not executable
 *          MHK_ERROR_ALREADY_CREATED if hook already exists
 *          MHK_ERROR_MEMORY_ALLOC on memory allocation failure
 *          MHK_ERROR_UNSUPPORTED_FUNCTION if function cannot be hooked
 */
MHK_STATUS MHK_CreateHook(
    PVOID pTarget,
    PVOID pDetour,
    PVOID* ppOriginal
);

/*
 * Remove a hook for the specified target function.
 *
 * pTarget: Address of the target function
 *
 * Returns: MHK_OK on success
 *          MHK_ERROR_NOT_INITIALIZED if not initialized
 *          MHK_ERROR_NOT_CREATED if hook does not exist
 */
MHK_STATUS MHK_RemoveHook(PVOID pTarget);

/*
 * Enable a hook for the specified target function.
 * Uses InterlockedCompareExchange128 for atomic patching.
 *
 * pTarget: Address of the target function (or MHK_ALL_HOOKS)
 *
 * Returns: MHK_OK on success
 *          MHK_ERROR_NOT_INITIALIZED if not initialized
 *          MHK_ERROR_NOT_CREATED if hook does not exist
 *          MHK_ERROR_ENABLED if already enabled
 */
MHK_STATUS MHK_EnableHook(PVOID pTarget);

/*
 * Disable a hook for the specified target function.
 * Uses InterlockedCompareExchange128 for atomic patching.
 *
 * pTarget: Address of the target function (or MHK_ALL_HOOKS)
 *
 * Returns: MHK_OK on success
 *          MHK_ERROR_NOT_INITIALIZED if not initialized
 *          MHK_ERROR_NOT_CREATED if hook does not exist
 *          MHK_ERROR_DISABLED if already disabled
 */
MHK_STATUS MHK_DisableHook(PVOID pTarget);

/*
 * Get status string for debugging.
 *
 * status: Status code
 *
 * Returns: String representation of the status
 */
const char* MHK_StatusToString(MHK_STATUS status);

#ifdef __cplusplus
}
#endif
