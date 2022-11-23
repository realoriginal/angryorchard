/*!
 *
 * Exploit
 *
 * GuidePoint Security LLC
 *
 * Threat and Attack Simulation
 *
!*/

#pragma once

/*!
 *
 * Purpose:
 *
 * Injects a target process with the payload. Returns
 * a thread id to the caller on success.
 *
!*/

D_SEC( C ) BOOL InjectProcess( _In_ DWORD Pid, _In_ PVOID Buffer, _In_ ULONG Length, _Out_ PHANDLE Thread );
