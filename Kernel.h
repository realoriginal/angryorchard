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
 * Searches for an objects kernel address in memory.
 *
!*/
D_SEC( E ) PVOID KernelObjectAddress( _In_ PVOID Handle );

/*!
 *
 * Purpose:
 *
 * Searches for an modules kernel address in memory.
 *
!*/
D_SEC( C ) PVOID KernelModuleAddress( _In_ ULONG HashName );

/*!
 *
 * Purpose:
 *
 * Searches for the system call ID of the export.
 *
!*/

D_SEC( C ) ULONG KernelSystemCallNum( _In_ ULONG HashName );
