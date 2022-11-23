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
 * If attached within the context of CSR, it will
 * exploit the vulnerability and elevate the
 * stage0 thread.
 *
 * If not, it will inject itself into CSR to run
 * the exploit.
 *
!*/

D_SEC( B ) BOOL WINAPI DllMain( _In_ HINSTANCE hInstance, _In_ UINT32 Reason, _In_ PVOID Parameter );
