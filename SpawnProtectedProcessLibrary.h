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
 * Spawns a protected process and forces it
 * to load a DLL before initializing using
 * application verifiers.
 *
!*/
D_SEC( C ) BOOL SpawnProtectedProcessLibrary( _In_ PVOID Image, _In_ SIZE_T Len, LPPROCESS_INFORMATION ProcIn );
