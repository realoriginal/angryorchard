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
 * Locates an export in a PE.
 *
!*/
D_SEC( E ) PVOID PeGetFuncEat( _In_ PVOID Image, _In_ UINT32 Hash );
