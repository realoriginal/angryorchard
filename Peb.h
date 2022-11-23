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
 * Searches for a PE loaded in memory.
 *
!*/

D_SEC( E ) PVOID PebGetModule( _In_ UINT32 Hash );
