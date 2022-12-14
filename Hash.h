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
 * Creates a hash of an input buffer. If a length
 * is not provided, it assumes it is a null 
 * terminated string.
 *
!*/

D_SEC( E ) UINT32 HashString( _In_ PVOID Buffer, _In_opt_ UINT32 Length );
