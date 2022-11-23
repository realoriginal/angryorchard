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
 * Searches for a token matching the specified
 * SID and privilege count.
 *
!*/

D_SEC( C ) HANDLE TokenGetTokenWithSidAndPrivilegeCount( _In_ LPSTR SidString, _In_ ULONG PrivCount );
