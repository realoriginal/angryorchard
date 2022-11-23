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

typedef struct __attribute__(( packed ))
{
	HANDLE	CsrssId;
	HANDLE	ThreadId;
	HANDLE	ProcessId;
} TABLE, *PTABLE;
