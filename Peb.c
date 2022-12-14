/*!
 *
 * Exploit
 *
 * GuidePoint Security LLC
 *
 * Threat and Attack Simulation
 *
!*/

#include "Common.h"

/*!
 *
 * Purpose:
 *
 * Searches for a PE loaded in memory.
 *
!*/

D_SEC( E ) PVOID PebGetModule( _In_ UINT32 Hash )
{
	PPEB			Peb = NULL;
	PLIST_ENTRY		Hdr = NULL;
	PLIST_ENTRY		Ent = NULL;
	PLDR_DATA_TABLE_ENTRY	Ldr = NULL;

	Peb = NtCurrentPeb();
	Hdr = & Peb->Ldr->InLoadOrderModuleList;
	Ent = Hdr->Flink;

	for ( ; Ent != Hdr ; Ent = Ent->Flink ) {
		Ldr = C_PTR( Ent );

		if ( HashString( Ldr->BaseDllName.Buffer, Ldr->BaseDllName.Length ) == Hash ) {
			return Ldr->DllBase;
		};
	};
	return NULL;
};
