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
 * Creates a hash of an input buffer. If a length
 * is not provided, it assumes it is a null 
 * terminated string.
 *
!*/

D_SEC( E ) UINT32 HashString( _In_ PVOID Buffer, _In_opt_ UINT32 Length )
{
	UINT8	Cur = 0;
	UINT32	Djb = 5381;
	PUINT8	Ptr = C_PTR( Buffer );

	while ( TRUE ) {
		Cur = * Ptr;

		if ( ! Length ) {
			if ( ! * Ptr ) {
				break;
			};
		} else {
			if ( ( UINT32 )( Ptr - ( PUINT8 ) Buffer ) >= Length ) {
				break;
			};
			if ( ! * Ptr ) {
				++Ptr; continue;
			};
		};
		if ( Cur >= 'a' ) {
			Cur -= 0x20;
		};
		Djb = ( ( Djb << 5 ) + Djb ) + Cur; ++Ptr;
	};
	return Djb;
};
