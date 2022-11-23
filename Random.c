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

ULONG
NTAPI
RtlRandomEx(
	_In_ PULONG Seed
);

typedef struct
{
	D_API( NtGetTickCount );
	D_API( RtlRandomEx );
} API ;

#define H_API_NTGETTICKCOUNT	0x6f0ecc3b /* NtGetTickCount */
#define H_API_RTLRANDOMEX	0x7f1224f5 /* RtlRandomEx */
#define H_LIB_NTDLL		0x1edab0ed /* ntdll.dll */

/*!
 *
 * Purpose:
 *
 * Creates a random unicode string of the requested length.
 *
!*/

D_SEC( C ) VOID RandomStringW( PWCHAR Buffer, ULONG Length )
{
	API	Api;

	INT	Idx   = 0;
	ULONG	Val   = 0;
	ULONG	Sed   = 0;
	PWCHAR	Str   = C_PTR( G_PTR( Array ) );
 
	RtlSecureZeroMemory( &Api, sizeof( Api ) );
	Api.NtGetTickCount = PeGetFuncEat( PebGetModule( H_LIB_NTDLL ), H_API_NTGETTICKCOUNT );
	Api.RtlRandomEx    = PeGetFuncEat( PebGetModule( H_LIB_NTDLL ), H_API_RTLRANDOMEX );

	for ( Idx = 0 ; Idx < Length ; ++Idx ) {
		Sed = Api.NtGetTickCount();
		Val = Api.RtlRandomEx( &Sed ); 
		Val = Api.RtlRandomEx( &Val );
		Val = Val % 26;
		Buffer[ Idx ] = Str[ Val ];
	};
};
