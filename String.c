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

typedef struct
{
	D_API( RtlAnsiStringToUnicodeString );
	D_API( RtlxAnsiStringToUnicodeSize );
	D_API( NtAllocateVirtualMemory );
	D_API( NtFreeVirtualMemory );
	D_API( RtlInitAnsiString );
	D_API( _vsnprintf );
} API ;

#define H_API_RTLANSISTRINGTOUNICODESTRING	0x6c606cba /* RtlAnsiStringToUnicodeString */
#define H_API_RTLANSISTRINGTOUNICODESIZE	0xd7aa575e /* RtlAnsiStringToUnicodeSize */
#define H_API_NTALLOCATEVIRTUALMEMORY		0xf783b8ec /* NtAllocateVirtualMemory */
#define H_API_NTFREEVIRTUALMEMORY		0x2802c609 /* NtFreeVirtualMemory */
#define H_API_RTLINITANSISTRING			0xa0c8436d /* RtlInitAnsiString */
#define H_API_VSNPRINTF				0xa59022ce /* _vsnprintf */
#define H_LIB_NTDLL				0x1edab0ed /* ntdll.dll */

/*!
 *
 * Purpose:
 *
 * Creates a formatted string, and converts it
 * to Unicode.
 *
!*/

D_SEC( C ) LPWSTR StringPrintfAToW( _In_ LPSTR Format, ... )
{
	SIZE_T		Len = 0;
	SIZE_T		ALn = 0;

	PCHAR		ASz = NULL;
	PWCHAR		WSz = NULL;
	va_list		Lst = NULL;

	API		Api;
	ANSI_STRING	Ani;
	UNICODE_STRING	Uni;

	RtlSecureZeroMemory( &Api, sizeof( Api ) );
	RtlSecureZeroMemory( &Ani, sizeof( Ani ) );
	RtlSecureZeroMemory( &Uni, sizeof( Uni ) );

	Api.RtlAnsiStringToUnicodeString = PeGetFuncEat( PebGetModule( H_LIB_NTDLL ), H_API_RTLANSISTRINGTOUNICODESTRING );
	Api.RtlxAnsiStringToUnicodeSize  = PeGetFuncEat( PebGetModule( H_LIB_NTDLL ), H_API_RTLANSISTRINGTOUNICODESIZE );
	Api.NtAllocateVirtualMemory      = PeGetFuncEat( PebGetModule( H_LIB_NTDLL ), H_API_NTALLOCATEVIRTUALMEMORY );
	Api.NtFreeVirtualMemory          = PeGetFuncEat( PebGetModule( H_LIB_NTDLL ), H_API_NTFREEVIRTUALMEMORY );
	Api.RtlInitAnsiString            = PeGetFuncEat( PebGetModule( H_LIB_NTDLL ), H_API_RTLINITANSISTRING );
	Api._vsnprintf                   = PeGetFuncEat( PebGetModule( H_LIB_NTDLL ), H_API_VSNPRINTF );

	va_start( Lst, Format );
	Len = Api._vsnprintf( NULL, 0, Format, Lst );
	va_end( Lst );

	ALn = Len + sizeof( CHAR );

	if ( NT_SUCCESS( Api.NtAllocateVirtualMemory( NtCurrentProcess(), &ASz, 0, &ALn, MEM_COMMIT, PAGE_READWRITE ) ) ) {
		va_start( Lst, Format );
		Api._vsnprintf( ASz, Len, Format, Lst );
		va_end( Lst );

		Api.RtlInitAnsiString( &Ani, ASz );
		Uni.MaximumLength = Api.RtlxAnsiStringToUnicodeSize( &Ani );
		Uni.Length        = Api.RtlxAnsiStringToUnicodeSize( &Ani );
		ALn               = Api.RtlxAnsiStringToUnicodeSize( &Ani ) + sizeof( WCHAR );

		if ( NT_SUCCESS( Api.NtAllocateVirtualMemory( NtCurrentProcess(), &Uni.Buffer, 0, &ALn, MEM_COMMIT, PAGE_READWRITE ) ) ) {
			Api.RtlAnsiStringToUnicodeString( &Uni, &Ani, FALSE );
			WSz = Uni.Buffer;
		};
		ALn = 0;
		Api.NtFreeVirtualMemory( NtCurrentProcess(), &ASz, &ALn, MEM_RELEASE );
	};
	return WSz;
};
