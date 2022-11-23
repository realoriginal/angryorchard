/*!
 *
 * Exploit
 *
 * GuidePoint Security LLC
 *
 * Threat and Attack Simulation
 *
!*/

#pragma once

typedef enum
{
	UserThreadShutdownInformation,
	UserThreadFlags,
	UserThreadTaskName,
	UserThreadWOWInformation,
	UserThreadHungStatus,
	UserThreadInitiateShutdown,
	UserThreadEndShutdown,
	UserThreadUseDesktop,
	UserThreadPolled,
	UserThreadKeyboardState,
	UserThreadCsrPort,
	UserThreadResyncKeyState,
	UserThreadUseActiveDesktop
} USERTHREADINFOCLASS ;

typedef enum
{
	HardErrorSetup,
	HardErrorCleanup,
	HardErrorAttach,
	HardErrorAttachUser,
	HardErrorDetach,
	HardErrorAttachNoQueue,
	HardErrorDetachNoQueue,
	HardErrorQuery,
	HardErrorInDefDesktop
} HARDERRORCONTROL ;

typedef struct
{
	HANDLE	pDeskRestore;
	HANDLE	pDeskNew;
} DESKTOPRESTOREDATA, *PDESKTOPRESTOREDATA ;

typedef struct
{
	HANDLE			Thread;
	DESKTOPRESTOREDATA	Restore;
} DESKTOPUSEDESKTOP, *PDESKTOPUSEDESKTOP ;

/*!
 *
 * Purpose:
 *
 * Executes NtUserHardErrorControl depending on the
 * operating system version.
 *
!*/

D_SEC( E ) NTSTATUS NtUserHardErrorControlCall( _In_ HARDERRORCONTROL Command, _In_ HANDLE Thread, _Out_ PDESKTOPRESTOREDATA DesktopRestore );

/*!
 *
 * Purpose:
 *
 * Executes NtUserSetInformationThread depending on the
 * operating system version.
 *
!*/

D_SEC( E ) NTSTATUS NtUserSetInformationThreadCall( _In_ HANDLE Thread, _In_ USERTHREADINFOCLASS ThreadInfoClass, PVOID ThreadInformation, ULONG ThreadInformationLength );
