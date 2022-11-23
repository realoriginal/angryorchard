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

/* Gets a pointer to the function or variable via its relative offset to GetIp() */
#define G_PTR( x )	( ULONG_PTR )( GetIp( ) - ( ( ULONG_PTR ) & GetIp - ( ULONG_PTR ) x ) )

/* Cast to store code in a specific section or piece of memory */
#define D_SEC( x )	__attribute__(( section( ".text$" #x ) ))

/* Locates the end of the code */
#define G_END( x )	U_PTR( GetIp( ) + 11 )

/* Casts code as a pointer with a specific typedef */
#define D_API( x )	__typeof__( x ) * x

/* Cast as a pointer-wide integer */
#define U_PTR( x )	( ( ULONG_PTR ) x )

/* Cast as a pointer */
#define C_PTR( x )	( ( PVOID )x )
