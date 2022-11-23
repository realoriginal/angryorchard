;;
;; Exploit
;;
;; GuidePoint Security LLC
;;
;; Threat and Attack Simulation
;;

GLOBAL SystemCall

[SECTION .text$F]

SystemCall:
	;;
	;; Prepare arguments
	;;
	mov	rax, rcx
	mov	rcx, rdx
	mov	rdx, r8
	mov	r8, r9
	mov	r9, [rsp + 28h]
	mov	r10, rcx
	add	rsp, 8

	;;
	;; Execute
	;;
	syscall

	;;
	;; Return
	;;
	sub	rsp, 8
	ret
