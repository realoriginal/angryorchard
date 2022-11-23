;##############################################################################
; Author : Seyhmus AKASLAN
; Contact: nalsakas@gmail.com
;
; NASM PE Macros
; Used for direct output to executables using only nasm.  
; Copyright (C) 2015  Seyhmus AKASLAN

; This program is free software; you can redistribute it and/or
; modify it under the terms of the GNU General Public License
; as published by the Free Software Foundation; either version 2
; of the License, or (at your option) any later version.

; This program is distributed in the hope that it will be useful,
; but WITHOUT ANY WARRANTY; without even the implied warranty of
; MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
; GNU General Public License for more details.
; 
; You should have received a copy of the GNU General Public License
; along with this program; if not, write to the Free Software
; Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston,
; MA  02110-1301, USA.
;##############################################################################

;##############################################################################
; Utility Functions and Global Definitions
;##############################################################################
; Section Alignment is above or equal to the File Alignment
%define SALIGN 1000h

; File Alignment, Can't be smaller than 200h
%define FALIGN 200h 

; Image Base
%define PE32_IMAGEBASE 400000h
%define DLL32_IMAGEBASE 10000000h
%define PE64_IMAGEBASE 400000h
%define DLL64_IMAGEBASE 10000000h

; Section Name
; max 8 chars
%define SECTIONNAME '.text'

; Subsystem
; NATIVE = 1, GUI = 2, CONSOLE = 3
%define SUBSYSTEM 2

; Stack and Heap Sizes
%define PE32_SizeOfStackReserve 0
%define PE32_SizeOfStackCommit 0
%define PE32_SizeOfHeapReserve 0
%define PE32_SizeOfHeapCommit 0

%define DLL32_SizeOfStackReserve 0
%define DLL32_SizeOfStackCommit 0
%define DLL32_SizeOfHeapReserve 0
%define DLL32_SizeOfHeapCommit 0

%define PE64_SizeOfStackReserve 0
%define PE64_SizeOfStackCommit 0
%define PE64_SizeOfHeapReserve 0
%define PE64_SizeOfHeapCommit 0

%define DLL64_SizeOfStackReserve 0
%define DLL64_SizeOfStackCommit 0
%define DLL64_SizeOfHeapReserve 0 
%define DLL64_SizeOfHeapCommit 0 
;##############################################################################
; DEBUG Macros
; 
; Used internally for testing purposes
; To test variable value inside pe.inc use bug() function to output its value
;##############################################################################
%macro DEBUG 0
	%define %$DEBUG 1
%endmacro

%macro dbgmsg 1+
	%ifdef %$DEBUG
		%warning %1
	%endif
%endmacro

; Debug Messages
%define bug(x) dbgmsg x

;##############################################################################
; PE MACROS
;
; Sample Usage:
; PE32 or DLL32 or PE64 or DLL64
;
; Data definitions
; label: db 'xxx'
;
; START
;   instructions
;   etc.
;
; Data Directories Definitions
; IMPORT / ENDIMPORT
; EXPORT / ENDEXPORT
; RESOURCE / ENDRESOURCE
; END
;
;##############################################################################
%macro PE32 0-2 NOFLAT, 1000h
	BITS 32
	%push pe32	
	
	%ifidn %1, FLAT
		org PE32_IMAGEBASE
		%define FLATMEMORY
		%define SALIGN %2
		%define FALIGN %2
		%define VA(x) x
		%define RVA(x) x - PE32_IMAGEBASE
		%define FA(x) x - PE32_IMAGEBASE 
	%endif

	IMAGE_DOS_HEADER
	IMAGE_NT_SIGNATURE
	IMAGE_FILE_HEADER
	IMAGE_OPTIONAL_HEADER
	IMAGE_DATA_DIRECTORY
	IMAGE_SECTION_HEADER
%endmacro

%macro DLL32 0-2 NOFLAT, 1000h
	BITS 32
	%push dll32

	%ifidn %1, FLAT
		org DLL32_IMAGEBASE
		%define FLATMEMORY
		%define SALIGN %2
		%define FALIGN %2
		%define VA(x) x
		%define RVA(x) x - DLL32_IMAGEBASE
		%define FA(x) x - DLL32_IMAGEBASE 
	%endif
	
	IMAGE_DOS_HEADER
	IMAGE_NT_SIGNATURE
	IMAGE_FILE_HEADER
	IMAGE_OPTIONAL_HEADER
	IMAGE_DATA_DIRECTORY
	IMAGE_SECTION_HEADER
%endmacro

%macro PE64 0-2 NOFLAT, 1000h
	BITS 64
	%push pe64
	
	%ifidn %1, FLAT
		org PE64_IMAGEBASE
		%define FLATMEMORY
		%define SALIGN %2
		%define FALIGN %2
		%define VA(x) x
		%define RVA(x) x - PE64_IMAGEBASE
		%define FA(x) x - PE64_IMAGEBASE 
	%endif	
	
	IMAGE_DOS_HEADER
	IMAGE_NT_SIGNATURE
	IMAGE_FILE_HEADER
	IMAGE_OPTIONAL_HEADER
	IMAGE_DATA_DIRECTORY
	IMAGE_SECTION_HEADER	
%endmacro

%macro DLL64 0-2 NOFLAT, 1000h
	BITS 64
	%push dll64

	%ifidn %1, FLAT
		org DLL64_IMAGEBASE
		%define FLATMEMORY
		%define SALIGN %2
		%define FALIGN %2
		%define VA(x) x
		%define RVA(x) x - DLL64_IMAGEBASE
		%define FA(x) x - DLL64_IMAGEBASE 
	%endif

	IMAGE_DOS_HEADER
	IMAGE_NT_SIGNATURE
	IMAGE_FILE_HEADER
	IMAGE_OPTIONAL_HEADER
	IMAGE_DATA_DIRECTORY
	IMAGE_SECTION_HEADER
%endmacro

%macro START 0
	%$ENTRY_POINT:
%endmacro

%macro END 0
	%ifndef %$IMPORT
		%$IMAGE_IMPORT_DESCRIPTOR_START:
		%$IMAGE_IMPORT_DESCRIPTOR_END:
	%endif

	%ifndef %$EXPORT
		%$IMAGE_EXPORT_DIRECTORY_START:
		%$IMAGE_EXPORT_DIRECTORY_END:
	%endif
	
	%ifndef %$RESOURCE
		%$IMAGE_RESOURCE_DIRECTORY_START:
		%$IMAGE_RESOURCE_DIRECTORY_END:
	%endif
	
	;ALIGN
	BINALIGN FALIGN, %$SECTION_START_1
	
	%$SECTION_END_1:
	%$IMAGE_END:
	
	; pops pe32, dll32, etc.
	%pop
%endmacro

; Round Functions
; There are two possible solutions
;%define ROUNDVS(x,y) ((x - y) / FALIGN) * SALIGN
%define ROUNDVS(x,y) ((x - y)/SALIGN)*SALIGN + (x - y) % SALIGN + ((SALIGN - (x - y) % SALIGN) % SALIGN ) 
 
; FA (File Address) function
%define FA(x) x

; VA (Virtual Address) function
%define VA(x)	x - %$SECTION_START_1 + ROUNDVS(%$IMAGE_SECTION_HEADER_END, %$IMAGE_DOS_HEADER) + IMAGEBASE

; RVA (Relative Virtual Address) function
%define RVA(x) VA(x) - IMAGEBASE 

; SIZEOF()
%define SIZEOF(x) x%+_end  - x 

; ALIGNMENT
; Fills gaps with 0s
; %1 = Size of alignment
; %2 = Align realtive to label
%macro BINALIGN 2
	times (((%1) - (($ - (%2)) % (%1))) % (%1)) db 0
%endmacro

;##############################################################################
; IMPORT TABLE Macros
; IMPORT/ENDIMPORT
; USAGE
; IMPORT
;   LIB user32.dll
;     FUNC FunctionName
;   ENDLIB
;
;   LIB kernel32.dll
;     FUNC FunctionName
;   ENDLIB
; ENDIMPORT
;##############################################################################
%macro IMPORT 0	
	%assign %$IMPORT 1
	%assign %$LIBRARY_COUNT 0
%endmacro

%macro LIB 1
	; Count number of LIBs
	%assign %$LIBRARY_COUNT %$LIBRARY_COUNT + 1
	
	; Get name of LIB
	%define %$LIBRARY_NAME_%[%$LIBRARY_COUNT] %1
	
	; Reset function count of LIB 
	%assign %$FUNCTION_COUNT 0
%endmacro

%macro ENDLIB 0
	%xdefine %$FUNCTION_COUNT_%[%$LIBRARY_COUNT] %$FUNCTION_COUNT
%endmacro

%macro FUNC 1
	%ifdef %$IMPORT
		%if %$IMPORT == 1
			; Count number of functions for each lib	
			%assign %$FUNCTION_COUNT %$FUNCTION_COUNT + 1
			%define %$FUNCTION_NAME_%[%$LIBRARY_COUNT]%[%$FUNCTION_COUNT] %1
		%endif
	%endif
	
	%ifdef %$EXPORT
		%if %$EXPORT == 1 
			%assign %$EXPORT_COUNT %$EXPORT_COUNT + 1
			%define %$EXPORT_NAME_%[%$EXPORT_COUNT] %1
		%endif
	%endif
%endmacro

%macro ENDIMPORT 0
	; Prepare IMAGE_IMPORT_BY_NAMEs
	; For each imported library
	%if %$LIBRARY_COUNT > 0
		
		%assign %%i 0
		%rep %$LIBRARY_COUNT
			%assign %%i %%i + 1
			
			%if %$FUNCTION_COUNT_%[%%i] > 0
			
				%assign %%j 0
				%rep %$FUNCTION_COUNT_%[%%i]
					%assign %%j %%j + 1
					%defstr %%FSNAME_%[%%i]%[%%j] %$FUNCTION_NAME_%[%%i]%[%%j]
					
					%%FN_%[%%i]%[%%j]:
					dw 0
					db %%FSNAME_%[%%i]%[%%j], 0
				%endrep
			%endif
		%endrep
	%endif
	
	; Prepare Original First Thunk
	; For each imported library
	%if %$LIBRARY_COUNT > 0
		%assign %%i 0
		%rep %$LIBRARY_COUNT
			%assign %%i %%i + 1
			
			%%OFTHUNK_%[%%i]:
			
			%if %$FUNCTION_COUNT_%[%%i] > 0
				%assign %%j 0
				%rep %$FUNCTION_COUNT_%[%%i]
					%assign %%j %%j + 1
					
					%ifctx pe32
						dd RVA(%%FN_%[%%i]%[%%j])
					%elifctx dll32
						dd RVA(%%FN_%[%%i]%[%%j])
					%elifctx pe64
						dq RVA(%%FN_%[%%i]%[%%j])
					%elifctx dll64
						dq RVA(%%FN_%[%%i]%[%%j])
					%endif
					
				%endrep
			%endif
			
			; Zero padding
			%ifctx pe32
				dd 0
			%elifctx dll32
				dd 0
			%elifctx pe64
				dq 0
			%elifctx dll64
				dq 0
			%endif
		%endrep
	%endif
	
	; First Thunk, IAT
	; For each imported library
	%if %$LIBRARY_COUNT > 0
			%assign %%i 0
			%rep %$LIBRARY_COUNT
				%assign %%i %%i + 1
				
				%%FTHUNK_%[%%i]:
				
				%if %$FUNCTION_COUNT_%[%%i] > 0
					
					%assign %%j 0
					%rep %$FUNCTION_COUNT_%[%%i]
						%assign %%j %%j + 1
						
						%$FUNCTION_NAME_%[%%i]%[%%j]:
						
						%ifctx pe32
							dd RVA(%%FN_%[%%i]%[%%j])
						%elifctx dll32
							dd RVA(%%FN_%[%%i]%[%%j])
						%elifctx pe64
							dq RVA(%%FN_%[%%i]%[%%j])
						%elifctx dll64
							dq RVA(%%FN_%[%%i]%[%%j])
						%endif						
						
					%endrep
				%endif
				
				; Zero padding
				%ifctx pe32
					dd 0
				%elifctx dll32
					dd 0
				%elifctx pe64
					dq 0
				%elifctx dll64
					dq 0
				%endif	
			%endrep
	%endif

	; LIBs names
	; For each imported library
	%if %$LIBRARY_COUNT > 0
		%assign %%i 0
		%rep %$LIBRARY_COUNT
			%assign %%i %%i + 1
			
			%defstr %%LIBNAME_%[%%i] %$LIBRARY_NAME_%[%%i] 
			
			%%LNAME_%[%%i]:
			db 	%%LIBNAME_%[%%i], 0
		%endrep
	%endif
	
	; Fill in IMAGE_IMPORT_DESCRIPTOR structure
	; For each imported library
	%$IMAGE_IMPORT_DESCRIPTOR_START:
	%if %$LIBRARY_COUNT > 0
		%assign %%i 0
		%rep %$LIBRARY_COUNT
			%assign %%i %%i + 1
			
			DWORD %%OriginalFirstThunk_%[%%i], RVA(%%OFTHUNK_%[%%i])
			DWORD %%TimeDateStamp_%[%%i]
			DWORD %%ForwarderChain_%[%%i]
			DWORD %%Name_%[%%i], RVA(%%LNAME_%[%%i])
			DWORD %%FirstThunk_%[%%i], RVA(%%FTHUNK_%[%%i])	
		%endrep
	%endif
	
	%assign %$IMPORT 0
	; zero termination
	times 5 dd 0
	%$IMAGE_IMPORT_DESCRIPTOR_END:
%endmacro

;##############################################################################
; EXPORT TABLE Macros
; EXPORT/ENDEXPORT
; USAGE
; EXPORT module_name
;   FUNC FunctionName
; ENDEXPORT
;##############################################################################
; %1 = Module name
%macro EXPORT 0-1 ''	
	%assign %$EXPORT 1
	
	; Reset exported function count
	%assign %$EXPORT_COUNT 0
	
	; Get module name from parameter
	%ifstr %1
		%define %$EXPORT_MODULE_NAME %1
	%else
		%defstr %$EXPORT_MODULE_NAME %1
	%endif
%endmacro

%macro ENDEXPORT 0
	; Export module name
	BYTE %%Module_Name, %$EXPORT_MODULE_NAME,0
	
	%%FUNCTIONS_ADDRESS:
	%if %$EXPORT_COUNT > 0
		%assign %%i 0
		
		%rep %$EXPORT_COUNT
			%assign %%i %%i + 1
			dd RVA(%[%$EXPORT_NAME_%[%%i]])
		%endrep
	%endif
	
	; Names of Exported Functions
	%if %$EXPORT_COUNT > 0
		%assign %%i 0
		%rep %$EXPORT_COUNT
			%assign %%i %%i + 1

			%defstr %%FNNAME_%[%%i] %$EXPORT_NAME_%[%%i]
			
			%%FN_%[%%i]:
			db %%FNNAME_%[%%i],0
		%endrep
	%endif
	
	; Names Array
	%%NAMES_ADDRESS:
	%if %$EXPORT_COUNT > 0
		%assign %%i 0
		%rep %$EXPORT_COUNT
			%assign %%i %%i + 1
			dd RVA(%%FN_%[%%i])
		%endrep
	%endif	
	
	; Ordinals Array
	%%ORDINALS_ADDRESS:
	%if %$EXPORT_COUNT > 0
		%assign %%i 0 
		%rep %$EXPORT_COUNT
			dw %%i
			%assign %%i %%i + 1
		%endrep
	%endif
	
	
	; Export Table
	%$IMAGE_EXPORT_DIRECTORY_START:
	
	DWORD %%Characteristics
	DWORD %%TimeDateStamp
	WORD %%MajorVersion
	WORD %%MinorVersion
	DWORD %%Name, RVA(%%Module_Name)
	DWORD %%Base
	DWORD %%NumberOfFunctions, %$EXPORT_COUNT 
	DWORD %%NumberOfNames, %$EXPORT_COUNT
	DWORD %%AddressOfFunctions, RVA(%%FUNCTIONS_ADDRESS)
	DWORD %%AddressOfNames, RVA(%%NAMES_ADDRESS)
	DWORD %%AddressOfNameOrdinals, RVA(%%ORDINALS_ADDRESS)	
	
	%assign %$EXPORT 0
	%$IMAGE_EXPORT_DIRECTORY_END:
%endmacro

;##############################################################################
; RESOURCE Macros
;
; RESOURCE/ENDRESOURCE
; ID/ENDID, TYPE/ENDTYPE, LANG/ENDLANG, LEAF, etc.

; USAGE:
; RESOURCE
;   TYPE type_id
;     ID resource_id
;       LANG lang_id, sublang_id
;         LEAF RVA(actual_resource_label), SIZEOF(actual_resource)
;       ENDLANG
;     ENDID
;  ENDTYPE
; ENDRESOURCE
;
; actual_resource:
; (MENU/DIALOG/STRINGTABLE, Raw, User Defined etc.)
;
; Actual resources may have special structures like string tables, menus
; and dialogs. They may also have no structure at all like a raw data or
; they may have user defined structures.
;##############################################################################
%macro RESOURCE 0	
	%assign %$RESOURCE 1
	%assign %$RESOURCE_TYPECOUNT 0
	%assign %$RESOURCE_IDCOUNT 0
	%assign %$RESOURCE_LANGCOUNT 0
%endmacro

%macro ENDRESOURCE 0
	%$IMAGE_RESOURCE_DIRECTORY_START:
	
	; TYPE Directory
	DWORD %%Characteristics
	DWORD %%TimeDateStamp
	WORD %%MajorVersion
	WORD %%MinorVersion
	WORD %%NumberOfNamedEntries
	WORD %%NumberOfIdEntries, %$RESOURCE_TYPECOUNT
	
	; TYPE Entries
	%assign %%i 0
	%rep %$RESOURCE_TYPECOUNT
		%assign %%i %%i + 1
		DWORD %%Name%[%%i], %$RESOURCE_TYPEID_%[%%i]
		DWORD %%OffsetToData%[%%i], (1<<31)|(%%ID_DIRECTORY%[%%i] - %$IMAGE_RESOURCE_DIRECTORY_START)
	%endrep
	
	; ID Directories   
	%assign %%i 0
	%rep %$RESOURCE_TYPECOUNT
		%assign %%i %%i + 1
		
		%%ID_DIRECTORY%[%%i]:
		DWORD %%Characteristics%[%%i]
		DWORD %%TimeDateStamp%[%%i]
		WORD %%MajorVersion%[%%i]
		WORD %%MinorVersion%[%%i]
		WORD %%NumberOfNamedEntries%[%%i]
		WORD %%NumberOfIdEntries%[%%i], %$RESOURCE_IDCOUNT_OF_%[%%i]
	
		;ID Entries
		%assign %%j 0
		%rep %$RESOURCE_IDCOUNT_OF_%[%%i]
			%assign %%j %%j + 1
			DWORD %%Name%[%%i]%[%%j], %$RESOURCE_ID_%[%%i]%[%%j]
			DWORD %%OffsetToData%[%%i]%[%%j], (1<<31)|(%%LANG_DIRECTORY%[%%i]%[%%j] - %$IMAGE_RESOURCE_DIRECTORY_START)
		%endrep
		
		; LANG directories
		%assign %%j 0
		%rep %$RESOURCE_IDCOUNT_OF_%[%%i]
			%assign %%j %%j + 1

			%%LANG_DIRECTORY%[%%i]%[%%j]:
			DWORD %%Characteristics%[%%i]%[%%j]
			DWORD %%TimeDateStamp%[%%i]%[%%j]
			WORD %%MajorVersion%[%%i]%[%%j]
			WORD %%MinorVersion%[%%i]%[%%j]
			WORD %%NumberOfNamedEntries%[%%i]%[%%j]
			WORD %%NumberOfIdEntries%[%%i]%[%%j], %$RESOURCE_LANGCOUNT_OF_%[%%i]%[%%j]
		
			;LANG Entries
			%assign %%k 0
			%rep %$RESOURCE_LANGCOUNT_OF_%[%%i]%[%%j]
				%assign %%k %%k + 1
				DWORD %%Name%[%%i]%[%%j]%[%%k], %$RESOURCE_LANGID_%[%%i]%[%%j]%[%%k]
				DWORD %%OffsetToData%[%%i]%[%%j]%[%%k], (%%LEAF_DIRECTORY_%[%%i]%[%%j]%[%%k] - %$IMAGE_RESOURCE_DIRECTORY_START)
			%endrep
			
			; Leaf Directories
			;LANG Entries
			%assign %%k 0
			%rep %$RESOURCE_LANGCOUNT_OF_%[%%i]%[%%j]
				%assign %%k %%k + 1
				
				%%LEAF_DIRECTORY_%[%%i]%[%%j]%[%%k]:
				
				DWORD %%DataOffset%[%%i]%[%%j]%[%%k], %$RESOURCE_LEAF_DATA_%[%%i]%[%%j]%[%%k]
				DWORD %%Size%[%%i]%[%%j]%[%%k], %$RESOURCE_LEAF_SIZE_%[%%i]%[%%j]%[%%k]
				DWORD %%CodePage%[%%i]%[%%j]%[%%k], %$RESOURCE_LEAF_CODEPAGE_%[%%i]%[%%j]%[%%k]
    			DWORD %%Reserved%[%%i]%[%%j]%[%%k]
			%endrep
		%endrep
	%endrep	
	
	%assign %$RESOURCE_TYPECOUNT 0
	%$IMAGE_RESOURCE_DIRECTORY_END:
%endmacro

%macro TYPE 1
	%ifnnum %1
		%error %1 is not a number. %?? macro expects number parameter.
	%endif
	%assign %$RESOURCE_TYPECOUNT %$RESOURCE_TYPECOUNT + 1
	%xdefine %$RESOURCE_TYPEID_%[%$RESOURCE_TYPECOUNT] %1
%endmacro

%macro ENDTYPE 0
	%xdefine %$RESOURCE_IDCOUNT_OF_%$RESOURCE_TYPECOUNT %$RESOURCE_IDCOUNT	
	%assign %$RESOURCE_IDCOUNT 0
%endmacro

%macro ID 1
	%ifnnum %1
		%error %1 is not a number. %?? macro expects number parameter.
	%endif
	%assign %$RESOURCE_IDCOUNT %$RESOURCE_IDCOUNT + 1
	%xdefine %$RESOURCE_ID_%[%$RESOURCE_TYPECOUNT]%[%$RESOURCE_IDCOUNT] %1
%endmacro

%macro ENDID 0
	%xdefine %$RESOURCE_LANGCOUNT_OF_%[%$RESOURCE_TYPECOUNT]%[%$RESOURCE_IDCOUNT] %$RESOURCE_LANGCOUNT
	%assign %$RESOURCE_LANGCOUNT 0
%endmacro

; %1 Primary Language id
; %2 Sublanguage id
%macro LANG 0-2 0,0
	%ifnnum %1
		%error %1 is not a number. %?? macro expects number parameter.
	%endif
	%assign %$RESOURCE_LANGCOUNT %$RESOURCE_LANGCOUNT + 1
	
	%assign %%language_id (%2 << 10) | %1
	%xdefine %$RESOURCE_LANGID_%[%$RESOURCE_TYPECOUNT]%[%$RESOURCE_IDCOUNT]%[%$RESOURCE_LANGCOUNT] %%language_id
%endmacro

%macro ENDLANG 0
%endmacro

%macro LEAF 1-3 0,0
	%define %$RESOURCE_LEAF_DATA_%[%$RESOURCE_TYPECOUNT]%[%$RESOURCE_IDCOUNT]%[%$RESOURCE_LANGCOUNT] %1
	%define %$RESOURCE_LEAF_SIZE_%[%$RESOURCE_TYPECOUNT]%[%$RESOURCE_IDCOUNT]%[%$RESOURCE_LANGCOUNT] %2
	%define %$RESOURCE_LEAF_CODEPAGE_%[%$RESOURCE_TYPECOUNT]%[%$RESOURCE_IDCOUNT]%[%$RESOURCE_LANGCOUNT] %3
%endmacro

;##############################################################################
; MENU Macros
; MENU name/ENDMENU
; POPUP/ENDPOPUP, MENUITEM, etc.
;
; USAGE:
; MENU name
;   MENUITEM 'name', id
;   POPUP 'name'
;     MENUITEM 'name', id
;   ENDPOPUP
;   MENUITEM 'name'
; ENDMENU
;;##############################################################################

; %1 = name
%macro MENU 1
	%ifctx dialog
		; menu macro inside dialog resources
		%define %$DIALOG_MENU %1
	%else
		; menu macro inside menu resources 
		;ALIGN DWORD
		BINALIGN 4, %$IMAGE_DOS_HEADER

		%1:
		; Menu Header structure
		WORD   %%wVersion
		WORD   %%cbHeaderSize

		%define %$MENU_NAME %1	
		%assign %$MENU_ITEM_NUMBER 0
	%endif
%endmacro

; %1 = name
; %2 = flags
%macro POPUP 1-2 0
	%assign %$MENU_ITEM_NUMBER %$MENU_ITEM_NUMBER + 1
	
	%ifnstr %1
		%error %?? String expected as first parameter
	%endif
	%xdefine %[%$MENU_NAME]_%[%$MENU_ITEM_NUMBER]_TYPE 1
	%xdefine %[%$MENU_NAME]_%[%$MENU_ITEM_NUMBER]_NAME %1
	%xdefine %[%$MENU_NAME]_%[%$MENU_ITEM_NUMBER]_FLAGS %2
	%xdefine %[%$MENU_NAME]_%[%$MENU_ITEM_NUMBER]_ID 0
	%xdefine %[%$MENU_NAME]_%[%$MENU_ITEM_NUMBER]_LAST 0
	%xdefine %[%$MENU_NAME]_%[%$MENU_ITEM_NUMBER]_POPUP 10h
	%xdefine %[%$MENU_NAME]_%[%$MENU_ITEM_NUMBER]_INPOPUP 0
%endmacro

%macro ENDPOPUP 0
	%xdefine %[%$MENU_NAME]_%[%$MENU_ITEM_NUMBER]_LAST 80h
	%xdefine %[%$MENU_NAME]_%[%$MENU_ITEM_NUMBER]_INPOPUP 1
%endmacro

; %1 = name
; %2 = menuID
; %3 = flags
%macro MENUITEM 2-3 0
	%assign %$MENU_ITEM_NUMBER  %$MENU_ITEM_NUMBER + 1
	
	%ifnstr %1
		%error %?? String expected as first parameter
	%endif
	%xdefine %[%$MENU_NAME]_%[%$MENU_ITEM_NUMBER]_TYPE 2
	%xdefine %[%$MENU_NAME]_%[%$MENU_ITEM_NUMBER]_ID %2
	%xdefine %[%$MENU_NAME]_%[%$MENU_ITEM_NUMBER]_NAME %1
	%xdefine %[%$MENU_NAME]_%[%$MENU_ITEM_NUMBER]_FLAGS %3
	%xdefine %[%$MENU_NAME]_%[%$MENU_ITEM_NUMBER]_POPUP 0
	%xdefine %[%$MENU_NAME]_%[%$MENU_ITEM_NUMBER]_LAST 0
	%xdefine %[%$MENU_NAME]_%[%$MENU_ITEM_NUMBER]_INPOPUP 0
%endmacro

%macro ENDMENU 0
	%xdefine %[%$MENU_NAME]_%[%$MENU_ITEM_NUMBER]_LAST 80h
	
	; Correct last popup menu problem
	%if %[%$MENU_NAME]_%[%$MENU_ITEM_NUMBER]_INPOPUP == 1
		%assign %%j %$MENU_ITEM_NUMBER
		%rep %$MENU_ITEM_NUMBER
			%assign %%j %%j - 1
			%if %[%$MENU_NAME]_%[%%j]_TYPE == 1
				%xdefine %[%$MENU_NAME]_%[%%j]_LAST 80h
				%exitrep
			%endif
		%endrep
	%endif
	
	%assign %%i 0
	%rep %$MENU_ITEM_NUMBER
		%assign %%i %%i + 1
		
		%if %[%$MENU_NAME]_%[%%i]_TYPE == 1
			WORD %%fItemFlags_%[%%i], %[%$MENU_NAME]_%[%%i]_FLAGS | %[%$MENU_NAME]_%[%%i]_LAST | %[%$MENU_NAME]_%[%%i]_POPUP
			WORD %%szItemText_%[%%i], __utf16__(%[%$MENU_NAME]_%[%%i]_NAME),0
		%else
			WORD %%fItemFlags_%[%%i], %[%$MENU_NAME]_%[%%i]_FLAGS | %[%$MENU_NAME]_%[%%i]_LAST | %[%$MENU_NAME]_%[%%i]_POPUP
			WORD %%wMenuID_%[%%i], %[%$MENU_NAME]_%[%%i]_ID
			WORD %%szItemText_%[%%i], __utf16__(%[%$MENU_NAME]_%[%%i]_NAME),0
		%endif
	%endrep
	
	; Clean up
	%assign %$MENU_ITEM_NUMBER 0
	%[%$MENU_NAME]_end:
%endmacro
;##############################################################################
; DIALOG Macros
; DIALOG name/ENDDIALOG
; CONTROL, STYLE, FONT, CAPTION, MENU etc.
;
; USAGE:
; DIALOG label, x, y, cx, cy
;   CAPTION 'caption'
;   STYLE bitflags
;   EXSTYLE bitflags
;   MENU MenuID
;   FONT pointsize,'family'
;   CONTROL 'caption', ClassID, ControlID, x, y, cx, cy, styles
;   ...
; ENDDIALOG
;;##############################################################################

; %1 = name/label
; %2 = x 
; %3 = y
; %4 = width
; %5 = height
%macro DIALOG 5
	;ALIGN DWORD
	BINALIGN 4, %$IMAGE_DOS_HEADER
	
	%push dialog

	; System Control Classes
	%define %$CSBUTTON		0x0080
	%define %$CSEDIT		0x0081
	%define %$CSSTATIC		0x0082
	%define %$CSLISTBOX		0x0083
	%define %$CSSCROLLBAR	0x0084
	%define %$CSCOMBOBOX	0x0085

	%define %$DIALOG_NAME %1
	%define %$DIALOG_X %2
	%define %$DIALOG_Y %3
	%define %$DIALOG_CX %4
	%define %$DIALOG_CY %5
	%define %$DIALOG_STYLE 0
	%define %$DIALOG_EXSTYLE 0
	%assign %$CONTROL_NUMBER 0
	%$DIALOG_NAME:
%endmacro

%macro CAPTION 1
	%ifctx dialog	
		%ifstr %1
			%define %$DIALOG_CAPTION %1
		%else
			%error Caption must be string.
		%endif
	%else
		%error Missing DIALOG statement.
	%endif	
%endmacro

%macro STYLE 1
	%ifctx dialog
		%assign %$DIALOG_STYLE %$DIALOG_STYLE | %1
	%else
		%error Missing DIALOG statement
	%endif	
%endmacro

%macro EXSTYLE 1
	%ifctx dialog
		%assign %$DIALOG_EXSTYLE %$DIALOG_EXSTYLE | %1
	%else
		%error Missing DIALOG statement
	%endif	
%endmacro

%macro CLASS 1
	%ifctx dialog
		%define %$DIALOG_CLASS %1
	%else
		%error Missing DIALOG statement
	%endif		
%endmacro

; 8, "MS Sans Serif"
%macro FONT 2 
	%ifctx dialog
		%define %$DIALOG_FONT
		%define %$DIALOG_FONT_SIZE %1
		%define %$DIALOG_FONT_FAMILY %2
	%else
		%error Missing DIALOG statement
	%endif		
%endmacro

; %1 = Name
; %2 = ID
; %3 = Class ID/Class Name
; %4 = x
; %5 = y
; %6 = cx
; %7 = cy
; %8 = style
; %9 = exstyle
%macro CONTROL 7-9 0,0
	%ifctx dialog
		%assign %$CONTROL_NUMBER %$CONTROL_NUMBER + 1

		%ifstr %1
			%xdefine %$DIALOG_CONTROL_%[%$CONTROL_NUMBER]_NAME %1	
		%else
			%error Control name must be a string.	
		%endif

		%xdefine %$DIALOG_CONTROL_%[%$CONTROL_NUMBER]_ID %2
		%xdefine %$DIALOG_CONTROL_%[%$CONTROL_NUMBER]_CLASS %3
		%xdefine %$DIALOG_CONTROL_%[%$CONTROL_NUMBER]_X %4
		%xdefine %$DIALOG_CONTROL_%[%$CONTROL_NUMBER]_Y %5
		%xdefine %$DIALOG_CONTROL_%[%$CONTROL_NUMBER]_CX %6
		%xdefine %$DIALOG_CONTROL_%[%$CONTROL_NUMBER]_CY %7
		%xdefine %$DIALOG_CONTROL_%[%$CONTROL_NUMBER]_STYLE %8 | WS_CHILD | WS_VISIBLE
		%xdefine %$DIALOG_CONTROL_%[%$CONTROL_NUMBER]_EXSTYLE %9
	%else
		%error Missing DIALOG statement
	%endif
%endmacro

%macro DEFPUSHBUTTON 6-8 0,0
	CONTROL %1, %2, %$CSBUTTON, %3, %4, %5, %6, %7 | BS_PUSHBUTTON | WS_TABSTOP, %8 
%endmacro

%macro PUSHBUTTON 6-8 0,0
	CONTROL %1, %2, %$CSBUTTON, %3, %4, %5, %6, %7 | BS_PUSHBUTTON | WS_TABSTOP, %8
%endmacro

%macro GROUPBOX 6-8 0,0
	CONTROL %1, %2, %$CSBUTTON, %3, %4, %5, %6, %7 | BS_GROUPBOX, %8
%endmacro

%macro RADIOBUTTON 6-8 0,0
	CONTROL %1, %2, %$CSBUTTON, %3, %4, %5, %6, %7 | BS_RADIOBUTTON | WS_TABSTOP, %8
%endmacro

%macro AUTOCHECKBOX 6-8 0,0
	CONTROL %1, %2, %$CSBUTTON, %3, %4, %5, %6, %7 | BS_AUTOCHECKBOX | WS_TABSTOP, %8
%endmacro

%macro AUTO3STATE 6-8 0,0
	CONTROL %1, %2, %$CSBUTTON, %3, %4, %5, %6, %7 | BS_AUTO3STATE | WS_TABSTOP, %8
%endmacro

%macro AUTORADIOBUTTON 6-8 0,0
	CONTROL %1, %2, %$CSBUTTON, %3, %4, %5, %6, %7 | BS_AUTORADIOBUTTON | WS_TABSTOP, %8
%endmacro

%macro PUSHBOX 6-8 0,0
	CONTROL %1, %2, %$CSBUTTON, %3, %4, %5, %6, %7 | BS_PUSHBOX | WS_TABSTOP, %8
%endmacro

%macro STATE3 6-8 0,0
	CONTROL %1, %2, %$CSBUTTON, %3, %4, %5, %6, %7 | BS_3STATE | WS_TABSTOP, %8
%endmacro

%macro COMBOBOX 5-7 0,0
	CONTROL "", %1, %$CSCOMBOBOX, %2, %3, %4, %5, %6 | CBS_SIMPLE | WS_TABSTOP, %7
%endmacro

%macro LTEXT 6-8 0,0
	CONTROL %1, %2, %$CSSTATIC, %3, %4, %5, %6, %7 | SS_LEFT | WS_GROUP, %8
%endmacro

%macro RTEXT 6-8 0,0
	CONTROL %1, %2, %$CSSTATIC, %3, %4, %5, %6, %7 | SS_RIGHT | WS_GROUP, %8
%endmacro

%macro CTEXT 6-8 0,0
	CONTROL %1, %2, %$CSSTATIC, %3, %4, %5, %6, %7 | SS_CENTER | WS_GROUP, %8
%endmacro

%macro CHECKBOX 6-8 0,0
	CONTROL %1, %2, %$CSBUTTON, %3, %4, %5, %6, %7 | BS_CHECKBOX | WS_TABSTOP, %8
%endmacro

%macro EDITTEXT 5-7 0,0
	CONTROL "", %1, %$CSEDIT, %2, %3, %4, %5, %6 | ES_LEFT | WS_BORDER | WS_TABSTOP, %7
%endmacro

%macro LISTBOX 5-7 0,0
	CONTROL "", %1, %$CSLISTBOX, %2, %3, %4, %5, %6 | ES_LEFT | WS_BORDER | WS_TABSTOP, %7
%endmacro

%macro SCROLLBAR 5-7 0,0
	CONTROL "", %1, %$CSSCROLLBAR, %2, %3, %4, %5, %6 | SBS_HORZ, %7
%endmacro

%macro  ENDDIALOG 0
	; DLGTEMPLATE and DLGITEMTEMPLATE structures
	%ifctx dialog	
		
		DWORD %%Style, %$DIALOG_STYLE | WS_POPUP | WS_BORDER | WS_SYSMENU | WS_VISIBLE | DS_SETFONT | WS_CAPTION | DS_NOFAILCREATE
		DWORD %%ExtendedStyle, %$DIALOG_EXSTYLE 
		WORD %%NumberOfItems, %$CONTROL_NUMBER
		WORD %%x, %$DIALOG_X
		WORD %%y, %$DIALOG_Y
		WORD %%cx, %$DIALOG_CX
		WORD %%cy, %$DIALOG_CY
		
		; Dialog Menu
		%ifdef %$DIALOG_MENU
			%ifstr %$DIALOG_MENU
				;WORD %%MenuName, __utf16__(%$DIALOG_MENU),0
				%error Only ID Menu Resources are supported.
			%elifnum %$DIALOG_MENU
				WORD %%MenuName, 0xFFFF,%$DIALOG_MENU
			%endif
		%else
			WORD %%MenuName
		%endif
		
		; Dialog Class
		%ifdef %$DIALOG_CLASS
			%ifstr %$DIALOG_CLASS
				WORD %%ClassName, __utf16__(%$DIALOG_CLASS),0
			%else
				WORD %%ClassName,0xFFFF, %$DIALOG_CLASS
			%endif
		%else
			WORD %%ClassName
		%endif
		
		; Dialog Title
		%ifdef %$DIALOG_CAPTION
			%ifstr %$DIALOG_CAPTION
				WORD %%szCaption, __utf16__(%$DIALOG_CAPTION),0
			;%elifnum %$DIALOG_CAPTION
			;	WORD %%szCaption, 0xFFFF, %$DIALOG_CAPTION
			%endif
		%else
			WORD %%szCaption
		%endif
	
		; Dialog Font
		%ifdef %$DIALOG_FONT
			WORD %%wPointSize, %$DIALOG_FONT_SIZE
			WORD %%szFontName, __utf16__(%$DIALOG_FONT_FAMILY),0
		%else
			WORD %%wPointSize, 8
			WORD %%szFontName, __utf16__("MS Sans Serif"),0
		%endif		
	
		; Dialog Controls
		%assign %%i 0
		%rep %$CONTROL_NUMBER			
			%assign %%i %%i + 1

			;ALIGN DWORD
			BINALIGN 4, %$DIALOG_NAME 
			
			DWORD %%STYLE_%[%%i], %$DIALOG_CONTROL_%[%%i]_STYLE 
			DWORD %%EXTENDEDSTYLE_%[%%i], %$DIALOG_CONTROL_%[%%i]_EXSTYLE
			WORD %%X_%[%%i], %$DIALOG_CONTROL_%[%%i]_X
			WORD %%Y_%[%%i], %$DIALOG_CONTROL_%[%%i]_Y
			WORD %%CX_%[%%i], %$DIALOG_CONTROL_%[%%i]_CX
			WORD %%CY_%[%%i], %$DIALOG_CONTROL_%[%%i]_CY
			WORD %%CONTROLID_%[%%i], %$DIALOG_CONTROL_%[%%i]_ID
			
			; Control Class
			%ifstr %$DIALOG_CONTROL_%[%%i]_CLASS				
				WORD %%CLASSID_%[%%i], __utf16__(%$DIALOG_CONTROL_%[%%i]_CLASS),0
			%elifnum %$DIALOG_CONTROL_%[%%i]_CLASS
				WORD %%CLASSID_%[%%i], 0xFFFF, %$DIALOG_CONTROL_%[%%i]_CLASS
			%else
				WORD %%CLASSID_%[%%i]
			%endif
			
			; Control Title
			%ifstr %$DIALOG_CONTROL_%[%%i]_NAME
				WORD %%TEXT_%[%%i], __utf16__(%$DIALOG_CONTROL_%[%%i]_NAME),0
			%elifnum %$DIALOG_CONTROL_%[%%i]_NAME
				WORD %%TEXT_%[%%i], 0xFFFF, %$DIALOG_CONTROL_%[%%i]_NAME
			%else
				WORD %%TEXT_%[%%i]
			%endif
			
			WORD %%CREATIONDATA_%[%%i]
		%endrep
	
		; End
		%[%$DIALOG_NAME]_end:
		%pop dialog
	%else
		%error Missing DIALOG statement
	%endif
%endmacro

;##############################################################################
; STRINGTABLE Macros
; STRINGTABLE / ENDSTRINGTABLE
; SID(String Table Resource ID, String Index in table)
;
; USAGE:
; LoadString (hInst, SID(ResourceID, 1)) --> First string in table 
;
; STRINGTABLE label
;   STRING 'this is a string'
;   ...
; ENDSTRINGTABLE
;;##############################################################################

; STRINGTABLE MACROS
%define SID(x, y) ((x - 1 ) << 4) + (y - 1)

%macro STRINGTABLE	1
	%push stringtable
	%assign %$COUNT 0
	%define %$NAME %1
	%$NAME:
%endmacro

%macro ENDSTRINGTABLE 0
	; Fill empty string slots
	%rep 16 - %$COUNT
		dw 0 ;padding
	%endrep

	%[%$NAME]_end:
	%pop stringtable
%endmacro

%macro STRING 1
	%assign %$COUNT %$COUNT + 1
	
	%if %$COUNT > 16
		%error "Too many strings. STRING count can't exceed 16."
	%endif
	
	%strlen %%strlen %1
	WORD %%len, %%strlen
	WORD %%str, __utf16__(%1)
%endmacro
;##############################################################################
; ACCELERATOR TABLE Macros
; ACCELERATOR / ENDACCELERATOR
;
; USAGE:
; LoadAccelerators (hInst, Resource ID)
; ACCELERATOR label
;   STRING 'this is a string'
;   ...
; ENDACCELERATOR
;;##############################################################################
%macro ACCELERATORTABLE 1
	%push accelerator
	%define %$NAME %1
	%assign %$COUNT 0
	%$NAME:
%endmacro

; %1 = ascii
; %2 = id
; %3 = flags | defaults to FSHIFT
%macro ACCELERATOR 2-3 0
	%assign %$COUNT %$COUNT + 1
	
	%xdefine %$ASCII_%[%$COUNT] %1
	%xdefine %$ID_%[%$COUNT] %2
	%xdefine %$FLAGS_%[%$COUNT] %3
%endmacro

%macro ENDACCELERATORTABLE 0
	; AccelTableEntries
	%assign %%i 0
	%rep %$COUNT
		%assign %%i %%i + 1
		
		; Flag last entry
		%if %%i == %$COUNT
			WORD %%flags_%[%%i], %$FLAGS_%[%%i] | 0x0080
		%else
			WORD %%flags_%[%%i], %$FLAGS_%[%%i]
		%endif
		
		WORD %%ascii_%[%%i], %$ASCII_%[%%i]
		WORD %%ID_%[%%i], %$ID_%[%%i]
		WORD %%padding_%[%%i]
	%endrep
	
	%[%$NAME]_end:
	%pop accelerator
%endmacro

;##############################################################################
; BITMAP Macros
; Includes bitmap file in binary form
;
; USAGE:
; BITMAP label, 'file.bmp'
;##############################################################################
; %1 = label
; %2 = Bitmap file in string form
%macro BITMAP 2
	;BINALIGN 4, %$IMAGE_DOS_HEADER
	%1:
	%ifnstr %2
		%error %2 parameter must be a string.
	%endif
	incbin %2, 14 ; skip bitmap file header
	%1_end: 
%endmacro

; %1 = label
; %2 = file name on file system
%macro FILE 2
	%1:
	%ifnstr %2
		%error %2 parameter must be a string.
	%endif

	incbin %2
	
	%1_end:
%endmacro
;##############################################################################
; PE HEADER Macros
; Converting C language structures into nasm is easy with below macros.
; DWORD var, WORD var, BYTE var
; DWORD var[], WORD var[], BYTE var[]
; 
; IMAGE_DOS_HEADER
; IMAGE_NT_SIGNATURE
; IMAGE_FILE_HEADER
; IMAGE_OPTIONAL_HEADER
; IMAGE_DATA_DIRECTORY
; IMAGE_SECTION_HEADER
;##############################################################################
%macro IMAGE_DOS_HEADER 0
	%$IMAGE_DOS_HEADER:
	WORD %%e_magic, 5A4Dh
	WORD %%e_cblp
	WORD %%e_cp
	WORD %%e_crlc
	WORD %%e_cparhdr
	WORD %%e_minalloc
	WORD %%e_maxalloc
	WORD %%e_ss
	WORD %%e_sp
	WORD %%e_csum
	WORD %%e_ip
	WORD %%e_cs
	WORD %%e_lfarcl
	WORD %%e_ovno
	WORD %%e_res[4]
	WORD %%e_oemid
	WORD %%e_oeminfo
	WORD %%e_res2[10]
	DWORD %%e_lfanew, FA(%$PE_SIGNATURE)
%endmacro

%macro IMAGE_NT_SIGNATURE 0
	%$IMAGE_NT_SIGNATURE:

	%assign %%IMAGE_DOS_SIGNATURE             0x5A4D      ;MZ
	%assign %%IMAGE_OS2_SIGNATURE             0x454E      ;NE
	%assign %%IMAGE_OS2_SIGNATURE_LE          0x454C      ;LE
	%assign %%IMAGE_NT_SIGNATURE              0x00004550  ;PE00
	%define %%SIGNATURE %%IMAGE_NT_SIGNATURE
	
	DWORD %$PE_SIGNATURE, %%SIGNATURE 
%endmacro

%macro IMAGE_FILE_HEADER 0
	%$IMAGE_FILE_HEADER:
	
	; Machine
	%assign %%IMAGE_FILE_MACHINE_I386 0x014c
	%assign %%IMAGE_FILE_MACHINE_IA64 0x0200
	%assign %%IMAGE_FILE_MACHINE_AMD64 0x8664
	
	%ifctx pe32
		%define %%Mac %%IMAGE_FILE_MACHINE_I386
	%elifctx dll32
		%define %%Mac %%IMAGE_FILE_MACHINE_I386
	%elifctx pe64
		%define %%Mac %%IMAGE_FILE_MACHINE_AMD64
	%elifctx dll64
		%define %%Mac %%IMAGE_FILE_MACHINE_AMD64
	%endif 
	
	; Characteristics
	%assign %%IMAGE_FILE_DLL 0x2000
	%assign %%IMAGE_FILE_32BIT_MACHINE 0x0100
	%assign %%IMAGE_FILE_EXECUTABLE_IMAGE 0x0002
	
	%ifctx pe32
		%define %%Character %%IMAGE_FILE_32BIT_MACHINE|%%IMAGE_FILE_EXECUTABLE_IMAGE
	%elifctx dll32
		%define %%Character %%IMAGE_FILE_32BIT_MACHINE|%%IMAGE_FILE_DLL|%%IMAGE_FILE_EXECUTABLE_IMAGE
	%elifctx pe64
		%define %%Character %%IMAGE_FILE_EXECUTABLE_IMAGE
	%elifctx dll64
		%define %%Character %%IMAGE_FILE_DLL|%%IMAGE_FILE_EXECUTABLE_IMAGE
	%endif
	
	; File Header
	WORD    %%Machine, %%Mac	
	WORD    %%NumberOfSections, 1
	DWORD   %%TimeDateStamp, __POSIX_TIME__
	DWORD   %%PointerToSymbolTable
	DWORD   %%NumberOfSymbols
	WORD    %%SizeOfOptionalHeader, %$IMAGE_SECTION_HEADER - %$IMAGE_OPTIONAL_HEADER
	WORD    %%Characteristics, %%Character
%endmacro

%macro IMAGE_OPTIONAL_HEADER 0
	%$IMAGE_OPTIONAL_HEADER:
	
	; Magic and IMAGEBASE
	%assign %%IMAGE_NT_OPTIONAL_HDR32_MAGIC 0x10b
	%assign %%IMAGE_NT_OPTIONAL_HDR64_MAGIC 0x20b
	
	%ifctx pe32
		%define %%Magik %%IMAGE_NT_OPTIONAL_HDR32_MAGIC
		%define IMAGEBASE PE32_IMAGEBASE
	%elifctx dll32
		%define %%Magik %%IMAGE_NT_OPTIONAL_HDR32_MAGIC
		%define IMAGEBASE DLL32_IMAGEBASE
	%elifctx pe64
		%define %%Magik %%IMAGE_NT_OPTIONAL_HDR64_MAGIC
		%define IMAGEBASE PE64_IMAGEBASE
	%elifctx dll64
		%define %%Magik %%IMAGE_NT_OPTIONAL_HDR64_MAGIC
		%define IMAGEBASE DLL64_IMAGEBASE
	%endif
	
	; Image Size
	%define %%IMAGE_SIZE  ROUNDVS(%$IMAGE_END, %$IMAGE_SECTION_HEADER_END) + ROUNDVS(%$IMAGE_SECTION_HEADER_END, %$IMAGE_DOS_HEADER)
	
	; Headers Size
	%define %%HEADERS_SIZE (%$IMAGE_SECTION_HEADER_END - %$IMAGE_DOS_HEADER)
	
	; Section Table
	WORD    %%Magic, %%Magik
	BYTE    %%MajorLinkerVersion
	BYTE    %%MinorLinkerVersion
	DWORD   %%SizeOfCode
	DWORD   %%SizeOfInitializedData
	DWORD   %%SizeOfUninitializedData
	DWORD   %%AddressOfEntryPoint, RVA(%$ENTRY_POINT)
	DWORD   %%BaseOfCode
	%ifctx pe32
		DWORD   %%BaseOfData1
		DWORD   %%ImageBase1, IMAGEBASE
	%elifctx dll32
		DWORD   %%BaseOfData1
		DWORD   %%ImageBase2, IMAGEBASE
	%elifctx pe64
		QWORD   %%ImageBase3, IMAGEBASE
	%elifctx dll64
		QWORD   %%ImageBase4, IMAGEBASE
	%endif
	DWORD   %%SectionAlignment, SALIGN
	DWORD   %%FileAlignment, FALIGN
	WORD    %%MajorOperatingSystemVersion, 4
	WORD    %%MinorOperatingSystemVersion, 0
	WORD    %%MajorImageVersion
	WORD    %%MinorImageVersion
	WORD    %%MajorSubsystemVersion, 4
	WORD    %%MinorSubsystemVersion, 0
	DWORD   %%Win32VersionValue
	DWORD   %%SizeOfImage, %%IMAGE_SIZE
	DWORD   %%SizeOfHeaders, %%HEADERS_SIZE
	DWORD   %%CheckSum
	WORD    %%Subsystem, SUBSYSTEM
	WORD    %%DllCharacteristics
	%ifctx pe32
		DWORD   %%SizeOfStackReserve1, PE32_SizeOfStackReserve
		DWORD   %%SizeOfStackCommit1, PE32_SizeOfStackCommit
		DWORD   %%SizeOfHeapReserve1, PE32_SizeOfHeapReserve
		DWORD   %%SizeOfHeapCommit1, PE32_SizeOfHeapCommit
	%elifctx dll32
		DWORD   %%SizeOfStackReserve2, DLL32_SizeOfStackReserve 
		DWORD   %%SizeOfStackCommit2, DLL32_SizeOfStackCommit
		DWORD   %%SizeOfHeapReserve2, DLL32_SizeOfHeapReserve
		DWORD   %%SizeOfHeapCommit2, DLL32_SizeOfHeapCommit
	%elifctx pe64
		QWORD   %%SizeOfStackReserve3, PE64_SizeOfStackReserve
		QWORD   %%SizeOfStackCommit3, PE64_SizeOfStackCommit
		QWORD   %%SizeOfHeapReserve3, PE64_SizeOfHeapReserve
		QWORD   %%SizeOfHeapCommit3, PE64_SizeOfHeapCommit
	%elifctx dll64
		QWORD   %%SizeOfStackReserve4, DLL64_SizeOfStackReserve
		QWORD   %%SizeOfStackCommit4, DLL64_SizeOfStackCommit
		QWORD   %%SizeOfHeapReserve4, DLL64_SizeOfHeapReserve
		QWORD   %%SizeOfHeapCommit4, DLL64_SizeOfHeapCommit		
	%endif	
	DWORD   %%LoaderFlags
	DWORD   %%NumberOfRvaAndSizes,10h
%endmacro

%macro IMAGE_DATA_DIRECTORY 0
	%$IMAGE_DATA_DIRECTORY:
	
	; Import Table
	%define %%ImportTable_VA RVA(%$IMAGE_IMPORT_DESCRIPTOR_START)
	%define %%ImportTable_SZ %$IMAGE_IMPORT_DESCRIPTOR_END - %$IMAGE_IMPORT_DESCRIPTOR_START
	
	; Export Table
	%define %%ExportTable_VA RVA(%$IMAGE_EXPORT_DIRECTORY_START)
	%define %%ExportTable_SZ %$IMAGE_EXPORT_DIRECTORY_END - %$IMAGE_EXPORT_DIRECTORY_START
	
	; Resource Table
	%define %%ResourceTable_VA RVA(%$IMAGE_RESOURCE_DIRECTORY_START)
	%define %%ResourceTable_SZ %$IMAGE_RESOURCE_DIRECTORY_END - %$IMAGE_RESOURCE_DIRECTORY_START
	
	DWORD   %%ExportTableVirtualAddress, %%ExportTable_VA
	DWORD   %%ExportTableSize, %%ExportTable_SZ
	
	DWORD   %%ImportTableVirtualAddress, %%ImportTable_VA
	DWORD   %%ImportTableSize, %%ImportTable_SZ
	
	DWORD   %%ResourceTableVirtualAddress, %%ResourceTable_VA
	DWORD   %%ResourceTableSize, %%ResourceTable_SZ
	
	DWORD   %%ExceptionTableVirtualAddress
	DWORD   %%ExceptionTableSize
	
	DWORD   %%CertificateTableVirtualAddress
	DWORD   %%CertificateTableSize
	
	DWORD   %%BaseRelocationTableVirtualAddress
	DWORD   %%BaseRelocationTableSize
	
	DWORD   %%DebuggingInformationVirtualAddress
	DWORD   %%DebuggingInformationSize
	
	DWORD   %%ArchitectureSpecificDataVirtualAddress
	DWORD   %%ArchitectureSpecificDataSize
	
	DWORD   %%GlobalPointerRegisterVirtualAddress
	DWORD   %%GlobalPointerRegisterSize
	
	DWORD   %%ThreadLocalStorageTLSVirtualAddress
	DWORD   %%ThreadLocalStorageTLSSize
	
	DWORD   %%LoadConfigurationTableVirtualAddress
	DWORD   %%LoadConfigurationTableSize
	
	DWORD   %%BoundImportTableVirtualAddress
	DWORD   %%BoundImportTableSize
	
	DWORD   %%ImportAddressTableVirtualAddress
	DWORD   %%ImportAddressTableSize
	
	DWORD   %%DelayImportDescriptorVirtualAddress
	DWORD   %%DelayImportDescriptorSize
	
	DWORD   %%TheCLRHeaderVirtualAddress
	DWORD   %%TheCLRHeaderSize
	
	DWORD   %%ReservedVirtualAddress
	DWORD   %%ReservedSize
%endmacro

%macro IMAGE_SECTION_HEADER 0
	%$IMAGE_SECTION_HEADER:
	
	; Virtual Address
	%define %$SECTION_VA_1 ROUNDVS(%$IMAGE_SECTION_HEADER_END, %$IMAGE_DOS_HEADER)
	
	; Virtual Size
	%define %$SECTION_VS_1 ROUNDVS(%$SECTION_END_1, %$SECTION_START_1)
	
	; File Address
	%define %$SECTION_FA_1 FA(%$SECTION_START_1)

	; File Size
	%define %$SECTION_FS_1 (%$SECTION_END_1 - %$SECTION_START_1)

	;Characteristics
	%define IMAGE_SCN_CNT_CODE 0x00000020
	%define IMAGE_SCN_CNT_INITIALIZED_DATA 0x00000040
	%define IMAGE_SCN_CNT_UNINITIALIZED_DATA 0x00000080
	%assign %%IMAGE_SCN_MEM_EXECUTE 0x20000000
	%assign %%IMAGE_SCN_MEM_READ 0x40000000
	%assign %%IMAGE_SCN_MEM_WRITE 0x80000000
	%assign %%IMAGE_SCN_MEM_SHARED 0x10000000		
	%define %$SECTION_CHARACTERISTICS_1 %%IMAGE_SCN_MEM_EXECUTE|%%IMAGE_SCN_MEM_READ|%%IMAGE_SCN_MEM_WRITE

	;Section Name
	%define %%str SECTIONNAME
	%ifstr %%str
		%strlen %%len %%str
		
		%if %%len == 8
			; keep %%str as it is
		%elif %%len < 8
			%rep (8 - %%len)
				%strcat %%str %%str, `\0`
			%endrep
		%elif %%len > 8
			%substr %%str %%str 1, 8
		%endif
		
		%define %%SECTION_NAME_1  %%str
	%else
		%error "String expected " %%str
	%endif
	
	; Section Table
	BYTE    %%Name, %%SECTION_NAME_1
	DWORD   %%VirtualSize, %$SECTION_VS_1 
	DWORD   %%VirtualAddress, %$SECTION_VA_1
	DWORD   %%SizeOfRawData, %$SECTION_FS_1 
	DWORD   %%PointerToRawData, %$SECTION_FA_1
	DWORD   %%PointerToRelocations
	DWORD   %%PointerToLinenumbers
	WORD    %%NumberOfRelocations
	WORD    %%NumberOfLinenumbers
	DWORD   %%Characteristics, %$SECTION_CHARACTERISTICS_1

	;ALIGN
	BINALIGN FALIGN, %$IMAGE_DOS_HEADER
	
	%$IMAGE_SECTION_HEADER_END:
	%$SECTION_START_1:
%endmacro

;##############################################################################
; General Purpose type Macros
;
; DWORD var, WORD var, BYTE var
; DWORD var[], WORD var[], BYTE var[]
;##############################################################################
%macro DWORD 1-2+ 0h
	%defstr %%label %1
	%strlen %%len %%label

	%assign %%i 1
	%rep %%len 
		%substr %%c %%label %%i

		%if %%c == '['
			%define %%array
			%assign %%start %%i + 1
		%endif

		%if %%c == ']'
			%assign %%end %%i
		%endif

		%assign %%i %%i + 1
	%endrep

	%ifdef %%array
	    %substr %%sublabel %%label 1,%%start-2
	    %deftok toklabel %%sublabel 
	    toklabel:
	%else
	    %deftok toklabel %%label 
	    toklabel:
	%endif

	%ifdef  %%array
		%assign %%lenght %%end - %%start
		%substr %%number %%label %%start, %%lenght
		%deftok %%number %%number
		%ifnum %%number
			times %%number dd %2
		%else
			%error %?? number expected between array [] parantesis. 
		%endif
	%else
		dd %2
	%endif
%endmacro

%macro WORD 1-2+ 0h
	%defstr %%label %1
	%strlen %%len %%label

	%assign %%i 1
	%rep %%len 
		%substr %%c %%label %%i

		%if %%c == '['
			%define %%array
			%assign %%start %%i + 1
		%endif

		%if %%c == ']'
			%assign %%end %%i
		%endif

		%assign %%i %%i + 1
	%endrep
	
	%ifdef %%array
	    %substr %%sublabel %%label 1,%%start-2
	    %deftok toklabel %%sublabel 
	    toklabel:
	%else
	    %deftok toklabel %%label 
	    toklabel:
	%endif
	
	%ifdef  %%array
		%assign %%lenght %%end - %%start
		%substr %%number %%label %%start, %%lenght
		%deftok %%number %%number

		%ifnum %%number
			times %%number dw %2
		%else
			%error %?? number expected between array [] parantesis. 
		%endif
	%else
		dw %2
	%endif
%endmacro

%macro BYTE 1-2+ 0h
	%defstr %%label %1
	%strlen %%len %%label

	%assign %%i 1
	%rep %%len 
		%substr %%c %%label %%i

		%if %%c == '['
			%define %%array
			%assign %%start %%i + 1
		%endif

		%if %%c == ']'
			%assign %%end %%i
		%endif

		%assign %%i %%i + 1
	%endrep
	
	%ifdef %%array
	    %substr %%sublabel %%label 1,%%start-2
	    %deftok toklabel %%sublabel 
	    toklabel:
	%else
	    %deftok toklabel %%label 
	    toklabel:
	%endif
	
	%ifdef  %%array
		%assign %%lenght %%end - %%start
		%substr %%number %%label %%start, %%lenght
		%deftok %%number %%number
		
		%ifnum %%number
			times %%number db %2
		%else
			%error %?? number expected between array [] parantesis. 
		%endif
	%else
		db %2
	%endif
%endmacro

%macro QWORD 1-2+ 0h
	%defstr %%label %1
	%strlen %%len %%label

	%assign %%i 1
	%rep %%len 
		%substr %%c %%label %%i

		%if %%c == '['
			%define %%array
			%assign %%start %%i + 1
		%endif

		%if %%c == ']'
			%assign %%end %%i
		%endif

		%assign %%i %%i + 1
	%endrep

	%ifdef %%array
	    %substr %%sublabel %%label 1,%%start-2
	    %deftok toklabel %%sublabel 
	    toklabel:
	%else
	    %deftok toklabel %%label 
	    toklabel:
	%endif

	%ifdef  %%array
		%assign %%lenght %%end - %%start
		%substr %%number %%label %%start, %%lenght
		%deftok %%number %%number
		%ifnum %%number
			times %%number dq %2
		%else
			%error %?? number expected between array [] parantesis. 
		%endif
	%else
		dq %2
	%endif
%endmacro
