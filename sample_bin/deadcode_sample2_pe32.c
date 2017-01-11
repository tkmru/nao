#include <stdio.h>

int main()
{
	__asm {
		loc_414938:
			add     ebx, 1
			sub     eax, ecx
			jmp     short loc_414977

		loc_414949:
			or al, 99h
			mov     al, 0D9h
			pop     es
			cmpsd
			xchg    eax, ebp
			and     dh, dh
			and[esi + 237282DDh], dh
			mov     edi, 0C1F52320h
			into
			or eax, 5476544Fh
			pop     esp
			shr     byte ptr[edi + edx], 0F1h
			ror     dword ptr[esi], 8
			or edi, ebx
			sbb     esi, [eax]
			and [ecx - 25h], cl
			//icebp
			and [ecx - 25h], cl
			//icebp
			jmp short loc_414977

		loc_414977:
			add     eax, ecx
			dec     ebx
			jmp     short loc_414998

		loc_414998:
			add     ebx, 1
			sub     eax, ecx
			jmp     short loc_4149C7

		loc_4149C7:
			add     eax, ecx
			dec     ebx
			jmp     short loc_414A00

		loc_414A00:
			add     ebx, 1
			sub     eax, ecx
			jmp     short loc_414A2B

		loc_414A2B:
			add     eax, ecx
			dec     ebx
			jmp     short loc_414A4C

		loc_414A4C:
			add     ebx, 1
			sub     eax, ecx
			jmp     short loc_414A8B

		loc_414A8B:
			add     eax, ecx
			dec     ebx
			jmp     short loc_414D1C

		loc_414D1C:
			add     ebx, 1
			sub     eax, ecx
			jmp     short loc_414D5B

		No_Call:
			rol     ch, 1
			cmp     bl, ch
			pop     esi
			cmp     [ecx], eax
			wait
			fild    dword ptr [eax]
			//db      26h
			dec     esi
			adc     al, 4Ah
			popa
			test    al, 7Bh
			inc     ecx
			inc     ebx
			xchg    eax, ecx
			das
			mov     cl, bl
			popf
			xor		[ecx + ecx + 3Ah], dl
			pushf
			int     3
			wait
			mov     dl, 3Fh
			scasd
			sahf
			enter   60Ch, 24h
			or al, 6
			and al, 67h

		loc_414D5B:
			add     eax, ecx
			dec     ebx
			mov     eax, 1
			mov     ebx, 2
	}

	puts("dead_code_sample2");
	return 0;
}
