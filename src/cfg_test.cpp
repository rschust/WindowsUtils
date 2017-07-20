#include <windows.h>
#include <stdio.h>

// this constant should be calculated from the first instruction of LdrpValidateUserCallTarget
#define LDRSYSTEMDLLINITBLOCK_OFFSET 0xB0

#ifndef _WIN64
#define CFG_SHR_BITS 8
#else
#define CFG_SHR_BITS 9
#endif
const unsigned int OFFSET_MASK = ((sizeof(LPVOID) << 3) - 1);

#define BIT_TEST(R1, R2) ((R1 >> (R2 & OFFSET_MASK)) & 0x1)

BOOL LdrpValidateUserCallTarget_clone(LPCVOID func_)
{
	const uintptr_t func_numeric = (uintptr_t)func_;
	HMODULE hmod = GetModuleHandle(TEXT("ntdll"));
	LPVOID init_block_addr = GetProcAddress(hmod, "LdrSystemDllInitBlock");
	if (!init_block_addr) {
		printf("Could not find LdrSystemDllInitBlock, aborting.\n");
		return TRUE;
	}
	
	uintptr_t cfg_bitmap = *(uintptr_t*)((uintptr_t)init_block_addr + LDRSYSTEMDLLINITBLOCK_OFFSET);
	uintptr_t top_bits = func_numeric >> CFG_SHR_BITS;
	if (!cfg_bitmap) {
		printf("CFG is disabled. Please compile using \"/guard:cf\"\n");
		return TRUE;
	}
	
	uintptr_t cfg_bitmap_func_offset = *(uintptr_t*)(cfg_bitmap + (top_bits * (sizeof(LPVOID))));
	uintptr_t offset = func_numeric >> 3;
	
	if ((func_numeric & 0xF) || !BIT_TEST(cfg_bitmap_func_offset, offset)) {
		offset |= 1;
		if (!BIT_TEST(cfg_bitmap_func_offset, offset)) {
			printf("Invalid function address: %p\n", func_);
			return FALSE;
		}
	}
	
	return TRUE;
}

__declspec(dllexport)
int main(int argc, char **argv)
{
	//((void(*)())(((uintptr_t)LdrpValidateUserCallTarget_clone) + 0x10))();
	
	printf("%p: %d\n", &LdrpValidateUserCallTarget_clone, LdrpValidateUserCallTarget_clone(&LdrpValidateUserCallTarget_clone));
	printf("%p: %d\n", (uintptr_t)LdrpValidateUserCallTarget_clone + 0x10, LdrpValidateUserCallTarget_clone((LPVOID)((uintptr_t)LdrpValidateUserCallTarget_clone + 0x10)));
	
	return 0;
}
/*

77096040 8b15e8921277    mov     edx,dword ptr [ntdll!LdrSystemDllInitBlock+0xb0 (771292e8)]
77096046 8bc1            mov     eax,ecx
77096048 c1e808          shr     eax,8
7709604b 8b1482          mov     edx,dword ptr [edx+eax*4]
7709604e 8bc1            mov     eax,ecx
77096050 c1e803          shr     eax,3
77096053 f6c10f          test    cl,0Fh
77096056 7506            jne     ntdll!LdrpValidateUserCallTargetBitMapRet+0x1 (7709605e)

ntdll!LdrpValidateUserCallTargetBitMapCheck+0xd:
77096058 0fa3c2          bt      edx,eax
7709605b 7301            jae     ntdll!LdrpValidateUserCallTargetBitMapRet+0x1 (7709605e)

ntdll!LdrpValidateUserCallTargetBitMapRet:
7709605d c3              ret

ntdll!LdrpValidateUserCallTargetBitMapRet+0x1:
7709605e 83c801          or      eax,1
77096061 0fa3c2          bt      edx,eax
77096064 7301            jae     ntdll!LdrpValidateUserCallTargetBitMapRet+0xa (77096067)

ntdll!LdrpValidateUserCallTargetBitMapRet+0x9:
77096066 c3              ret

ntdll!LdrpValidateUserCallTargetBitMapRet+0xa:
77096067 51              push    ecx
77096068 8d642480        lea     esp,[esp-80h]
7709606c 0f110424        movups  xmmword ptr [esp],xmm0
77096070 0f114c2410      movups  xmmword ptr [esp+10h],xmm1
77096075 0f11542420      movups  xmmword ptr [esp+20h],xmm2
7709607a 0f115c2430      movups  xmmword ptr [esp+30h],xmm3
7709607f 0f11642440      movups  xmmword ptr [esp+40h],xmm4
77096084 0f116c2450      movups  xmmword ptr [esp+50h],xmm5
77096089 0f11742460      movups  xmmword ptr [esp+60h],xmm6
7709608e 0f117c2470      movups  xmmword ptr [esp+70h],xmm7
77096093 e8c753feff      call    ntdll!RtlpHandleInvalidUserCallTarget (7707b45f)
77096098 0f100424        movups  xmm0,xmmword ptr [esp]
7709609c 0f104c2410      movups  xmm1,xmmword ptr [esp+10h]
770960a1 0f10542420      movups  xmm2,xmmword ptr [esp+20h]
770960a6 0f105c2430      movups  xmm3,xmmword ptr [esp+30h]
770960ab 0f10642440      movups  xmm4,xmmword ptr [esp+40h]
770960b0 0f106c2450      movups  xmm5,xmmword ptr [esp+50h]
770960b5 0f10742460      movups  xmm6,xmmword ptr [esp+60h]
770960ba 0f107c2470      movups  xmm7,xmmword ptr [esp+70h]
770960bf 8da42480000000  lea     esp,[esp+80h]
770960c6 59              pop     ecx
770960c7 c3              ret

*/
