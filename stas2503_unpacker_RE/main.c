#pragma comment(lib, "comctl32.lib")
#pragma comment(lib, "Shlwapi.lib")
#pragma comment(lib, "Winmm.lib")
#pragma comment(lib, "zlibstat.lib ")

#define NTDDI_VERSION NTDDI_VISTA 
#define _WIN32_WINNT 0x0600 

#include <Windows.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>

#include <mbctype.h>
#include <shlwapi.h>
#include <Shlobj.h>

#include <intrin.h>

#include "defs.h"
#include "md5.h"


#include "zlib-1.2.11\zlib.h"
//#include "../zlib-1.2.11/deflate.h"
//#include "../zlib-1.2.11/inflate.h"

//TYPES
#pragma pack(push, 1)
typedef struct g_data_{
	HANDLE g_hHeap;
	HINSTANCE g_hModule;
	__int64 g_uExitCode;
	__int64 field_18;
	__int64 g_copy_of_star;
	__int64 g_sizeofres;
	__int64 script1;
	__int64 g_wCommandLine;
	__int64 g_temp_fn02;
	__int64 field_48;
	__int64* g_cursor;
	__int64 field_58;
	__int64 g_hSTD_OUTPUT_HANDLE;
	__int64 g_temp_fn03;
	__int64 g_unk_2;
	//__int64 field_78;
	wchar_t* field_78; //2D46DA3FCC2DEFDC323544CDEF33D9E7
	__int64 field_80;
	wchar_t* g_path01;
	HMODULE g_module0handle;
	__int64 g_IsCmdLinesEQ;
	wchar_t* field_A0;
	wchar_t* g_temp_fn100;
	__int64 field_B0;
	__int64 field_B8;
	wchar_t* g_copy_of_slash;
	__int64 g_temp_fn04;
	__int64 g_unk;
	__int64 g_temp_fn01;
	__int64 field_E0;
	__int64 field_E8;
	__int64 field_F0;
	__int64 field_F8;
	__int64 field_100;
	__int64 field_108;
	__int64 g_flag_main;
	QWORD* g_200020;
	__int64 g_unk_1;
	void* g_root_601_1;
	__int64 field_130;
	void* g_root_601_2;
	__int64 field_140;
	void* g_root_601_3;
	__int64 field_150;
	void* g_stu602_root;
	__int64 g_unk_3;
	__int64 g_unk_4;
} g_data;
#pragma pack(pop)

typedef struct unk001_{
	struct unk001_* fld01_next;
	_QWORD fld02_freefn;
	_QWORD fld03_unk01;
} unk001;

typedef struct RegSingleObject_{
	_QWORD root;
	_QWORD next;
	unk001* fld03_uk01;
	PHANDLE phNewWaitObject;
	LPHANDLE lpTargetHandle;
} RegSingleObject;

typedef struct stru0x20_{
	struct stru0x20_* left;
	struct stru0x20_* right;
	HANDLE hObject;
	QWORD index;
} stru0x20;

typedef struct stru0x28_{
	stru0x20 s20;
	QWORD fld04;
} stru0x28;

typedef struct myV10_0x28_{
	QWORD parent;
	QWORD left;
	QWORD right;
	QWORD size_plus;
	DWORD aFlags;
	DWORD nn;
} myV10_0x28;

typedef struct unk028_{
	QWORD f0;
	QWORD f1;
	QWORD offset;
	QWORD function;
	QWORD arg3;
} unk028;


typedef struct strNode_{
	char* str;
	_QWORD ssize;
	_QWORD slen;
} strNode;

typedef struct stru_0x60_{
	DWORD itemsize;
	DWORD sizex8;
	QWORD qallocatedx8;
	QWORD mem;
	QWORD fld03;
	QWORD fn_free;
	QWORD fld05;
	QWORD fld06;
	CRITICAL_SECTION lpCriticalSection;
} stru_0x60;

#pragma pack(push, 1)
typedef struct myV13_0x60_{
	QWORD f0;
	QWORD f1;
	QWORD f2;
	QWORD f3;
	QWORD sizePlsu0x18;
	DWORD size;
	DWORD items;
	DWORD CS_initialized;
	DWORD f34;
	CRITICAL_SECTION CS;
} myV13_0x60;
#pragma pack(pop)

typedef struct stru_602_{
	struct stru_602_* parent;
	QWORD subitems_8xcount;
	QWORD f2;
	QWORD subitems_10PlsSize;
	signed __int64 mask;
	DWORD blockIdx;
	DWORD f2C;
	QWORD size;
	DWORD arg2;
	int count;
	QWORD mask_walk_res;
	struct stru_602_* root;
	QWORD f10;
	QWORD treeIter;
} stru_602;

typedef struct root_601_{
	QWORD left;
	QWORD right;
} root_601;

typedef struct stru_601_{
	QWORD f0;
	QWORD f1;
	QWORD f2;
	root_601* root_next;
	QWORD f4;
	QWORD f5;
	QWORD aMASK;
	QWORD treeIter;
	QWORD f8;
	root_601* proot;
	QWORD size_plus_0x10;
	DWORD arg4;
	BYTE f5c;
	BYTE maskwalk;
	BYTE DoHeapAlloc;
	BYTE f5f;
} stru_601;

typedef struct _GUID_ {
	unsigned int Data1;
	unsigned __int16 Data2;
	unsigned __int16 Data3;
	unsigned __int8 Data4[8];
} _GUID;

#pragma pack(push, 1)
typedef struct s30_{
	DWORD f0;
	DWORD f4;
	QWORD elsize;
	QWORD mask;
	QWORD* root;
	QWORD count;
	DWORD arg3;
	DWORD f2c;
} s30;
#pragma pack(pop)

typedef struct file_holder_{
	HANDLE handle;
	LPCVOID lpBuffer;
	DWORD alloc_size;
	DWORD seekpos;
	DWORD a18;
	DWORD doSeek;
	DWORD dwCreationDisposition;
	DWORD IsSeekCur;
} file_holder;

union subs{
	myV13_0x60* a;
	myV10_0x28* b;
};






//typedef enum z_err_ {
//	Z_OK = 0x0,
//	Z_STREAM_END = 0x1,
//	Z_NEED_DICT = 0x2,
//	Z_ERRNO = 0xFFFFFFFF,
//	Z_STREAM_ERROR = 0xFFFFFFFE,
//	Z_DATA_ERROR = 0xFFFFFFFD,
//	Z_MEM_ERROR = 0xFFFFFFFC,
//	Z_BUF_ERROR = 0xFFFFFFFB,
//	Z_VERSION_ERROR = 0xFFFFFFFA,
//} z_err;


//DATA

wchar_t g_PrefixString[3] = {0u, 10u, 0u};
wchar_t aOpen[8] = L"open\x00**";
wchar_t NL[2] = {13u, 10u};


const wchar_t slash[] = L"\\";


_QWORD g_MASK[6] = {0i64, -1i64, 4i64, -1i64, 8i64, -1i64};
unsigned char g_salt[] = {
  0x7F, 0x3B, 0xD5, 0x06, 0x70, 0x06, 0x49, 0x05, 0xBB, 0x8E,
  0x8E, 0x91, 0x8E, 0xC0, 0x8D, 0x98, 0x97, 0x9A, 0x8C, 0xE0,
  0xD1, 0xD0, 0xAD, 0x9B, 0x94, 0x9B, 0x9D, 0x8C, 0xE0, 0x8C,
  0x98, 0x9B, 0xE0, 0x9B, 0x88, 0x8C, 0x8E, 0x9F, 0x9D, 0x8C,
  0x97, 0x91, 0x92, 0xE0, 0x90, 0x9F, 0x8C, 0x98, 0xAD, 0x9B,
  0x94, 0x9B, 0x9D, 0x8C, 0xE0, 0x8C, 0x98, 0x9B, 0xE0, 0x89,
  0x91, 0x8E, 0x95, 0x97, 0x92, 0x99, 0xE0, 0x9C, 0x97, 0x8E,
  0x9B, 0x9D, 0x8C, 0x91, 0x8E, 0x87, 0x9E, 0xCE, 0x9B, 0x9F,
  0x8E, 0x99, 0x8D, 0x9E, 0xCE, 0x9B, 0x97, 0x92, 0x9D, 0x9A,
  0x97, 0x94, 0x9B, 0x90, 0x9F, 0x8C, 0x98, 0x9E, 0xCE, 0x9B,
  0x97, 0x92, 0x9D, 0x9A, 0x97, 0x94, 0x9B, 0x9D, 0x91, 0x8B,
  0x92, 0x8C, 0x9E, 0xCE, 0x9B, 0x97, 0x92, 0x9D, 0x9A, 0x97,
  0x94, 0x9B, 0x9D, 0x93, 0x9C, 0xD1, 0x9D, 0xD2, 0x9B, 0x88,
  0x9B, 0xD2, 0x9E, 0x9F, 0x8C, 0x9B, 0x88, 0x8C, 0x9C, 0x00,
  0x00, 0x00, 0x00, 0x00
};

__int64 g_tree_node_counter = 1i64;
LPCWSTR g_lpClassName = L"InputRequester";
unsigned int g_ExceptionCode = 0xFFFFFFFF;
//align 8
_GUID g_cFOLDERID_Downloads = {927851152u, 4671u, 17765u, { 145u, 100u, 57u, 196u, 146u, 94u, 70u, 123u }};
int g_dw_1000 = 4096;
//align 10h
char g_MD5PADDING[64] =
{
  '\x80',
  '\0',
  '\0',
  '\0',
  '\0',
  '\0',
  '\0',
  '\0',
  '\0',
  '\0',
  '\0',
  '\0',
  '\0',
  '\0',
  '\0',
  '\0',
  '\0',
  '\0',
  '\0',
  '\0',
  '\0',
  '\0',
  '\0',
  '\0',
  '\0',
  '\0',
  '\0',
  '\0',
  '\0',
  '\0',
  '\0',
  '\0',
  '\0',
  '\0',
  '\0',
  '\0',
  '\0',
  '\0',
  '\0',
  '\0',
  '\0',
  '\0',
  '\0',
  '\0',
  '\0',
  '\0',
  '\0',
  '\0',
  '\0',
  '\0',
  '\0',
  '\0',
  '\0',
  '\0',
  '\0',
  '\0',
  '\0',
  '\0',
  '\0',
  '\0',
  '\0',
  '\0',
  '\0',
  '\0'
};
DWORD g_dwTlsIndex = 0xFFFFFFFF;
int g_unk = 39029;



g_data g_DATA =
{
  NULL,
  NULL,
  0i64,
  0i64,
  0i64,
  0i64,
  0i64,
  0i64,
  0i64,
  0i64,
  NULL,
  0i64,
  0i64,
  0i64,
  0i64,
  0i64,
  0i64,
  NULL,
  NULL,
  0i64,
  NULL,
  NULL,
  0i64,
  0i64,
  NULL,
  0i64,
  0i64,
  0i64,
  0i64,
  0i64,
  0i64,
  0i64,
  0i64,
  0i64,
  0i64,
  NULL,
  0i64,
  NULL,
  0i64,
  NULL,
  0i64,
  NULL,
  0i64,
  NULL,
  0i64,
  0i64
};
int g_unk_1 = 0;
stru0x20* g_tree_stru0x20__ = NULL;
int g_timeBeginPeriod_flag = 0;
int g_unk_0 = 0;
HGDIOBJ g_default_font = NULL;
int g_wndProcExit = 0;
int g_isWindowEnabled = 0;
__int64 hWnd_btnOK_ctrl = 0i64;
HWND hWnd_edit_ctrl = NULL;
HWND static_control_hwnd = NULL;
HWND g_fgWnd = NULL;
int g_IsCoInitialized = 0;

//align 20h
stru0x28 g_tree_stru0x28;
HRESULT(__stdcall* p_SHGetKnownFolderPath)(const REFKNOWNFOLDERID* const rfid, DWORD dwFlags, HANDLE hToken, PWSTR* ppszPath);
int g_counter10;

//align 20h
_DWORD g_buf_0x28[640];
__int64 g_root_unk028;
SIZE_T g_TLS_8_allocated_size;
DWORD g_TLS_8;

//align 8
unsigned __int64 g_qword_140021058;
__int64 g_TREE_ROOT;
struct _RTL_CRITICAL_SECTION g_treeCritSect;
QWORD g_unk_2;
struct _RTL_CRITICAL_SECTION stru_140021098;
DWORD nullstr1;
DWORD nullstr2;
void* (__fastcall* g_fn_01_obj1)(__int64 a1, QWORD aElSize, int a3, QWORD* aMask, void* aResult);
void* (__fastcall* g_fn_alloc_obj1)(QWORD aElSize, QWORD aCnt, int a3, QWORD* aMask, void** aResult);
stru_601* (__fastcall* g_ctor_0x60_2)(__int64 aSize, root_601** root, signed __int64* aMASK, DWORD a4);
stru_602* (__fastcall* g_ctor_0x60)(QWORD asize, DWORD a2, signed __int64 aMask, stru_602* aRoot, int acount);
__int64(__fastcall* g_fn_02_obj1)(QWORD* src, __int64 a2, int aAllocNew);
__int64(__fastcall* g_fn_0x60_2)(_QWORD, _QWORD, _QWORD);
__int64(__fastcall* g_fn_0_0x60)(stru_602* a1, stru_602* a2, int aRemove);
BOOL(__fastcall* g_fn_free_obj1)(stru_602* a1);
__int64(__fastcall* g_dtor_0x60_2)(_QWORD);
BOOL(__fastcall* g_dtor_0x60)(stru_602* aroot);
int g_tls_rso_init;
//align 20h
RegSingleObject* g_RegSingleObject;
struct _RTL_CRITICAL_SECTION stru_140021128;
DWORD g_TLS_rso;
char g_unk_3[28];
struct _RTL_CRITICAL_SECTION CriticalSection;
//align 40h
__int64 g_stru_0x60_4;
//align 10h
__int64 g_TLS_8_pos;
//align 20h
struct _RTL_CRITICAL_SECTION stru_1400211E0;
__int64 g_unk_4;
DWORD g_Exception_unk;
//align 20h
__int64 g_ExceptionAddress;
//align 10h
__int64 g_ExceptionInformation;
//align 20h
DWORD g_ExRax;
DWORD g_ExRcx;
DWORD g_ExRdx;
DWORD g_ExRbx;
DWORD g_ExRsp;
DWORD g_ExRbp;
DWORD g_ExRsi;
DWORD g_ExRdi;
DWORD g_ExR8;
DWORD g_ExR9;
DWORD g_ExR10;
DWORD g_ExR11;
DWORD g_ExR12;
DWORD g_ExR13;
DWORD g_ExR14;
DWORD g_ExR15;
DWORD g_ExEFlags;
//align 10h
HANDLE G_ZHEAP;
//align 40h
stru_0x60* g_stru_0x60_10;
//align 10h
HANDLE heap_HANDLE; //last
//END DATA

//rdata
DWORD nullstr = 0u;
unsigned __int16 g_SPACE[4] = {32u, 0u, 0u, 0u};


__m128i stru_1400196A0 = {{ 16, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 }};
//end rdara


char md6_padding[8] = {'\x80', '\0', '\0', '\0', '\0', '\0', '\0', '\0'};
char a0123456789abcd[16] = "0123456789abcdef";


wchar_t* __fastcall wcscpy_heap_alloc(wchar_t* Source){
	size_t v2; // rax
	wchar_t* v3; // rax
	wchar_t* v4; // rdi

	if (!Source)
		return 0i64;
	v2 = wcslen(Source);
	v3 = (wchar_t*)HeapAlloc(g_DATA.g_hHeap, 0, 2 * v2 + 2);
	v4 = v3;
	if (!v3)
		return 0i64;
	wcscpy(v3, Source);
	return v4;
}
void __stdcall alloc_strNode(){
	strNode* mem; // [rsp+20h] [rbp-18h]

	mem = (strNode*)HeapAlloc(heap_HANDLE, 0, 0x18ui64);
	mem->str = (char*)HeapAlloc(heap_HANDLE, 0, 0x10ui64);
	mem->ssize = 0x10i64;
	mem->slen = 0i64;
	TlsSetValue(g_dwTlsIndex, mem);
}

void __stdcall create_and_alloc_STRtree(){
	heap_HANDLE = HeapCreate(0, 0x1000ui64, 0i64);
	g_dwTlsIndex = TlsAlloc();
	alloc_strNode();
}

void ShowExeptionMessageBox(){
	MessageBoxW(0, "Exeption", "Exeption", 0);
	exit(0);
}

BOOL __fastcall HeapFree__0(void* a1){
	if (a1)
		return HeapFree(heap_HANDLE, 0, a1);
	return 0;
}

__int64 __fastcall mask_walk(signed __int64* aMASK){
	__int64 Result; // rcx
	signed __int64* v3; // rcx
	__int64 itm; // rax

	// Mask:
	// 0, 0FFFFFFFFFFFFFFFFh, 4, 0FFFFFFFFFFFFFFFFh, 8, 0FFFFFFFFFFFFFFFFh

	Result = 0i64;
	if (!aMASK)
		return Result;
	while (1){
		do{
			itm = *aMASK;
			if (*aMASK == -1i64)
				return Result;
			++aMASK;
		} while (itm < -7);
		if (itm <= -4){
			Result = 1i64;
			goto LABEL_11;
		}
		if (itm == -3)
			break;
		if (itm == -2){
			v3 = (signed __int64*)aMASK[3];
			aMASK += 4;
LABEL_9:
			Result = mask_walk(v3);
LABEL_11:
			if (Result)
				return Result;
		}
	}

	v3 = (signed __int64*)aMASK[2];
	aMASK += 3;
	goto LABEL_9;
}
void __fastcall dtor_by_MASK(stru_602* aRoot, __int64 aMASK){
	__int64 maskitem; // rax
	__int64* mask; // rbx
	void* v5; // rcx
	__int64 v6; // rsi
	__int64 v7; // rax
	__int64 v8; // rcx
	__int64 v9; // rdx
	int v10; // ebp
	__int64 v11; // rax
	__int64 mval; // rcx
	__int64 m2; // rdx
	__int64 v14; // rcx
	__int64 v15; // rcx
	__int64 v16; // rcx
	__int64 v17; // [rsp+20h] [rbp-28h]
	__int64 v18; // [rsp+60h] [rbp+18h]
	__int64 v19; // [rsp+68h] [rbp+20h]

	maskitem = *(_QWORD*)aMASK;
	mask = (__int64*)aMASK;
	while (maskitem != 0xFFFFFFFFFFFFFFFFui64){
		++mask;
		switch (maskitem){
			case -7i64:
				v14 = *mask;
				mask += mask[1] + 5;
				goto LABEL_19;
			case -6i64:
				v16 = *mask;
				mask += 5;
				g_dtor_0x60(*(stru_602**)((char*)&aRoot->parent + v16));
				break;
			case -5i64:
				v15 = *mask;
				mask += 4;
				g_dtor_0x60_2(*(stru_602**)((char*)&aRoot->parent + v15));
				break;
			case -4i64:
				v14 = *mask;
				mask += 5;
LABEL_19:
				// BOOL __fastcall fn_free_obj1(stru_602 *a1)
				g_fn_free_obj1(*(stru_602**)((char*)&aRoot->parent + v14));
				break;
			case -3i64:
				mval = *mask;
				m2 = mask[2];
				mask += 3;
				dtor_by_MASK((stru_602*)((char*)aRoot + mval), m2);
				break;
			case -2i64:
				v6 = *mask;
				v7 = mask[1];
				v8 = mask[2];
				v9 = mask[3];
				mask += 4;
				v10 = 0;
				v18 = v7;
				v19 = v8;
				v17 = v9;
				if (v6 > 0){
					v11 = 0i64;
					do{
						dtor_by_MASK((stru_602*)((char*)aRoot + v18 + v11 * v8), v9);
						v8 = v19;
						v9 = v17;
						v11 = ++v10;
					} while (v10 < v6);
				}
				break;
			default:
				v5 = *(stru_602**)((char*)&aRoot->parent + maskitem);
				if (v5)
					HeapFree__0(v5);
				break;
		}
		maskitem = *mask;
	}
}
__int64 __fastcall ctor_c602(stru_602* a602, __int64* aMask){
	__int64 mval; // rax
	__int64* mask; // rbx
	stru_602* i; // rdi
	__int64 v5; // rsi
	__int64* v6; // rbx
	__int64 v7; // rax
	__int64 v8; // rcx
	__int64* v9; // rcx
	stru_602* v10; // rbp
	__int64* v11; // rbx
	__int64 v12; // rcx
	__int64** v13; // rbx
	__int64* v14; // rdx
	__int64 v15; // rax
	QWORD* v16; // rbx
	QWORD v17; // rcx
	QWORD v18; // rdx
	__int64 v19; // r8
	QWORD* v20; // r9
	__int64 v21; // rdx
	__int64* v22; // rbx
	__int64 v23; // rcx
	signed __int64* v24; // r8
	__int64 v25; // r9
	__int64 v26; // r9
	QWORD* v27; // rbx
	QWORD v28; // rcx
	__int64 v29; // rdx
	signed __int64 v30; // r8
	QWORD v31; // rax
	__int64 v32; // rsi
	__int64* v33; // rbx
	__int64 v34; // rcx
	QWORD v35; // rdx
	__int64 v36; // r8
	QWORD* v37; // r9
	__int64 v38; // r11
	_QWORD* v39; // r10
	__int64 v40; // rax
	__int64* v42; // [rsp+68h] [rbp+10h]
	__int64 v43; // [rsp+70h] [rbp+18h]

	mval = *aMask;
	mask = aMask;
	for (i = a602; *mask != 0xFFFFFFFFFFFFFFFFui64; mval = *mask){
		++mask;
		switch (mval){
			case 0xFFFFFFFFFFFFFFF9i64:
				v32 = *mask;
				v33 = mask + 1;
				v34 = *v33++;
				v35 = *v33++;
				v36 = *v33++;
				v37 = (QWORD*)*v33;
				mask = v33 + 1;
				if (v34 > 0){
					v38 = v34;
					v39 = (QWORD*)((char*)&i->subitems_8xcount + v32);
					do{
						v40 = *mask++;
						*v39++ = v40;
						--v38;
					} while (v38);
				}
				g_fn_01_obj1(v34, v35, v36, v37, (char*)i + v32);
				break;
			case 0xFFFFFFFFFFFFFFFAi64:
				v26 = *mask;
				v27 = (QWORD*)(mask + 1);
				v28 = *v27++;
				v29 = *v27++;
				v30 = *v27++;
				v31 = *v27;
				mask = (__int64*)(v27 + 1);
				g_ctor_0x60(v28, v29, v30, (stru_602*)((char*)i + v26), v31);
				break;
			case 0xFFFFFFFFFFFFFFFBi64:
				v21 = *mask;
				v22 = mask + 1;
				v23 = *v22++;
				v24 = (signed __int64*)*v22++;
				v25 = *v22;
				mask = v22 + 1;
				// stru_601 *__fastcall ctor_0x60_2(__int64 aSize, root_601 **root, signed __int64 *aMASK, DWORD a4)
				g_ctor_0x60_2(v23, (root_601**)((char*)i + v21), v24, v25);
				break;
			case 0xFFFFFFFFFFFFFFFCi64:
				v15 = *mask;
				v16 = (QWORD*)(mask + 1);
				v17 = *v16++;
				v18 = *v16++;
				v19 = *v16++;
				v20 = (QWORD*)*v16;
				mask = (__int64*)(v16 + 1);
				g_fn_alloc_obj1(v17, v18, v19, v20, (void**)((char*)&i->parent + v15));
				break;
			case 0xFFFFFFFFFFFFFFFDi64:
				v12 = *mask;
				v13 = (__int64**)(mask + 2);
				v14 = *v13;
				mask = (__int64*)(v13 + 1);
				ctor_c602((stru_602*)((char*)i + v12), v14);
				break;
			case 0xFFFFFFFFFFFFFFFEi64:
				v5 = *mask;
				v6 = mask + 1;
				v7 = *v6++;
				v8 = *v6++;
				v43 = v8;
				v9 = (__int64*)*v6;
				mask = v6 + 1;
				v42 = mask;
				if (v5 > 0){
					v10 = (stru_602*)((char*)i + v7);
					v11 = v9;
					do{
						ctor_c602(v10, v11);
						v10 = (stru_602*)((char*)v10 + v43);
						--v5;
					} while (v5);
					mask = v42;
					i = a602;
				}
				break;
		}
	}
	return mval;
}
BOOL __fastcall fn_free_obj1_(stru_602* a1){
	int v2; // esi
	stru_602* i; // rdi
	BOOL result; // eax

	if (!a1)
		return 0;
	if (a1[-1].mask_walk_res){
		v2 = 0;
		for (i = a1; v2 < (signed __int64)a1[-1].f10; ++v2){
			dtor_by_MASK(i, a1[-1].mask_walk_res);
			i = (stru_602*)((char*)i + *(_QWORD*)&a1[-1].arg2);
		}
	}
	a1[-1].root->parent = 0i64;
	return HeapFree(g_DATA.g_hHeap, 0, &a1[-1].size);
}
void* __fastcall fn_alloc_obj1(QWORD aElSize, QWORD aCnt, int a3, QWORD* aMask, void** aResult){
	int v6; // edi
	char* mem; // rbx
	s30* hdr; // rax
	__int64 itr; // rax

	v6 = 0;
	mem = 0i64;
	fn_free_obj1_((stru_602*)*aResult);
	if ((__int64)aCnt <= 0)
		return mem;

	hdr = (s30*)HeapAlloc(g_DATA.g_hHeap, 0, aCnt * aElSize + 0x30);
	mem = (char*)hdr;
	if (!hdr)
		return mem;
	mem = (char*)&hdr[1];
	hdr->elsize = aElSize;
	hdr->count = aCnt;
	hdr->arg3 = a3;
	hdr->mask = (QWORD)aMask;
	hdr->root = (QWORD*)aResult;
	hdr->f0 = 1;
	memset(&hdr[1], 0, aCnt * aElSize);

	*aResult = mem;
	if (!mask_walk((signed __int64*)aMask))
		return mem;
	itr = 0i64;
	do{
		ctor_c602((stru_602*)&mem[aElSize * itr], (__int64*)aMask);
		itr = ++v6;
	} while (v6 < (__int64)aCnt);
	return mem;
}
void* __fastcall fn_01_obj1(__int64 a1, QWORD aElSize, int a3, QWORD* aMask, void* aResult){
	//s30* __shifted(unk028, 0x30) v5; // r10
	void* v5; // r10
	QWORD elSize; // r12
	int v10; // edi
	QWORD cnt; // rbp
	__int64* v12; // r9
	int v13; // r8d
	__int64 v14; // rsi
	int v15; // edx
	QWORD* v16; // rcx

	v5 = 0i64;
	elSize = aElSize;
	v10 = 0;
	cnt = 1i64;
	if (a1 <= 0)
		goto LABEL_10;
	v12 = (__int64*)((char*)aResult + 8);
	v13 = 1;
	do{
		v14 = 1i64;
		if (*v12 <= 0)
			v10 = 1;
		v15 = v13;
		cnt *= *v12;
		if (v13 < a1){
			v16 = (QWORD*)((char*)aResult + 8 * v13 + 8);
			do{
				v14 *= *v16;
				++v15;
				++v16;
			} while (v15 < a1);
		}
		++v13;
		*v12++ = v14;
	} while (v13 - 1 < a1);
	elSize = aElSize;
	if (v10)
		return v5;
LABEL_10:
	//v5 = (s30 * __shifted(unk028, 0x30))fn_alloc_obj1(elSize, cnt, a3, aMask, (void**)aResult);
	//LODWORD(ADJ(v5)->f0) = a1;
	v5 = fn_alloc_obj1(elSize, cnt, a3, aMask, (void**)aResult);
	*((_DWORD*)v5 - 0xC) = a1;
	return v5;
}
__int64 __fastcall wstrcpy(_DWORD* dst, _DWORD* src, int len){
	__int64 result; // rax
	_DWORD* dst_1; // [rsp+20h] [rbp+8h]
	int len_1; // [rsp+30h] [rbp+18h]

	len_1 = len;
	dst_1 = dst;
	while (len_1 > 0){
		*dst_1++ = *src++;
		len_1 -= 2;
	}
	result = 0i64;
	*((_WORD*)dst + len) = 0;
	return result;
}
void __fastcall wstrdup_10(LPVOID* out, wchar_t* src){
	int len; // [rsp+20h] [rbp-18h]

	if (src){
		len = wcslen(src);
		*out = HeapAlloc(heap_HANDLE, 0, 2i64 * (len + 5));
		wstrcpy(*out, src, len);
	}
}
size_t __fastcall my_wstrcpy(LPVOID* a1, wchar_t* aSrc){
	void* v2; // rax
	size_t len; // [rsp+20h] [rbp-18h]

	len = 0i64;
	if (aSrc){
		len = wcslen(aSrc);
		if (*a1)
			v2 = HeapReAlloc(heap_HANDLE, 0, *a1, 2 * len + 0xA);
		else
			v2 = HeapAlloc(heap_HANDLE, 0, 2 * len + 0xA);
		*a1 = v2;
		wstrcpy(*a1, aSrc, len);
	} else if (*a1){
		HeapFree(heap_HANDLE, 0, *a1);
		*a1 = 0i64;
	}
	return 2 * len + 2;
}
void __fastcall stu602_cpy(stru_602* a602, QWORD asize, signed __int64 aMask, stru_602* b602){
	signed __int64 v5; // rax
	stru_602* bb602; // rbp
	signed __int64 size; // r8
	stru_602* aaa602; // r10
	__int64 mask; // rdi
	wchar_t* v10; // rax
	LPVOID* v11; // rsi
	void* v12; // rcx
	__int64 v13; // rsi
	QWORD v14; // rax
	signed __int64 v15; // rdx
	signed __int64 v16; // rcx
	__int64 v17; // rbx
	stru_602* v18; // rbp
	signed __int64 v19; // rsi
	QWORD v20; // rsi
	signed __int64 v21; // r8
	stru_602* v22; // r9
	stru_602* v23; // rcx
	QWORD* v24; // rsi
	void** v25; // rax
	stru_602* v26; // rcx
	void* v27; // rax
	__int64 v28; // rsi
	root_601** v29; // rax
	__int64 v30; // rcx
	stru_602* v602; // rsi
	stru_602* root_item602; // rdx
	stru_602* item602; // rcx
	int* v34; // rbx
	QWORD* v35; // rsi
	void** v36; // rax
	stru_602* v37; // rcx
	_DWORD* v38; // rax
	stru_602* a602_src; // rdx
	size_t Size; // [rsp+30h] [rbp-68h]
	QWORD Sizea; // [rsp+30h] [rbp-68h]
	root_601** v54; // [rsp+30h] [rbp-68h]
	stru_602** v53; // [rsp+30h] [rbp-68h]
	int Sized; // [rsp+30h] [rbp-68h]
	__int64 v45; // [rsp+38h] [rbp-60h]
	signed __int64 v46; // [rsp+50h] [rbp-48h]
	__int64 v47; // [rsp+60h] [rbp-38h]
	void** v48; // [rsp+60h] [rbp-38h]
	void** v49; // [rsp+60h] [rbp-38h]
	stru_602* aa602; // [rsp+A0h] [rbp+8h]
	signed __int64 v52; // [rsp+B0h] [rbp+18h]

	if (b602 == a602)
		return;
	aa602 = a602;
	v5 = 0i64;
	bb602 = b602;
	size = asize;
	aaa602 = a602;
	v45 = 0i64;
	if (aMask){
		mask = *(_QWORD*)aMask;
		if (*(_QWORD*)aMask == 0xFFFFFFFFFFFFFFFFui64)
			goto LABEL_43;
		while (1){
			aMask += 8i64;
			if (mask == 0xFFFFFFFFFFFFFFF9ui64){
				mask = *(_QWORD*)aMask;
				v34 = (int*)(aMask + 8);
				v35 = *(QWORD**)((char*)&bb602->parent + mask);
				Sized = *v34;
				v36 = (void**)((char*)&aaa602->parent + mask);
				v37 = *(stru_602**)((char*)&aaa602->parent + mask);
				v49 = (void**)((char*)&aaa602->parent + mask);
				aMask = (signed __int64)&v34[2 * *v34 + 8];
				if (v37){
					// BOOL __fastcall fn_free_obj1(stru_602 *a1)
					g_fn_free_obj1(v37);
					v36 = v49;
				}
				if (v35){
					v38 = g_fn_alloc_obj1(v35[-5], v35[-2], *((_DWORD*)v35 - 2), (QWORD*)v35[-4], v36);
					v38[-0xC] = *((_DWORD*)v35 - 0xC);
					g_fn_02_obj1(v35, (__int64)v38, 0);
				}
				v20 = 8i64 * Sized + 8;
				goto LABEL_39;
			}
			if (mask == 0xFFFFFFFFFFFFFFFAui64)
				break;
			if (mask == 0xFFFFFFFFFFFFFFFBui64){
				mask = *(_QWORD*)aMask;
				aMask += 0x20i64;
				v28 = *(__int64*)((char*)&bb602->parent + mask);
				v29 = (root_601**)((char*)aaa602 + mask);
				v30 = *(__int64*)((char*)&aaa602->parent + mask);
				v54 = (root_601**)((char*)aaa602 + mask);
				if (v30){
					g_dtor_0x60_2(v30);
					v29 = v54;
				}
				if (v28){
					// stru_601 *__fastcall ctor_0x60_2(__int64 aSize, root_601 **root, signed __int64 *aMASK, DWORD a4)
					g_ctor_0x60_2(
						*(_QWORD*)(v28 + 0x50) - 0x10i64,
						v29,
						*(signed __int64**)(v28 + 0x30),
						*(_DWORD*)(v28 + 0x58));
					// fn_0x60_2
					g_fn_0x60_2(*(stru_602**)((char*)&bb602->parent + mask), *v54, 0i64);
				}
				v20 = 0x10i64;
				goto LABEL_39;
			}
			if (mask == 0xFFFFFFFFFFFFFFFCui64){
				mask = *(_QWORD*)aMask;
				aMask += 0x28i64;
				v24 = *(QWORD**)((char*)&bb602->parent + mask);
				v25 = (void**)((char*)&aaa602->parent + mask);
				v26 = *(stru_602**)((char*)&aaa602->parent + mask);
				v48 = (void**)((char*)&aaa602->parent + mask);
				if (v26){
					// BOOL __fastcall fn_free_obj1(stru_602 *a1)
					g_fn_free_obj1(v26);
					v25 = v48;
				}
				if (v24){
					v27 = g_fn_alloc_obj1(v24[-5], v24[-2], *((_DWORD*)v24 - 2), (QWORD*)v24[-4], v25);
					g_fn_02_obj1(v24, (__int64)v27, 0);
				}
LABEL_24:
				v20 = 8i64;
				goto LABEL_39;
			}
			if (mask != 0xFFFFFFFFFFFFFFFDui64){
				if (mask == 0xFFFFFFFFFFFFFFFEui64){
					v13 = *(_QWORD*)aMask;
					mask = *(_QWORD*)(aMask + 8);
					v14 = *(_QWORD*)(aMask + 0x10);
					v15 = *(_QWORD*)(aMask + 0x18);
					aMask += 0x20i64;
					v47 = v13;
					Sizea = v14;
					v52 = aMask;
					v46 = v15;
					if (v13 > 0){
						v16 = (char*)bb602 - (char*)aaa602;
						v17 = v13;
						v18 = (stru_602*)((char*)aaa602 + mask);
						v19 = v16;
						do{
							stu602_cpy(v18, Sizea, v15, (stru_602*)((char*)v18 + v19));
							v15 = v46;
							v18 = (stru_602*)((char*)v18 + Sizea);
							--v17;
						} while (v17);
						aMask = v52;
						v13 = v47;
						bb602 = b602;
						v14 = Sizea;
					}
					v20 = v14 * v13;
					goto LABEL_39;
				}
				v10 = *(wchar_t**)((char*)&bb602->parent + mask);
				v11 = (LPVOID*)((char*)&aaa602->parent + mask);
				v12 = *(stru_602**)((char*)&aaa602->parent + mask);
				Size = (size_t)v10;
				if (v12){
					HeapFree__0(v12);
					*v11 = 0i64;
					v10 = (wchar_t*)Size;
				}
				if (v10)
					wstrdup_10(v11, v10);
				goto LABEL_24;
			}
			mask = *(_QWORD*)aMask;
			v20 = *(_QWORD*)(aMask + 8);
			v21 = *(_QWORD*)(aMask + 0x10);
			v22 = (stru_602*)((char*)bb602 + *(_QWORD*)aMask);
			v23 = (stru_602*)((char*)aaa602 + *(_QWORD*)aMask);
			aMask += 0x18i64;
			stu602_cpy(v23, v20, v21, v22);
LABEL_39:
			if (v45 < mask)
				memcpy((char*)aa602 + v45, (char*)bb602 + v45, mask - v45);
			aaa602 = aa602;
			v5 = v20 + mask;
			mask = *(_QWORD*)aMask;
			v45 = v5;
			if (*(_QWORD*)aMask == 0xFFFFFFFFFFFFFFFFui64){
				size = asize;
LABEL_43:
				if (v5 >= size)
					return;
				size -= v5;
				a602_src = (stru_602*)((char*)bb602 + v5);
				a602 = (stru_602*)((char*)aaa602 + v5);
				goto LABEL_46;
			}
		}
		mask = *(_QWORD*)aMask;
		aMask += 0x28i64;
		v602 = *(stru_602**)((char*)&bb602->parent + mask);
		root_item602 = (stru_602*)((char*)aaa602 + mask);
		item602 = *(stru_602**)((char*)&aaa602->parent + mask);
		v53 = (stru_602**)((char*)&aaa602->parent + mask);
		if (item602){
			// BOOL __fastcall dtor_0x60(stru_602 *aroot)
			g_dtor_0x60(item602);
			root_item602 = (stru_602*)v53;
		}
		if (v602){
			// stru_602 *__fastcall ctor_0x60(QWORD asize, DWORD a2, signed __int64 aMask, stru_602 *aRoot, int acount)
			g_ctor_0x60(v602->size, v602->arg2, v602->mask, root_item602, v602->count);
			// __int64 __fastcall fn_0_0x60(stru_602 *a1, stru_602 *a2, int aRemove)
			g_fn_0_0x60(*(stru_602**)((char*)&bb602->parent + mask), *v53, 0);
		}
		goto LABEL_24;
	}
	a602_src = b602;
LABEL_46:
	memcpy(a602, a602_src, size);
}
__int64 __fastcall fn_02_obj1(QWORD* src, __int64 a2, int aAllocNew){
	__int64 v3; // rsi
	__int64 v5; // rbp
	char* v6; // rdi
	__int64 v7; // rax
	stru_602* v8; // rdi
	stru_602* v9; // rbp

	v3 = 0i64;
	if (!src)
		return v3;
	if (!a2)
		return v3;
	v5 = *((int*)src - 0xC);
	v6 = (char*)(a2 - 0x30);
	if ((_DWORD)v5 != *(_DWORD*)(a2 - 0x30))
		return v3;
	if (aAllocNew){
		v6 = (char*)fn_alloc_obj1(src[-5], src[-2], *((_DWORD*)src - 2), (QWORD*)src[-4], *((void***)v6 + 3)) - 48;
		*(_DWORD*)v6 = v5;
	}
	if ((int)v5 > 1)
		memcpy((void*)(*((_QWORD*)v6 + 3) + 8i64), (const void*)(src[-3] + 8), 8 * v5);
	v7 = src[-2];
	if (v7 != *((_QWORD*)v6 + 4))
		return v3;
	if (src[-4]){
		v8 = (stru_602*)(v6 + 0x30);
		v9 = (stru_602*)src;
		if (v7 > 0){
			do{
				stu602_cpy(v8, src[-5], src[-4], v9);
				v9 = (stru_602*)((char*)v9 + src[-5]);
				v8 = (stru_602*)((char*)v8 + src[-5]);
				LODWORD(v3) = v3 + 1;
			} while ((int)v3 < (__int64)src[-2]);
		}
	} else{
		memcpy(v6 + 0x30, src, v7 * src[-5]);
	}
	return 1i64;
}
BOOL __fastcall fn_free_obj1(stru_602* a1){
	return fn_free_obj1_(a1);
}

void __fastcall initMainVT(){
	// void *__fastcall fn_alloc_obj1(QWORD aElSize, QWORD aCnt, int a3, QWORD *aMask, void **aResult)
	g_fn_alloc_obj1 = fn_alloc_obj1;
	g_fn_01_obj1 = fn_01_obj1;
	g_fn_02_obj1 = fn_02_obj1;
	g_fn_free_obj1 = fn_free_obj1;
}

void __fastcall EnterCriticalSection_stru60(stru_0x60* a1){
	EnterCriticalSection(&a1->lpCriticalSection);
	a1->fld05 = 0i64;
}
QWORD __fastcall stru60_getnotempty(stru_0x60* a1, __int64* aOUT){
	QWORD v3; // rbx
	signed __int64 fld05_idx; // r8
	QWORD mem; // rax
	_QWORD* v6; // rdx
	QWORD fld03; // rax

	v3 = 0i64;
	do{
		fld05_idx = a1->fld05;
		if (fld05_idx < 0)
			break;
		if (fld05_idx >= (signed __int64)a1->qallocatedx8)
			break;
		mem = a1->mem;
		v6 = *(_QWORD**)(mem + 8 * fld05_idx);
		if (v6){
			if (*v6){
				v3 = *(_QWORD*)(mem + 8 * fld05_idx);
				*aOUT = fld05_idx;
			}
		}
		++a1->fld05;
	} while (!v3);

	if (v3)
		return v3;

	fld03 = a1->fld03;
	if (!fld03 || (v3 = fld03 + 16, *aOUT = fld03 + 16, fld03 == -16i64))
		LeaveCriticalSection(&a1->lpCriticalSection);
	return v3;
}
void __fastcall free_stru60(stru_0x60* a1){
	__int64 out; // [rsp+30h] [rbp+8h] BYREF

	if (a1->fn_free){
		EnterCriticalSection_stru60(a1);
		while (stru60_getnotempty(a1, &out))
			((void(__fastcall*)(__int64))a1->fn_free)(out);
	}
}
__int64 __fastcall stru60_get_at(stru_0x60* a1, __int64 aAT){
	EnterCriticalSection(&a1->lpCriticalSection);
	if (aAT >= 0 && aAT < (signed __int64)a1->qallocatedx8)
		aAT = *(_QWORD*)(a1->mem + 8 * aAT);
	LeaveCriticalSection(&a1->lpCriticalSection);
	if (aAT)
		return -(__int64)(*(_QWORD*)aAT != 0i64) & aAT;
	return aAT;
}
__int64 __fastcall MyWriteFile(file_holder* a1){
	DWORD NumberOfBytesWritten; // [rsp+40h] [rbp+8h] BYREF

	NumberOfBytesWritten = 0;
	if (a1->doSeek)
		return 0i64;

	//WriteFile(a1->handle, a1->lpBuffer, a1->alloc_size - a1->seekpos, &NumberOfBytesWritten, 0i64);
	printf("WriteFile %d\n", a1->alloc_size - a1->seekpos);
	WriteFile(a1->handle, a1->lpBuffer, a1->alloc_size - a1->seekpos, &NumberOfBytesWritten, 0i64);

	a1->seekpos = a1->alloc_size;
	return (int)NumberOfBytesWritten;
}
BOOL __fastcall del_fr_tree(stru0x20** a1, HANDLE* hObject){
	stru0x20* v2; // rdx
	stru0x20* left; // rax

	v2 = (stru0x20*)(hObject - 2);
	left = v2->left;
	if (*a1 == v2){
		*a1 = left;
		if (v2->left)
			v2->left->right = 0i64;
	} else{
		v2->right->left = left;
		if (v2->left)
			v2->left->right = v2->right;
	}
	return HeapFree(g_DATA.g_hHeap, 0, v2);
}
void __fastcall stru60_zeroAt(stru_0x60* a1, __int64 aAT){
	void* v4; // rcx

	EnterCriticalSection(&a1->lpCriticalSection);
	if (aAT < 0 || aAT >= (signed __int64)a1->qallocatedx8){
		del_fr_tree((stru0x20**)&a1->fld03, (HANDLE*)aAT);
	} else{
		v4 = *(void**)(a1->mem + 8 * aAT);
		if (v4)
			memset(v4, 0, (int)a1->itemsize);
	}
	LeaveCriticalSection(&a1->lpCriticalSection);
}
void __fastcall fn_free_obj_0x60_0(__int64 aAT){
	file_holder* file_holder_0; // rax
	file_holder* file_holder_1; // rbx

	if (aAT == -1){
		free_stru60(g_stru_0x60_10);
	} else{
		file_holder_0 = (file_holder*)stru60_get_at(g_stru_0x60_10, aAT);
		file_holder_1 = file_holder_0;
		if (file_holder_0){
			if (file_holder_0->lpBuffer){
				MyWriteFile(file_holder_0);
				HeapFree(g_DATA.g_hHeap, 0, (LPVOID)file_holder_1->lpBuffer);
			}
			CloseHandle(file_holder_1->handle);
			stru60_zeroAt(g_stru_0x60_10, aAT);
		}
	}
}
stru_0x60* __fastcall ctor_0x60_0(int aitemsize, int an, __int64 fn_free){
	QWORD elements; // rsi
	stru_0x60* mem; // rax
	stru_0x60* mem_1; // r14

	elements = an;
	mem = (stru_0x60*)HeapAlloc(g_DATA.g_hHeap, HEAP_ZERO_MEMORY, 0x60ui64);
	mem->fld03 = 0i64;
	mem->itemsize = aitemsize;
	mem->fn_free = fn_free;
	mem->sizex8 = elements;
	mem->qallocatedx8 = elements;
	mem_1 = mem;
	mem->mem = (QWORD)HeapAlloc(g_DATA.g_hHeap, HEAP_ZERO_MEMORY, 8 * elements);
	InitializeCriticalSection(&mem_1->lpCriticalSection);
	return mem_1;
}
void __stdcall init_g_stru_0x60_10(){
	g_stru_0x60_10 = ctor_0x60_0(0x28, 0x10, (__int64)fn_free_obj_0x60_0);
}

void INIT_TREE_ROOT(){
	InitializeCriticalSection(&g_treeCritSect);
	g_TREE_ROOT = 0i64;
}

__int64 __stdcall sub_140011A88(__int64 a1, void (*a2)(void), _QWORD* a3){
	((void(__fastcall*)(__int64))a2)(a1);
	*a3 = 4i64;
	return 1i64;
}
void __fastcall DOInitOnceExecuteOnce(void* a1, void (*a2)(void)){
	int v4; // ebp
	HMODULE LibraryW; // rax
	HMODULE v6; // rbx
	BOOL(__stdcall * InitOnceExecuteOnce)(PINIT_ONCE, PINIT_ONCE_FN, PVOID, LPVOID*); // rax
	signed __int32 v8; // eax
	LPVOID v9; // [rsp+50h] [rbp+18h] BYREF

	v4 = 0;
	LibraryW = LoadLibraryW(L"Kernel32.dll");
	v6 = LibraryW;
	if (!LibraryW)
		goto LABEL_5;
	InitOnceExecuteOnce = (BOOL(__stdcall*)(PINIT_ONCE, PINIT_ONCE_FN, PVOID, LPVOID*))GetProcAddress(
		LibraryW,
		"InitOnceExecuteOnce");
	if (InitOnceExecuteOnce){
		InitOnceExecuteOnce((PINIT_ONCE)a1, (PINIT_ONCE_FN)sub_140011A88, a2, &v9);
		v4 = 1;
	}
	FreeLibrary(v6);
	if (!v4){
LABEL_5:
		v8 = _InterlockedCompareExchange((volatile signed __int32*)a1, 1, 0);
		if (v8){
			if (v8 == 1){
				while (*(_DWORD*)a1 != 2)
					Sleep(0);
			}
		} else{
			a2();
			_InterlockedExchange((volatile __int32*)a1, 2);
		}
	}
}
void* __fastcall TREE_iter(__int64 asize_plus_0x10, unsigned int asize, unsigned int aitems, int aFlags){
	void* Result; // rbx
	unsigned int v6; // edi
	QWORD sizePLS_0x18; // rsi
	unsigned int v8; // ecx
	myV10_0x28* i; // rax
	myV10_0x28* v10; // rdi
	myV10_0x28* LAST; // rax
	myV10_0x28* v12; // rax
	myV13_0x60* v13; // rax

	Result = 0i64;
	v6 = aFlags & 3;
	sizePLS_0x18 = asize_plus_0x10 + 8;
	v8 = ((_BYTE)asize_plus_0x10 + 8) & 7;
	if (v8)
		sizePLS_0x18 += 8i64 - v8;
	if ((aFlags & 4) != 0){
		//INIT_ONCE_STATIC_INIT
		DOInitOnceExecuteOnce(&g_qword_140021058, INIT_TREE_ROOT);
		EnterCriticalSection(&g_treeCritSect);
		for (i = (myV10_0x28*)g_TREE_ROOT; i; i = (myV10_0x28*)i->parent){
			if (i->size_plus == sizePLS_0x18 && i->aFlags == aFlags){
				Result = (void*)i->right;
				++i->nn;
				if (Result)
					goto LABEL_15;
				break;
			}
		}
		v10 = (myV10_0x28*)HeapAlloc(g_DATA.g_hHeap, 0, 0x28ui64);
		if (v10){
			LAST = (myV10_0x28*)TREE_iter(sizePLS_0x18 - 8, asize, aitems, aFlags & 0xFFFFFFFB);
			Result = LAST;
			if (LAST){
				LAST->right = (QWORD)v10;
				v10->left = 0i64;
				v10->right = (QWORD)LAST;
				v12 = (myV10_0x28*)g_TREE_ROOT;
				v10->size_plus = sizePLS_0x18;
				v10->aFlags = aFlags;
				v10->nn = 1;
				v10->parent = (QWORD)v12;
				if (v12)
					v12->left = (QWORD)v10;
				g_TREE_ROOT = (__int64)v10;
			}
		}
LABEL_15:
		LeaveCriticalSection(&g_treeCritSect);
	} else{
		v13 = (myV13_0x60*)HeapAlloc(g_DATA.g_hHeap, 0, 0x60ui64);
		Result = v13;
		if (v13){
			v13->f0 = 0i64;
			v13->f1 = 0i64;
			v13->f2 = 0i64;
			v13->sizePlsu0x18 = sizePLS_0x18;
			v13->size = asize;
			v13->items = aitems;
			if (v6 <= 1){
				v13->CS_initialized = 1;
				InitializeCriticalSection(&v13->CS);
			} else{
				v13->CS_initialized = 0;
			}
		}
	}
	return Result;
}
stru_601* __fastcall ctor_0x60_2(__int64 aSize, root_601** root, signed __int64* aMASK, DWORD a4){
	stru_601* mem; // rax
	stru_601* itm; // rdi
	void* p; // rax
	__int64 size_plus_0x10; // rbx
	BYTE v12; // al

	mem = (stru_601*)HeapAlloc(g_DATA.g_hHeap, 0, 0x60ui64);
	itm = mem;
	if (root){
		mem->DoHeapAlloc = 0;
	} else{
		p = HeapAlloc(g_DATA.g_hHeap, 0, 0x10ui64);
		itm->DoHeapAlloc = 1;
		root = (root_601**)p;
	}
	itm->f2 = 0i64;
	itm->f0 = 0i64;
	itm->f1 = 0i64;
	itm->f4 = 0i64;
	size_plus_0x10 = aSize + 0x10;
	itm->size_plus_0x10 = size_plus_0x10;
	itm->aMASK = (QWORD)aMASK;
	itm->root_next = (root_601*)(root + 1);
	itm->f5c = 1;
	itm->arg4 = a4;
	v12 = mask_walk(aMASK);
	itm->f8 = 0i64;
	itm->proot = (root_601*)root;
	itm->maskwalk = v12;
	*root = (root_601*)itm;
	itm->treeIter = (QWORD)TREE_iter(size_plus_0x10, 0x10u, 0x10000u, 4);
	return itm;
}
void __fastcall treeIter_dtor_todo(myV13_0x60* atreeIter, QWORD* a2){
	QWORD* v4; // r8
	int v5; // eax
	QWORD v6; // rcx
	QWORD v7; // rax
	QWORD v8; // rax
	QWORD f1; // rax

	if (atreeIter->CS_initialized)
		EnterCriticalSection(&atreeIter->CS);

	v4 = (QWORD*)*(a2 - 1);
	*(a2 - 1) = v4[2];
	v5 = *((_DWORD*)v4 + 7);
	++* ((_DWORD*)v4 + 8);
	v4[2] = (QWORD)(a2 - 1);
	if (*((_DWORD*)v4 + 8) == v5){
		v6 = *v4;
		if (*((_DWORD*)v4 + 6) == 1){
			if (v6)
				*(_QWORD*)(v6 + 8) = v4[1];
			v7 = *v4;
			if (v4 == (QWORD*)atreeIter->f0){
				atreeIter->f0 = v7;
LABEL_14:
				atreeIter->f3 -= *((int*)v4 + 6);
				HeapFree(g_DATA.g_hHeap, 0, v4);
				goto LABEL_24;
			}
		} else{
			if (v6)
				*(_QWORD*)(v6 + 8) = v4[1];
			v7 = *v4;
			if (v4 == (QWORD*)atreeIter->f1){
				atreeIter->f1 = v7;
				goto LABEL_14;
			}
		}
		*(_QWORD*)v4[1] = v7;
		goto LABEL_14;
	}
	if (*((_DWORD*)v4 + 8) == 1 && v5 >= *((_DWORD*)v4 + 6)){
		if (*v4)
			*(_QWORD*)(*v4 + 8) = v4[1];
		v8 = *v4;
		if (v4 == (QWORD*)atreeIter->f0)
			atreeIter->f0 = v8;
		else
			*(_QWORD*)v4[1] = v8;
		f1 = atreeIter->f1;
		v4[1] = 0i64;
		*v4 = f1;
		atreeIter->f1 = (QWORD)v4;
		if (*v4)
			*(_QWORD*)(*v4 + 8) = v4;
	}
LABEL_24:

	if (atreeIter->CS_initialized)
		LeaveCriticalSection(&atreeIter->CS);
}
root_601* __fastcall stru601_dtor(stru_601* as601){
	__int64 aMASK; // rsi
	QWORD* f0; // rdi
	QWORD* v4; // rbp
	QWORD* v5; // rdx
	root_601* result; // rax

	aMASK = as601->aMASK;
	f0 = (QWORD*)as601->f0;
	if (aMASK){
		while (1){
			v4 = f0;
			if (!f0)
				break;
			f0 = (QWORD*)*f0;
			dtor_by_MASK((stru_602*)(v4 + 2), aMASK);
			treeIter_dtor_todo((myV13_0x60*)as601->treeIter, v4);
		}
	} else{
		while (1){
			v5 = f0;
			if (!f0)
				break;
			f0 = (QWORD*)*f0;
			treeIter_dtor_todo((myV13_0x60*)as601->treeIter, v5);
		}
	}
	as601->f2 = 0i64;
	result = as601->root_next;
	result->left = 0i64;
	as601->f0 = 0i64;
	as601->f1 = 0i64;
	as601->f4 = 0i64;
	as601->f5c = 1;
	return result;
}
QWORD* __fastcall fn_myv13(myV13_0x60* myv13){
	QWORD* f2; // rsi
	stru_602* f1; // rbx
	int mask; // ecx
	__int64 subitems_10PlsSize_high; // rdx
	stru_602* parent; // rax
	stru_602* f0; // rax
	int size; // ebp
	__int64 v9; // rax
	stru_602* v10; // rax
	stru_602* v11; // rax
	bool v12; // cc
	stru_602* v13; // rax
	stru_602* v14; // rax

	f2 = 0i64;
	if (myv13->CS_initialized)
		EnterCriticalSection(&myv13->CS);
	f1 = (stru_602*)myv13->f1;
	if (f1){
		mask = f1->mask;
		if (mask <= 0){
			subitems_10PlsSize_high = SHIDWORD(f1->subitems_10PlsSize);
			f2 = (QWORD*)((char*)&f1->blockIdx + subitems_10PlsSize_high * myv13->sizePlsu0x18);
			HIDWORD(f1->subitems_10PlsSize) = subitems_10PlsSize_high + 1;
		} else{
			f2 = (QWORD*)f1->f2;
			f1->f2 = *f2;
			LODWORD(f1->mask) = mask - 1;
		}
		if (!LODWORD(f1->mask) && SHIDWORD(f1->subitems_10PlsSize) >= SLODWORD(f1->subitems_10PlsSize)){
			if (f1->parent)
				f1->parent->subitems_8xcount = f1->subitems_8xcount;
			parent = f1->parent;
			if (f1 == (stru_602*)myv13->f1)
				myv13->f1 = (QWORD)parent;
			else
				*(_QWORD*)f1->subitems_8xcount = parent;
			f0 = (stru_602*)myv13->f0;
			f1->subitems_8xcount = 0i64;
			f1->parent = f0;
			myv13->f0 = (QWORD)f1;
			if (f1->parent)
				f1->parent->subitems_8xcount = (QWORD)f1;
		}
	} else{
		size = myv13->size;
		v9 = ((__int64)myv13->f3 >> 4) & 0xFFFFFFF0i64;
		if ((int)v9 >= size){
			size = ((__int64)myv13->f3 >> 4) & 0xFFFFFFF0;
			if ((int)v9 > (signed int)myv13->items)
				size = myv13->items;
		}
		v10 = (stru_602*)HeapAlloc(g_DATA.g_hHeap, 0, myv13->sizePlsu0x18 * size + 0x28);
		f1 = v10;
		if (v10){
			LODWORD(v10->subitems_10PlsSize) = size;
		} else{
			v11 = (stru_602*)HeapAlloc(g_DATA.g_hHeap, 0, myv13->sizePlsu0x18 + 0x28);
			f1 = v11;
			if (!v11)
				goto LABEL_29;
			LODWORD(v11->subitems_10PlsSize) = 1;
		}
		myv13->f3 += SLODWORD(f1->subitems_10PlsSize);
		LODWORD(f1->mask) = 0;
		f1->f2 = 0i64;
		v12 = SLODWORD(f1->subitems_10PlsSize) <= 1;
		HIDWORD(f1->subitems_10PlsSize) = 1;
		if (v12){
			v14 = (stru_602*)myv13->f0;
			f1->subitems_8xcount = 0i64;
			f1->parent = v14;
			myv13->f0 = (QWORD)f1;
		} else{
			v13 = (stru_602*)myv13->f1;
			f1->subitems_8xcount = 0i64;
			f1->parent = v13;
			myv13->f1 = (QWORD)f1;
		}
		if (f1->parent)
			f1->parent->subitems_8xcount = (QWORD)f1;
		f2 = (QWORD*)&f1->blockIdx;
	}
LABEL_29:
	if (myv13->CS_initialized)
		LeaveCriticalSection(&myv13->CS);
	if (!f2)
		return 0i64;
	*f2 = (QWORD)f1;
	return f2 + 1;
}
stru_602* __fastcall fn_stru601(stru_601* a601){
	stru_602* result; // rax
	stru_602* v3; // rdi
	QWORD f2; // rax
	stru_602* f0; // rax
	QWORD v6; // rax
	stru_602* s602; // rcx

	result = (stru_602*)fn_myv13((myV13_0x60*)a601->treeIter);
	v3 = result;
	if (!result)
		return result;
	memset(result, 0, a601->size_plus_0x10);

	if (a601->maskwalk)
		ctor_c602((stru_602*)&v3->f2, (__int64*)a601->aMASK);

	f2 = a601->f2;
	++a601->f4;
	if (f2){
		v3->subitems_8xcount = f2;
		v3->parent = *(stru_602**)a601->f2;
		v6 = a601->f2;
		if (*(_QWORD*)v6)
			*(_QWORD*)(*(_QWORD*)v6 + 8i64) = v3;
		*(_QWORD*)a601->f2 = v3;
		++a601->f5;
		a601->f2 = (QWORD)v3;
	} else{
		if (a601->f0)
			*(_QWORD*)(a601->f0 + 8) = v3;
		f0 = (stru_602*)a601->f0;
		a601->f2 = (QWORD)v3;
		v3->subitems_8xcount = 0i64;
		v3->parent = f0;
		a601->f5 = 0i64;
		a601->f5c = 0;
	}

	s602 = (stru_602*)a601->f2;
	if (!s602->subitems_8xcount)
		a601->f0 = (QWORD)s602;
	if (!s602->parent)
		a601->f1 = (QWORD)s602;
	a601->root_next->left = (QWORD)s602;
	return (stru_602*)&v3->f2;
}
__int64 __fastcall fn_0x60_2(char** a1, stru_601* a601, int aRemove){
	__int64 v3; // rbx
	__int64* i; // rdi
	stru_602* s602; // rax

	v3 = 0i64;
	if (!a1)
		return v3;
	if (!a601)
		return v3;
	if (aRemove)
		stru601_dtor(a601);
	for (i = (__int64*)*a1; i; i = (__int64*)*i){
		s602 = fn_stru601(a601);
		stu602_cpy(s602, (QWORD)(a1[0xA] - 0x10), (signed __int64)a1[6], (stru_602*)(i + 2));
	}
	return 1i64;
}
void __fastcall free_myV13_0x60(myV13_0x60* aVal){
	_QWORD* f1; // r8
	_QWORD* v3; // rbx
	_QWORD* f0; // r8
	_QWORD* v5; // rbx

	if (aVal->CS_initialized)
		EnterCriticalSection(&aVal->CS);
	f1 = (_QWORD*)aVal->f1;
	if (f1){
		do{
			v3 = (_QWORD*)*f1;
			HeapFree(g_DATA.g_hHeap, 0, f1);
			f1 = v3;
		} while (v3);
	}
	f0 = (_QWORD*)aVal->f0;
	if (aVal->f0){
		do{
			v5 = (_QWORD*)*f0;
			HeapFree(g_DATA.g_hHeap, 0, f0);
			f0 = v5;
		} while (v5);
	}
	aVal->f0 = 0i64;
	aVal->f1 = 0i64;
	aVal->f3 = 0i64;
	if (aVal->CS_initialized)
		LeaveCriticalSection(&aVal->CS);
}
void __fastcall dtor_TREES(void* aa){
	union subs a1;
	a1.a = aa;
	myV10_0x28* right; // rdi
	_QWORD* left; // rcx

	right = (myV10_0x28*)a1.b->right;
	if (right){
		EnterCriticalSection(&g_treeCritSect);
		if ((int)-- * (_DWORD*)(a1.b->right + 0x24) <= 0){
			a1.a->f2 = 0i64;
			dtor_TREES(a1.a);
			if (right->parent)
				*(_QWORD*)(right->parent + 8) = right->left;
			left = (_QWORD*)right->left;
			if (left)
				*left = right->parent;
			if ((myV10_0x28*)g_TREE_ROOT == right)
				g_TREE_ROOT = right->parent;
			HeapFree(g_DATA.g_hHeap, 0, right);
		}
		LeaveCriticalSection(&g_treeCritSect);
	} else{
		free_myV13_0x60(a1.a);
		if (a1.a->CS_initialized)
			DeleteCriticalSection(&a1.a->CS);
		HeapFree(g_DATA.g_hHeap, 0, a1.a);
	}
}
BOOL __fastcall dtor_0x60_2(stru_601* lpMem){
	_QWORD* f8; // r8
	_QWORD* v3; // rbx
	BOOL result; // eax

	if (!lpMem)
		return 0;
	stru601_dtor(lpMem);
	dtor_TREES((void*)lpMem->treeIter);
	lpMem->proot->left = 0i64;
	lpMem->proot->right = 0i64;
	f8 = (_QWORD*)lpMem->f8;
	if (f8){
		do{
			v3 = (_QWORD*)*f8;
			HeapFree(g_DATA.g_hHeap, 0, f8);
			f8 = v3;
		} while (v3);
	}
	if (lpMem->DoHeapAlloc)
		HeapFree(g_DATA.g_hHeap, 0, lpMem->proot);
	return HeapFree(g_DATA.g_hHeap, 0, lpMem);
}

void __stdcall init_VT_0x60_2(){
	g_ctor_0x60_2 = ctor_0x60_2;
	g_fn_0x60_2 = (__int64(__fastcall*)(_QWORD, _QWORD, _QWORD))fn_0x60_2;
	g_dtor_0x60_2 = (__int64(__fastcall*)(_QWORD))dtor_0x60_2;
}

void __fastcall s602_reset_parent(stru_602* aroot){
	aroot->parent = 0i64;
	aroot->blockIdx = 0xFFFFFFFF;
}
QWORD* __fastcall s602_get_parent_f2(stru_602* aroot){
	stru_602* p0; // rax
	DWORD blockIdx; // edx
	int v3; // eax
	QWORD v4; // r8
	_QWORD* v5; // rdx
	stru_602* v6; // rdx
	stru_602* p1; // rax
	int v9; // edx
	QWORD subitems_8xcount; // r9
	_QWORD* v11; // r8

	p0 = aroot->parent;
	blockIdx = aroot->blockIdx;
	aroot->f2 = (QWORD)aroot->parent;
	aroot->f2C = blockIdx;
	if (p0){
		p1 = p0->parent;
		aroot->parent = p1;
		if (p1)
			return &aroot->parent->f2;
		v9 = blockIdx + 1;
		aroot->blockIdx = v9;
		if (v9 < aroot->count){
			subitems_8xcount = aroot->subitems_8xcount;
			v11 = (_QWORD*)(subitems_8xcount + 8i64 * v9);
			while (!*v11){
				++v9;
				++v11;
				if (v9 >= aroot->count)
					goto LABEL_7;
			}
			aroot->blockIdx = v9;
			v6 = *(stru_602**)(subitems_8xcount + 8i64 * v9);
			goto LABEL_8;
		}
	} else{
		if (blockIdx != -1u)
			goto LABEL_9;
		aroot->blockIdx = 0;
		v3 = 0;
		if (aroot->count > 0){
			v4 = aroot->subitems_8xcount;
			v5 = (_QWORD*)v4;
			while (!*v5){
				++v3;
				++v5;
				if (v3 >= aroot->count)
					goto LABEL_7;
			}
			aroot->blockIdx = v3;
			v6 = *(stru_602**)(v4 + 8i64 * v3);
			goto LABEL_8;
		}
	}
LABEL_7:
	v6 = 0i64;
LABEL_8:
	aroot->parent = v6;
LABEL_9:
	if (!aroot->parent)
		return 0i64;
	return &aroot->parent->f2;
}
void __fastcall dtor_s602(stru_602* aroot){
	__int64 aMASK; // rsi
	myV13_0x60* treeIter; // rcx
	QWORD* parent_f2; // rax
	QWORD* v5; // rdi
	QWORD v6; // [rsp+20h] [rbp-18h] BYREF

	aMASK = aroot->mask;
	s602_reset_parent(aroot);
	while (1){
		parent_f2 = s602_get_parent_f2(aroot);
		v5 = parent_f2;
		if (!parent_f2)
			break;
		if ((aroot->mask_walk_res & 0x400000000i64) == 0)
			// subitems_8xcount
			HeapFree(g_DATA.g_hHeap, 0, (LPVOID)parent_f2[-1]);
		if (aMASK)
			dtor_by_MASK((stru_602*)v5, aMASK);
		treeIter = (myV13_0x60*)aroot->treeIter;
		v6 = v5[-2];
		aroot->parent = (stru_602*)&v6;
		treeIter_dtor_todo(treeIter, v5 - 2);
	}
	memset((void*)aroot->subitems_8xcount, 0, 8 * aroot->count);
	s602_reset_parent(aroot);
	LODWORD(aroot->mask_walk_res) = 0;
}
BOOL __fastcall dtor_0x60(stru_602* aroot){
	_QWORD* f10; // r8
	_QWORD* v3; // rbx
	BOOL result; // eax

	if (!aroot)
		return 0;
	dtor_s602(aroot);
	//dtor_TREES((subs)aroot->treeIter);
	dtor_TREES((void*)aroot->treeIter);
	HeapFree(g_DATA.g_hHeap, 0, (LPVOID)aroot->subitems_8xcount);
	HeapFree(g_DATA.g_hHeap, 0, (LPVOID)aroot->subitems_10PlsSize);
	f10 = (_QWORD*)aroot->f10;
	if (f10){
		do{
			v3 = (_QWORD*)*f10;
			HeapFree(g_DATA.g_hHeap, 0, f10);
			f10 = v3;
		} while (v3);
	}
	aroot->root->parent = 0i64;
	return HeapFree(g_DATA.g_hHeap, 0, aroot);
}
stru_602* __fastcall fn_602_index_todo(stru_602* a601, __int64 a2){
	__int64 v3; // rdx
	stru_602* result; // rax

	v3 = a2 % a601->count;
	for (result = *(stru_602**)(a601->subitems_8xcount + 8 * v3); result; result = result->parent){
		if (result->subitems_8xcount == a2){
			a601->parent = result;
			a601->blockIdx = v3;
			return (stru_602*)((char*)result + 0x10);
		}
		a601->f2 = (QWORD)result;
	}
	return result;
}
stru_602* __fastcall stu602_idx_f2(stru_602* a602, __int64 aIdx, int aRemove){
	stru_602* v5; // rax
	stru_602* p_f2; // rbx
	__int64 mask; // rdx
	__int64 v8; // rbp
	stru_602* v9; // rax

	if (aRemove == 1 && (v5 = fn_602_index_todo(a602, aIdx), (p_f2 = v5) != 0i64)){
		mask = a602->mask;
		if (mask)
			dtor_by_MASK(v5, mask);
	} else{
		v8 = aIdx % a602->count;
		v9 = (stru_602*)fn_myv13((myV13_0x60*)a602->treeIter);
		p_f2 = v9;
		if (!v9)
			return p_f2;
		v9->subitems_8xcount = aIdx;
		v9->parent = *(stru_602**)(a602->subitems_8xcount + 8i64 * (unsigned int)v8);
		*(_QWORD*)(a602->subitems_8xcount + 8i64 * (unsigned int)v8) = v9;
		a602->f2 = 0i64;
		++LODWORD(a602->mask_walk_res);
		a602->parent = v9;
		a602->blockIdx = v8;
		p_f2 = (stru_602*)&v9->f2;
	}
	if (!p_f2)
		return p_f2;
	memset(p_f2, 0, SLODWORD(a602->size));
	if ((a602->mask_walk_res & 0x200000000i64) != 0)
		ctor_c602(p_f2, (__int64*)a602->mask);
	return p_f2;
}
__int64 __fastcall str_hash_65599_lower(unsigned __int16* awstr){
	unsigned __int16* iter; // rdi
	int chr; // ecx
	unsigned int i; // ebx
	int v4; // eax

	iter = awstr;
	chr = *awstr;
	i = 0;
	while (1){
		v4 = tolower(chr);
		if (!v4)
			break;
		++iter;
		i = v4 + 65599 * i;
		chr = *iter;
	}
	return i;
}
__int64 __fastcall str_hash_65599(_WORD* awstr){
	__int64 result; // rax
	int chr; // edx

	for (result = 0i64; ; result = (unsigned int)(chr + 65599 * result)){
		chr = (unsigned __int16)*awstr;
		if (!*awstr)
			break;
		++awstr;
	}
	return result;
}

__int64* __fastcall stu602_get_by_name(stru_602* a602, unsigned __int16* awstr){
	unsigned __int16* v2; // rsi
	unsigned int sum_lower; // eax
	QWORD v5; // rdi
	int blockIdx; // ebp
	unsigned int sum; // eax

	v2 = (unsigned __int16*)&nullstr;
	if (awstr)
		v2 = awstr;
	if ((a602->mask_walk_res & 0x100000000i64) != 0){
		sum_lower = str_hash_65599_lower(v2);
		v5 = *(_QWORD*)(a602->subitems_8xcount + 8i64 * (sum_lower % a602->count));
		blockIdx = sum_lower % a602->count;
		while (v5){
			if (!wcsicmp(*(const wchar_t**)(v5 + 8), v2))
				goto LABEL_9;
			a602->f2 = v5;
			v5 = *(_QWORD*)v5;
		}
	} else{
		sum = str_hash_65599(v2);
		v5 = *(_QWORD*)(a602->subitems_8xcount + 8i64 * (sum % a602->count));
		blockIdx = sum % a602->count;
		while (v5){
			if (!wcscmp(*(const wchar_t**)(v5 + 8), v2)){
LABEL_9:
				a602->blockIdx = blockIdx;
				a602->parent = (stru_602*)v5;
				return (__int64*)(v5 + 0x10);
			}
			a602->f2 = v5;
			v5 = *(_QWORD*)v5;
		}
	}
	return 0i64;
}
stru_602* __fastcall stu602_add(stru_602* a602, wchar_t* awstr, int aRemove){
	__int64* v5; // rax
	stru_602* v6; // rdi
	__int64 mask; // rdx
	unsigned __int16* wstr; // rsi
	unsigned int sum; // eax
	unsigned int idx; // ebp
	size_t v11; // rax
	wchar_t* v12; // rax

	if (aRemove == 1){
		v5 = stu602_get_by_name(a602, awstr);
		v6 = (stru_602*)v5;
		if (v5){
			mask = a602->mask;
			if (mask)
				dtor_by_MASK((stru_602*)v5, mask);
			goto LABEL_12;
		}
	}
	wstr = (unsigned __int16*)&nullstr;
	if (awstr)
		wstr = awstr;
	if ((a602->mask_walk_res & 0x100000000i64) != 0)
		sum = str_hash_65599_lower(wstr);
	else
		sum = str_hash_65599(wstr);

	idx = sum % a602->count;
	v6 = (stru_602*)fn_myv13((myV13_0x60*)a602->treeIter);
	if (!v6)
		return v6;

	v11 = wcslen(wstr);
	v12 = (wchar_t*)HeapAlloc(g_DATA.g_hHeap, 0, 2 * v11 + 2);
	v6->subitems_8xcount = (QWORD)v12;
	wcscpy(v12, wstr);
	v6->parent = *(stru_602**)(a602->subitems_8xcount + 8i64 * idx);
	*(_QWORD*)(a602->subitems_8xcount + 8i64 * idx) = v6;
	a602->f2 = 0i64;
	++LODWORD(a602->mask_walk_res);
	a602->parent = v6;
	a602->blockIdx = idx;
	v6 = (stru_602*)((char*)v6 + 0x10);
LABEL_12:
	if (!v6)
		return v6;
	memset(v6, 0, SLODWORD(a602->size));
	if ((a602->mask_walk_res & 0x200000000i64) != 0)
		ctor_c602(v6, (__int64*)a602->mask);
	return v6;
}
__int64 __fastcall fn_0_0x60(stru_602* a1, stru_602* a2, int aRemove){
	__int64 v3; // rdi
	stru_602* parent; // r14
	DWORD blockIdx; // r15d
	wchar_t* wstr; // rdx
	stru_602* v9; // rax
	QWORD* parent_f2; // rax
	stru_602* v11; // rbp

	v3 = 0i64;
	if (!a1)
		return v3;
	if (!a2)
		return v3;
	parent = a1->parent;
	blockIdx = a1->blockIdx;
	if (aRemove)
		dtor_s602(a2);

	s602_reset_parent(a1);
	while (1){
		parent_f2 = s602_get_parent_f2(a1);
		v11 = (stru_602*)parent_f2;
		if (!parent_f2)
			break;
		wstr = (wchar_t*)parent_f2[-1];

		if ((a1->mask_walk_res & 0x400000000i64) != 0)
			v9 = stu602_idx_f2(a2, (__int64)wstr, 0);
		else
			v9 = stu602_add(a2, wstr, 0);

		stu602_cpy(v9, a1->size, a1->mask, v11);
	}
	a1->parent = parent;
	a1->blockIdx = blockIdx;
	return 1i64;
}
stru_602* __fastcall ctor_0x60(QWORD asize, DWORD a2, signed __int64 aMask, stru_602* aRoot, int acount){
	stru_602* itm; // rdi
	int count; // ebx
	LPVOID v11; // rax
	_QWORD* subitems; // rax

	dtor_0x60(aRoot->parent);
	itm = (stru_602*)HeapAlloc(g_DATA.g_hHeap, 0, 0x60ui64);
	if (!itm)
		return itm;
	count = acount;
	if (acount <= 0)
		count = 1;
	v11 = HeapAlloc(g_DATA.g_hHeap, HEAP_ZERO_MEMORY, 8i64 * count);
	itm->subitems_8xcount = (QWORD)v11;
	if (v11){
		itm->parent = 0i64;
		itm->mask_walk_res = 0i64;
		itm->f10 = 0i64;
		itm->count = count;
		itm->size = asize;
		itm->arg2 = a2;
		itm->mask = aMask;
		itm->root = aRoot;
		if (mask_walk((signed __int64*)aMask))
			HIDWORD(itm->mask_walk_res) |= 2u;
		itm->treeIter = (QWORD)TREE_iter(asize + 0x10, 0x10u, 0x10000u, 4);
		subitems = HeapAlloc(g_DATA.g_hHeap, HEAP_ZERO_MEMORY, asize + 0x10);
		itm->subitems_10PlsSize = (QWORD)subitems;
		subitems[1] = &nullstr;
		aRoot->parent = itm;
	} else{
		HeapFree(g_DATA.g_hHeap, 0, itm);
		return 0i64;
	}
	return itm;
}

void __stdcall init_VT_0x60(){
	g_ctor_0x60 = ctor_0x60;
	g_fn_0_0x60 = fn_0_0x60;
	g_dtor_0x60 = dtor_0x60;
}


void __stdcall ZHeapCreate(){
	G_ZHEAP = (__int64)HeapCreate(0, 0x1000ui64, 0i64);
}
SIZE_T __stdcall ZHeapSize(HANDLE hHeap){
	if (hHeap)
		return HeapSize(G_ZHEAP, 0, hHeap);
	else
		return 0i64;
}
BOOL __stdcall ZHeapFree(HANDLE hHeap){
	return HeapFree(G_ZHEAP, 0, hHeap);
}
LPVOID __stdcall ZHeapAlloc(SIZE_T dwBytes_1){
	if ((__int64)dwBytes_1 <= 0)
		return 0i64;
	else
		return HeapAlloc(G_ZHEAP, 8u, dwBytes_1);
}
SIZE_T __fastcall HeapSize__0(void* a1){
	return ZHeapSize(a1);
}

void __fastcall MyCloseHandle(__int64 aAT){
	file_holder* fileholder; // rax

	fileholder = (file_holder*)stru60_get_at((stru_0x60*)g_stru_0x60_4, aAT);
	if (fileholder){
		CloseHandle(fileholder->handle);
		stru60_zeroAt((stru_0x60*)g_stru_0x60_4, aAT);
	}
}


HANDLE* __fastcall add_to_tree(stru0x20* root, int size){
	stru0x28* mem; // rax

	mem = (stru0x28*)HeapAlloc(g_DATA.g_hHeap, HEAP_ZERO_MEMORY, size);
	if (!mem)
		return &mem->s20.hObject;

	if (root->left){
		root->left->right = &mem->s20;
		mem->s20.left = root->left;
	}
	root->left = &mem->s20;
	return &mem->s20.hObject;
}
char* __fastcall add_to_TLS_8(int aSize, void(__fastcall* aFN)(char*), QWORD a3){
	int aAignSize; // ebx
	int v6; // ecx
	SIZE_T size; // rcx
	void* mem; // rax
	QWORD size_1; // rsi
	void* Value; // rax
	void* mem_1; // rbx
	// unk028 *__shifted(unk028,0x10) v12
	QWORD* v12; // rax

	aAignSize = aSize;
	v6 = aSize & 7;
	if (v6)
		aAignSize += 8 - v6;
	size = g_TLS_8_allocated_size;
	if (!g_TLS_8_allocated_size){
		g_TLS_8 = TlsAlloc();
		mem = HeapAlloc(g_DATA.g_hHeap, HEAP_ZERO_MEMORY, aAignSize);
		TlsSetValue(g_TLS_8, mem);
		size = g_TLS_8_allocated_size;
	}
	size_1 = size;
	g_TLS_8_allocated_size = aAignSize + size;

	Value = TlsGetValue(g_TLS_8);
	mem_1 = HeapReAlloc(g_DATA.g_hHeap, HEAP_ZERO_MEMORY, Value, g_TLS_8_allocated_size);
	TlsSetValue(g_TLS_8, mem_1);

	if (!aFN && !a3)
		return (char*)size_1;

	//v12 = (unk028 * __shifted(unk028, 0x10))add_to_tree((stru0x20*)&g_root_unk028, 0x28);
	//ADJ(v12)->offset = size_1;
	//ADJ(v12)->function = (QWORD)aFN;
	//ADJ(v12)->arg3 = a3;
	v12 = (QWORD*)add_to_tree((stru0x20*)&g_root_unk028, 0x28);
	*v12 = size_1;
	v12[1] = (QWORD)aFN;
	v12[2] = a3;

	if (aFN)
		aFN((char*)mem_1 + size_1);
	return (char*)size_1;
}
void init_g_TLS_8_g_stru60_4(){
	g_TLS_8_pos = add_to_TLS_8(0x18, 0i64, 0i64);
	g_stru_0x60_4 = (__int64)ctor_0x60_0(8, 4, (__int64)MyCloseHandle);
	InitializeCriticalSection(&stru_1400211E0);
}


void __stdcall MyInitCommonControls(){
	INITCOMMONCONTROLSEX picce; // [rsp+30h] [rbp+8h] BYREF

	picce.dwSize = 8;
	picce.dwICC = 0xB48;
	InitCommonControlsEx(&picce);
	CoInitialize(0i64);
}

void InitCriticalSection(){
	InitializeCriticalSection(&CriticalSection);
}

__int64 __fastcall dup_from_STR_tree(LPVOID* a1, int a2){
	void* v2; // rax
	__int64 result; // rax
	int v4; // [rsp+20h] [rbp-18h]
	strNode* Value; // [rsp+28h] [rbp-10h]

	Value = (strNode*)TlsGetValue(g_dwTlsIndex);
	v4 = LODWORD(Value->slen) - a2;
	if (*a1)
		v2 = HeapReAlloc(heap_HANDLE, 0, *a1, v4 + 0xAi64);
	else
		v2 = HeapAlloc(heap_HANDLE, 0, v4 + 0xAi64);
	*a1 = v2;
	wstrcpy(*a1, &Value->str[a2], v4 / 2ui64);

	result = a2;
	Value->slen = a2;

	return result;
}
QWORD __stdcall GET_TLS_StrLen(){
	DWORD dwErrCode; // [rsp+20h] [rbp-28h]
	QWORD* v2; // [rsp+30h] [rbp-18h]

	dwErrCode = GetLastError();
	v2 = (QWORD*)*((_QWORD*)TlsGetValue(g_dwTlsIndex) + 2);
	SetLastError(dwErrCode);
	return (QWORD)v2;
}


BOOL __fastcall rso_call_back(RegSingleObject* rso);
BOOL __fastcall unkfree_fn(LPVOID* a1){
	HeapFree(heap_HANDLE, 0, *a1);
	return HeapFree(heap_HANDLE, 0, a1);
}
void __fastcall Callback(RegSingleObject* a1, char TimerOrWaitFired){
	if (!TimerOrWaitFired)
		rso_call_back(a1);
}
void __fastcall add_to_rso(void* free_fn, unk001* un001){
	RegSingleObject* rso; // rbp
	RegSingleObject* root; // rax
	HANDLE CurrentProcess; // rdi
	HANDLE CurrentThread; // rbx
	HANDLE v8; // rax
	unk001* v9; // rax

	if (!g_tls_rso_init){
		g_TLS_rso = TlsAlloc();
		InitializeCriticalSection(&stru_140021128);
		g_tls_rso_init = 1;
	}
	rso = (RegSingleObject*)TlsGetValue(g_TLS_rso);
	if (!rso){
		rso = (RegSingleObject*)HeapAlloc(g_DATA.g_hHeap, HEAP_ZERO_MEMORY, 0x28ui64);
		if (!rso)
			return;
		EnterCriticalSection(&stru_140021128);
		root = g_RegSingleObject;
		if (g_RegSingleObject)
			g_RegSingleObject->root = rso;
		rso->next = root;
		g_RegSingleObject = rso;
		LeaveCriticalSection(&stru_140021128);
		CurrentProcess = GetCurrentProcess();
		CurrentThread = GetCurrentThread();
		v8 = GetCurrentProcess();
		DuplicateHandle(v8, CurrentThread, CurrentProcess, (LPHANDLE)&rso->lpTargetHandle, 0x100000u, 0, 0);
		RegisterWaitForSingleObject(
			(PHANDLE)&rso->phNewWaitObject,
			rso->lpTargetHandle,
			(WAITORTIMERCALLBACK)Callback,
			rso,
			0xFFFFFFFF,
			WT_EXECUTEONLYONCE);
		TlsSetValue(g_TLS_rso, rso);
	}
	v9 = (unk001*)HeapAlloc(g_DATA.g_hHeap, 0, 0x18ui64);
	if (v9){
		v9->fld02_freefn = free_fn;
		v9->fld03_unk01 = un001;
		v9->fld01_next = rso->fld03_uk01;
		rso->fld03_uk01 = v9;
	}
}

void __stdcall init_RSO(){
	unk001* value1; // rax
	unk001* value2; // rax

	if (g_dwTlsIndex == 0xFFFFFFFF){
		create_and_alloc_STRtree();
		value1 = (unk001*)TlsGetValue(g_dwTlsIndex);
		add_to_rso(unkfree_fn, value1);
	} else if (!TlsGetValue(g_dwTlsIndex)){
		alloc_strNode();
		value2 = (unk001*)TlsGetValue(g_dwTlsIndex);
		add_to_rso(unkfree_fn, value2);
	}
}
BOOL __fastcall rso_call_back(RegSingleObject* rso){
	_QWORD* next; // rdx
	unk001* fld03_uk01; // rsi
	unk001* v4; // rbx

	UnregisterWait(rso->phNewWaitObject);
	CloseHandle(rso->lpTargetHandle);

	EnterCriticalSection(&stru_140021128);
	if (rso->root)
		*(_QWORD*)(rso->root + 8i64) = rso->next;
	else
		g_RegSingleObject = (RegSingleObject*)rso->next;
	next = (_QWORD*)rso->next;
	if (next)
		*next = rso->root;
	LeaveCriticalSection(&stru_140021128);

	fld03_uk01 = rso->fld03_uk01;
	while (fld03_uk01){
		v4 = fld03_uk01;
		fld03_uk01 = fld03_uk01->fld01_next;
		((void(__fastcall*)(_QWORD))v4->fld02_freefn)(v4->fld03_unk01);
		HeapFree(g_DATA.g_hHeap, 0, v4);
	}

	return HeapFree(g_DATA.g_hHeap, 0, rso);
}



char* __fastcall put_in_buf_0x28(int a1){
	_DWORD* v1; // rax
	int cntr; // edx
	bool is_zero; // zf
	_DWORD* el1; // rcx
	_DWORD* el2; // r8
	__int64 i; // r9
	__int64 cntr_1; // rax
	int cntrnext; // edx

	v1 = 0i64;
	if (a1 == -1){
		cntr = g_counter10;
		is_zero = g_counter10 == 0;
	} else{
		cntr = g_counter10;
		if (g_counter10 <= 0)
			goto LABEL_11;
		el1 = g_buf_0x28;
		el2 = g_buf_0x28;
		i = (unsigned int)g_counter10;
		do{
			is_zero = *el1 == a1;
			el1 += 0xA;
			if (is_zero)
				v1 = el2;
			el2 += 0xA;
			--i;
		} while (i);
		is_zero = v1 == 0i64;
	}
	if (!is_zero)
		return 0i64;
LABEL_11:
	cntr_1 = cntr;
	cntrnext = cntr + 1;
	g_counter10 = cntrnext;
	g_buf_0x28[0xA * cntr_1] = a1;
	return (char*)&g_buf_0x28[0xA * cntrnext - 0xA];
}
_DWORD* __fastcall find_in_buf_0x28(int a1){
	_DWORD* result; // rax
	__int64 cntr; // r8
	_DWORD* el1; // rcx
	_DWORD* el2; // rdx
	bool is_zero; // zf

	result = 0i64;
	if (a1 == -1){
		if (g_counter10)
			return g_buf_0x28;
	} else{
		cntr = (unsigned int)g_counter10;
		if (g_counter10 > 0){
			el1 = g_buf_0x28;
			el2 = g_buf_0x28;
			do{
				is_zero = *el1 == a1;
				el1 += 0xA;
				if (is_zero)
					result = el2;
				el2 += 0xA;
				--cntr;
			} while (cntr);
		}
	}
	return result;
}

inline uint32 __ROL4__(uint32 value, int count){ return __ROL__((uint32)value, count); }
inline uint32 __ROR4__(uint32 value, int count){ return __ROL__((uint32)value, -count); }

typedef struct MD5Context_{
	uint32_t buffer[4];
	uint64_t size;
} MD5Context;
#pragma pack(push, 1)
typedef struct MD5_{
	DWORD unk00;
	uint8_t padding[64];
	MD5Context ctx;
	char unk[64];
} MD5;
#pragma pack(pop)
typedef struct md5_VT_{
	QWORD id;
	MD5* (__fastcall* ctor)(__int64 a1, int a2);
	char(__fastcall* f1_md5_Update)(MD5* a1, __int64 a2, unsigned int a3);
	void* (__fastcall* f2_md5_Stuff)(MD5* a1);
	BOOL(__fastcall* dtor)(void* a1);
} md5_VT;
void __fastcall md5_Init(MD5Context* ctx){
	ctx->size = 0i64;
	ctx->buffer[0] = 0x67452301;
	ctx->buffer[1] = 0xEFCDAB89;
	ctx->buffer[2] = 0x98BADCFE;
	ctx->buffer[3] = 0x10325476;
}
MD5* __fastcall md5_ctor(__int64 a1, int a2){
	MD5* md5; // rbx

	md5 = (MD5*)HeapAlloc(g_DATA.g_hHeap, 0, 0x9Cui64);
	md5->unk00 = 0x80;
	md5_Init(&md5->ctx);
	return md5;
}
BOOL __fastcall md5_dtor(void* a1){
	return HeapFree(g_DATA.g_hHeap, 0, a1);
}
void md5_Step(BYTE* field, const BYTE* param){
	//https://github.com/fdsprod/cuodesktop/blob/master/EncPatcher/MD5.cpp#L190
	unsigned int a = *((unsigned int*)(field + 0));
	unsigned int b = *((unsigned int*)(field + 4));
	unsigned int c = *((unsigned int*)(field + 8));
	unsigned int d = *((unsigned int*)(field + 12));

	a = ((b & c) | (~b & d)) + *((unsigned int*)(param + 0x00)) + a - 0x28955B88;
	a = ((a << 0x07) | (a >> 0x19)) + b;
	d = ((a & b) | (~a & c)) + *((unsigned int*)(param + 0x04)) + d - 0x173848AA;
	d = ((d << 0x0c) | (d >> 0x14)) + a;
	c = ((d & a) | (~d & b)) + *((unsigned int*)(param + 0x08)) + c + 0x242070DB;
	c = ((c << 0x11) | (c >> 0x0f)) + d;
	b = ((c & d) | (~c & a)) + *((unsigned int*)(param + 0x0c)) + b - 0x3E423112;
	b = ((b << 0x16) | (b >> 0x0a)) + c;
	a = ((b & c) | (~b & d)) + *((unsigned int*)(param + 0x10)) + a - 0x0A83F051;
	a = ((a << 0x07) | (a >> 0x19)) + b;
	d = ((a & b) | (~a & c)) + *((unsigned int*)(param + 0x14)) + d + 0x4787C62A;
	d = ((d << 0x0c) | (d >> 0x14)) + a;
	c = ((d & a) | (~d & b)) + *((unsigned int*)(param + 0x18)) + c - 0x57CFB9ED;
	c = ((c << 0x11) | (c >> 0x0f)) + d;
	b = ((c & d) | (~c & a)) + *((unsigned int*)(param + 0x1c)) + b - 0x02B96AFF;
	b = ((b << 0x16) | (b >> 0x0a)) + c;
	a = ((b & c) | (~b & d)) + *((unsigned int*)(param + 0x20)) + a + 0x698098D8;
	a = ((a << 0x07) | (a >> 0x19)) + b;
	d = ((a & b) | (~a & c)) + *((unsigned int*)(param + 0x24)) + d - 0x74BB0851;
	d = ((d << 0x0c) | (d >> 0x14)) + a;
	c = ((d & a) | (~d & b)) + *((unsigned int*)(param + 0x28)) + c - 0x0000A44F;
	c = ((c << 0x11) | (c >> 0x0f)) + d;
	b = ((c & d) | (~c & a)) + *((unsigned int*)(param + 0x2C)) + b - 0x76A32842;
	b = ((b << 0x16) | (b >> 0x0a)) + c;
	a = ((b & c) | (~b & d)) + *((unsigned int*)(param + 0x30)) + a + 0x6B901122;
	a = ((a << 0x07) | (a >> 0x19)) + b;
	d = ((a & b) | (~a & c)) + *((unsigned int*)(param + 0x34)) + d - 0x02678E6D;
	d = ((d << 0x0c) | (d >> 0x14)) + a;
	c = ((d & a) | (~d & b)) + *((unsigned int*)(param + 0x38)) + c - 0x5986BC72;
	c = ((c << 0x11) | (c >> 0x0f)) + d;
	b = ((c & d) | (~c & a)) + *((unsigned int*)(param + 0x3c)) + b + 0x49B40821;
	b = ((b << 0x16) | (b >> 0x0a)) + c;

	a = ((b & d) | (~d & c)) + *((unsigned int*)(param + 0x04)) + a - 0x09E1DA9E;
	a = ((a << 0x05) | (a >> 0x1b)) + b;
	d = ((a & c) | (~c & b)) + *((unsigned int*)(param + 0x18)) + d - 0x3FBF4CC0;
	d = ((d << 0x09) | (d >> 0x17)) + a;
	c = ((d & b) | (~b & a)) + *((unsigned int*)(param + 0x2c)) + c + 0x265E5A51;
	c = ((c << 0x0e) | (c >> 0x12)) + d;
	b = ((c & a) | (~a & d)) + *((unsigned int*)(param + 0x00)) + b - 0x16493856;
	b = ((b << 0x14) | (b >> 0x0c)) + c;
	a = ((b & d) | (~d & c)) + *((unsigned int*)(param + 0x14)) + a - 0x29D0EFA3;
	a = ((a << 0x05) | (a >> 0x1b)) + b;
	d = ((a & c) | (~c & b)) + *((unsigned int*)(param + 0x28)) + d + 0x02441453;
	d = ((d << 0x09) | (d >> 0x17)) + a;
	c = ((d & b) | (~b & a)) + *((unsigned int*)(param + 0x3c)) + c - 0x275E197F;
	c = ((c << 0x0e) | (c >> 0x12)) + d;
	b = ((c & a) | (~a & d)) + *((unsigned int*)(param + 0x10)) + b - 0x182C0438;
	b = ((b << 0x14) | (b >> 0x0c)) + c;
	a = ((b & d) | (~d & c)) + *((unsigned int*)(param + 0x24)) + a + 0x21E1CDE6;
	a = ((a << 0x05) | (a >> 0x1b)) + b;
	d = ((a & c) | (~c & b)) + *((unsigned int*)(param + 0x38)) + d - 0x3CC8F82A;
	d = ((d << 0x09) | (d >> 0x17)) + a;
	c = ((d & b) | (~b & a)) + *((unsigned int*)(param + 0x0c)) + c - 0x0B2AF279;
	c = ((c << 0x0e) | (c >> 0x12)) + d;
	b = ((c & a) | (~a & d)) + *((unsigned int*)(param + 0x20)) + b + 0x455A14ED;
	b = ((b << 0x14) | (b >> 0x0c)) + c;
	a = ((b & d) | (~d & c)) + *((unsigned int*)(param + 0x34)) + a - 0x561C16FB;
	a = ((a << 0x05) | (a >> 0x1b)) + b;
	d = ((a & c) | (~c & b)) + *((unsigned int*)(param + 0x08)) + d - 0x03105C08;
	d = ((d << 0x09) | (d >> 0x17)) + a;
	c = ((d & b) | (~b & a)) + *((unsigned int*)(param + 0x1c)) + c + 0x676F02D9;
	c = ((c << 0x0e) | (c >> 0x12)) + d;
	b = ((c & a) | (~a & d)) + *((unsigned int*)(param + 0x30)) + b - 0x72D5B376;
	b = ((b << 0x14) | (b >> 0x0c)) + c;

	a = (b ^ c ^ d) + *((unsigned int*)(param + 0x14)) + a - 0x0005C6BE;
	a = ((a << 0x04) | (a >> 0x1c)) + b;
	d = (a ^ b ^ c) + *((unsigned int*)(param + 0x20)) + d - 0x788E097F;
	d = ((d << 0x0b) | (d >> 0x15)) + a;
	c = (d ^ a ^ b) + *((unsigned int*)(param + 0x2c)) + c + 0x6D9D6122;
	c = ((c << 0x10) | (c >> 0x10)) + d;
	b = (c ^ d ^ a) + *((unsigned int*)(param + 0x38)) + b - 0x021AC7F4;
	b = ((b << 0x17) | (b >> 0x09)) + c;
	a = (b ^ c ^ d) + *((unsigned int*)(param + 0x04)) + a - 0x5B4115BC;
	a = ((a << 0x04) | (a >> 0x1c)) + b;
	d = (a ^ b ^ c) + *((unsigned int*)(param + 0x10)) + d + 0x4BDECFA9;
	d = ((d << 0x0b) | (d >> 0x15)) + a;
	c = (d ^ a ^ b) + *((unsigned int*)(param + 0x1c)) + c - 0x0944B4A0;
	c = ((c << 0x10) | (c >> 0x10)) + d;
	b = (c ^ d ^ a) + *((unsigned int*)(param + 0x28)) + b - 0x41404390;
	b = ((b << 0x17) | (b >> 0x09)) + c;
	a = (b ^ c ^ d) + *((unsigned int*)(param + 0x34)) + a + 0x289B7EC6;
	a = ((a << 0x04) | (a >> 0x1c)) + b;
	d = (a ^ b ^ c) + *((unsigned int*)(param + 0x00)) + d - 0x155ED806;
	d = ((d << 0x0b) | (d >> 0x15)) + a;
	c = (d ^ a ^ b) + *((unsigned int*)(param + 0x0c)) + c - 0x2B10CF7B;
	c = ((c << 0x10) | (c >> 0x10)) + d;
	b = (c ^ d ^ a) + *((unsigned int*)(param + 0x18)) + b + 0x04881D05;
	b = ((b << 0x17) | (b >> 0x09)) + c;
	a = (b ^ c ^ d) + *((unsigned int*)(param + 0x24)) + a - 0x262B2FC7;
	a = ((a << 0x04) | (a >> 0x1c)) + b;
	d = (a ^ b ^ c) + *((unsigned int*)(param + 0x30)) + d - 0x1924661B;
	d = ((d << 0x0b) | (d >> 0x15)) + a;
	c = (d ^ a ^ b) + *((unsigned int*)(param + 0x3c)) + c + 0x1fa27cf8;
	c = ((c << 0x10) | (c >> 0x10)) + d;
	b = (c ^ d ^ a) + *((unsigned int*)(param + 0x08)) + b - 0x3B53A99B;
	b = ((b << 0x17) | (b >> 0x09)) + c;

	a = ((~d | b) ^ c) + *((unsigned int*)(param + 0x00)) + a - 0x0BD6DDBC;
	a = ((a << 0x06) | (a >> 0x1a)) + b;
	d = ((~c | a) ^ b) + *((unsigned int*)(param + 0x1c)) + d + 0x432AFF97;
	d = ((d << 0x0a) | (d >> 0x16)) + a;
	c = ((~b | d) ^ a) + *((unsigned int*)(param + 0x38)) + c - 0x546BDC59;
	c = ((c << 0x0f) | (c >> 0x11)) + d;
	b = ((~a | c) ^ d) + *((unsigned int*)(param + 0x14)) + b - 0x036C5FC7;
	b = ((b << 0x15) | (b >> 0x0b)) + c;
	a = ((~d | b) ^ c) + *((unsigned int*)(param + 0x30)) + a + 0x655B59C3;
	a = ((a << 0x06) | (a >> 0x1a)) + b;
	d = ((~c | a) ^ b) + *((unsigned int*)(param + 0x0C)) + d - 0x70F3336E;
	d = ((d << 0x0a) | (d >> 0x16)) + a;
	c = ((~b | d) ^ a) + *((unsigned int*)(param + 0x28)) + c - 0x00100B83;
	c = ((c << 0x0f) | (c >> 0x11)) + d;
	b = ((~a | c) ^ d) + *((unsigned int*)(param + 0x04)) + b - 0x7A7BA22F;
	b = ((b << 0x15) | (b >> 0x0b)) + c;
	a = ((~d | b) ^ c) + *((unsigned int*)(param + 0x20)) + a + 0x6FA87E4F;
	a = ((a << 0x06) | (a >> 0x1a)) + b;
	d = ((~c | a) ^ b) + *((unsigned int*)(param + 0x3c)) + d - 0x01D31920;
	d = ((d << 0x0a) | (d >> 0x16)) + a;
	c = ((~b | d) ^ a) + *((unsigned int*)(param + 0x18)) + c - 0x5CFEBCEC;
	c = ((c << 0x0f) | (c >> 0x11)) + d;
	b = ((~a | c) ^ d) + *((unsigned int*)(param + 0x34)) + b + 0x4E0811A1;
	b = ((b << 0x15) | (b >> 0x0b)) + c;
	a = ((~d | b) ^ c) + *((unsigned int*)(param + 0x10)) + a - 0x08AC817E;
	a = ((a << 0x06) | (a >> 0x1a)) + b;
	d = ((~c | a) ^ b) + *((unsigned int*)(param + 0x2c)) + d - 0x42C50DCB;
	d = ((d << 0x0a) | (d >> 0x16)) + a;
	c = ((~b | d) ^ a) + *((unsigned int*)(param + 0x08)) + c + 0x2AD7D2BB;
	c = ((c << 0x0f) | (c >> 0x11)) + d;
	b = ((~a | c) ^ d) + *((unsigned int*)(param + 0x24)) + b - 0x14792C6F;
	b = ((b << 0x15) | (b >> 0x0b)) + c;

	*((unsigned int*)(field + 0)) += a;
	*((unsigned int*)(field + 4)) += b;
	*((unsigned int*)(field + 8)) += c;
	*((unsigned int*)(field + 12)) += d;
}
__int64 __fastcall md5_Step2(MD5Context* abuffer, __int64 a2){
	uint32_t AA; // edi
	uint32_t BB; // r10d
	uint32_t CC; // r11d
	uint32_t DD; // ebx
	__int64 v6=0; // r8
	unsigned __int8* v7=0; // rdx
	__int64 v8=0; // r9
	int v9=0; // eax
	int v10=0; // ecx
	uint32_t v11=0; // edx
	uint32_t v12=0; // r8d
	uint32_t v13=0; // r9d
	uint32_t v14=0; // r10d
	uint32_t v15=0; // r11d
	uint32_t v16=0; // edx
	uint32_t v17=0; // r8d
	uint32_t v18=0; // r9d
	uint32_t v19=0; // r10d
	int v20=0; // edx
	int v21=0; // edi
	int v22=0; // r9d
	int v23=0; // r11d
	int v24=0; // ebx
	int v25=0; // r10d
	int v26=0; // r9d
	int v27=0; // r11d
	int v28=0; // r8d
	int v29=0; // edx
	int v30=0; // r10d
	int v31=0; // r9d
	int v32=0; // r11d
	int v33=0; // r8d
	int v34=0; // edx
	int v35=0; // r10d
	int v36=0; // r9d
	int v37=0; // r11d
	int v38=0; // ebx
	int v39=0; // edx
	int v40=0; // r8d
	int v41=0; // r9d
	int v42=0; // r10d
	int v43=0; // edx
	int v44=0; // r8d
	int v45=0; // r9d
	int v46=0; // r10d
	int v47=0; // r11d
	int v48=0; // edx
	int v49=0; // r8d
	int v50=0; // r9d
	int v51=0; // r10d
	int v52=0; // r11d
	int v53=0; // r8d
	int v54=0; // edx
	int v55=0; // r9d
	int v56=0; // ecx
	int v57=0; // r10d
	int v58=0; // r8d
	int v59=0; // edx
	int v60=0; // r9d
	int v61=0; // ecx
	int v62=0; // r10d
	int v63=0; // r8d
	int v64=0; // edx
	int v65=0; // r9d
	int v66=0; // ecx
	int v67=0; // r10d
	int v68=0; // r11d
	int v69=0; // r9d
	int v70=0; // ebx
	int v71=0; // r8d
	int v72=0; // edx
	int v73=0; // ecx
	int v74=0; // ecx
	__int64 result=0; // rax
	int v76=0; // [rsp+0h] [rbp-40h]
	int v77=0; // [rsp+4h] [rbp-3Ch]
	int v78=0; // [rsp+8h] [rbp-38h]
	int v79=0; // [rsp+Ch] [rbp-34h]
	int v80=0; // [rsp+10h] [rbp-30h]
	int v81=0; // [rsp+14h] [rbp-2Ch]
	int v82=0; // [rsp+18h] [rbp-28h]
	int v83=0; // [rsp+1Ch] [rbp-24h]
	int v84=0; // [rsp+20h] [rbp-20h]
	int v85=0; // [rsp+24h] [rbp-1Ch]
	int v86=0; // [rsp+28h] [rbp-18h]
	int v87=0; // [rsp+2Ch] [rbp-14h]
	int v88=0; // [rsp+30h] [rbp-10h]
	int v89=0; // [rsp+34h] [rbp-Ch]
	int v90=0; // [rsp+38h] [rbp-8h]
	int v91=0; // [rsp+3Ch] [rbp-4h]
	uint32_t v93; // [rsp+90h] [rbp+50h]

	AA = abuffer->buffer[0];
	BB = abuffer->buffer[1];
	CC = abuffer->buffer[2];
	DD = abuffer->buffer[3];
	v6 = 0i64;
	v93 = abuffer->buffer[0];
	v7 = (unsigned __int8*)(a2 + 2);
	v8 = 0x10i64;
	do{
		v9 = *v7;
		v10 = v7[1];
		v7 += 4;
		*(&v76 + v6) = v7[-6] | ((v7[-5] | ((v9 | (v10 << 8)) << 8)) << 8);
		v6 = (unsigned int)(v6 + 1);
		--v8;
	} while (v8);
	v11 = BB  + __ROL4__(v76 + (BB & CC | DD & ~BB) + AA - 0x28955B88, 7);
	v12 = v11 + __ROL4__(v77 + (v11 & BB | CC & ~v11) + DD - 0x173848AA, 0xC);
	v13 = v12 + __ROR4__(v78 + (v11 & v12 | BB & ~v12) + CC + 0x242070DB, 0xF);
	v14 = v13 + __ROR4__(v79 + (v13 & v12 | v11 & ~v13) + BB - 0x3E423112, 0xA);
	v15 = v14 + __ROL4__(v80 + (v14 & v13 | v12 & ~v14) + v11 - 0xA83F051, 7);
	v16 = v15 + __ROL4__(v81 + (v15 & v14 | v13 & ~v15) + v12 + 0x4787C62A, 0xC);
	v17 = v16 + __ROR4__(v82 + (v15 & v16 | v14 & ~v16) + v13 - 0x57CFB9ED, 0xF);
	v18 = v17 + __ROR4__(v83 + (v17 & v16 | v15 & ~v17) + v14 - 0x2B96AFF, 0xA);
	v19 = v18 + __ROL4__(v15 + v84 + (v18 & v17 | v16 & ~v18) + 0x698098D8, 7);
	v20 = v19 + __ROL4__(v85 + (v19 & v18 | v17 & ~v19) - 0x74BB0851 + v16, 0xC);
	v21 = v20 + __ROR4__(v17 + v86 + (v19 & v20 | v18 & ~v20) - 0xA44F, 0xF);
	v22 = v21 + __ROR4__(v87 + (v21 & v20 | v19 & ~v21) - 0x76A32842 + v18, 0xA);
	v23 = v22 + __ROL4__(v88 + (v22 & v21 | v20 & ~v22) + v19 + 0x6B901122, 7);
	v24 = v23 + __ROL4__(v89 + (v23 & v22 | v21 & ~v23) + v20 - 0x2678E6D, 0xC);
	v25 = v24 + __ROR4__(v90 + (v23 & v24 | v22 & ~v24) + v21 - 0x5986BC72, 0xF);
	v26 = v25 + __ROR4__(v91 + (v25 & v24 | v23 & ~v25) + 0x49B40821 + v22, 0xA);
	v27 = v26 + __ROL4__(v77 + (v26 & v24 | v25 & ~v24) - 0x9E1DA9E + v23, 5);
	v28 = v27 + __ROL4__(v24 + v82 + (v26 & ~v25 | v27 & v25) - 0x3FBF4CC0, 9);
	v29 = v28 + __ROL4__(v87 + (v26 & v28 | v27 & ~v26) + v25 + 0x265E5A51, 0xE);
	v30 = v29 + __ROR4__(v76 + (v27 & v29 | v28 & ~v27) + v26 - 0x16493856, 0xC);
	v31 = v30 + __ROL4__(v81 + (v30 & v28 | v29 & ~v28) + v27 - 0x29D0EFA3, 5);
	v32 = v31 + __ROL4__(v86 + (v31 & v29 | v30 & ~v29) + v28 + 0x2441453, 9);
	v33 = v32 + __ROL4__(v91 + (v30 & v32 | v31 & ~v30) + v29 - 0x275E197F, 0xE);
	v34 = v33 + __ROR4__(v80 + (v31 & v33 | v32 & ~v31) + v30 - 0x182C0438, 0xC);
	v35 = v34 + __ROL4__(v85 + (v34 & v32 | v33 & ~v32) + v31 + 0x21E1CDE6, 5);
	v36 = v35 + __ROL4__(v90 + (v35 & v33 | v34 & ~v33) + v32 - 0x3CC8F82A, 9);
	v37 = v36 + __ROL4__(v33 + v79 + (v34 & v36 | v35 & ~v34) - 0xB2AF279, 0xE);
	v38 = v37 + __ROR4__(v84 + (v35 & v37 | v36 & ~v35) + v34 + 0x455A14ED, 0xC);
	v39 = v38 + __ROL4__(v89 + (v38 & v36 | v37 & ~v36) + v35 - 0x561C16FB, 5);
	v40 = v39 + __ROL4__(v78 + (v39 & v37 | v38 & ~v37) + v36 - 0x3105C08, 9);
	v41 = v40 + __ROL4__(v83 + (v38 & v40 | v39 & ~v38) + v37 + 0x676F02D9, 0xE);
	v42 = v41 + __ROR4__(v38 + v88 + (v39 & v41 | v40 & ~v39) - 0x72D5B376, 0xC);
	v43 = v42 + __ROL4__(v81 + (v42 ^ v41 ^ v40) - 0x5C6BE + v39, 4);
	v44 = v43 + __ROL4__(v84 + (v43 ^ v42 ^ v41) - 0x788E097F + v40, 0xB);
	v45 = v44 + __ROL4__(v87 + (v43 ^ v42 ^ v44) + 0x6D9D6122 + v41, 0x10);
	v46 = v45 + __ROR4__(v90 + (v43 ^ v45 ^ v44) - 0x21AC7F4 + v42, 9);
	v47 = v46 + __ROL4__(v77 + (v46 ^ v45 ^ v44) + v43 - 0x5B4115BC, 4);
	v48 = v47 + __ROL4__(v80 + (v47 ^ v46 ^ v45) + v44 + 0x4BDECFA9, 0xB);
	v49 = v48 + __ROL4__(v83 + (v47 ^ v46 ^ v48) + v45 - 0x944B4A0, 0x10);
	v50 = v49 + __ROR4__(v86 + (v47 ^ v49 ^ v48) + v46 - 0x41404390, 9);
	v51 = v50 + __ROL4__(v89 + (v50 ^ v49 ^ v48) + v47 + 0x289B7EC6, 4);
	v52 = v51 + __ROL4__(v76 + (v51 ^ v50 ^ v49) + v48 - 0x155ED806, 0xB);
	v53 = v52 + __ROL4__(v79 + (v51 ^ v50 ^ v52) - 0x2B10CF7B + v49, 0x10);
	v54 = v53 + __ROR4__(v82 + (v51 ^ v53 ^ v52) + v50 + 0x4881D05, 9);
	v55 = v54 + __ROL4__(v85 + (v54 ^ v53 ^ v52) + v51 - 0x262B2FC7, 4);
	v56 = v55 + __ROL4__(v52 + v88 + (v55 ^ v54 ^ v53) - 0x1924661B, 0xB);
	v57 = v56 + __ROL4__(v91 + (v55 ^ v54 ^ v56) + v53 + 0x1FA27CF8, 0x10);
	v58 = v57 + __ROR4__(v78 + (v55 ^ v57 ^ v56) + v54 - 0x3B53A99B, 9);
	v59 = v58 + __ROL4__(v76 + (v57 ^ (v58 | ~v56)) + v55 - 0xBD6DDBC, 6);
	v60 = v59 + __ROL4__(v83 + (v58 ^ (v59 | ~v57)) + v56 + 0x432AFF97, 0xA);
	v61 = v60 + __ROL4__(v90 + (v59 ^ (v60 | ~v58)) + v57 - 0x546BDC59, 0xF);
	v62 = v61 + __ROR4__(v81 + (v60 ^ (v61 | ~v59)) + v58 - 0x36C5FC7, 0xB);
	v63 = v62 + __ROL4__(v88 + (v61 ^ (v62 | ~v60)) + v59 + 0x655B59C3, 6);
	v64 = v63 + __ROL4__(v79 + (v62 ^ (v63 | ~v61)) + v60 - 0x70F3336E, 0xA);
	v65 = v64 + __ROL4__(v86 + (v63 ^ (v64 | ~v62)) + v61 - 0x100B83, 0xF);
	v66 = v65 + __ROR4__(v77 + (v64 ^ (v65 | ~v63)) + v62 - 0x7A7BA22F, 0xB);
	v67 = v66 + __ROL4__(v84 + (v65 ^ (v66 | ~v64)) + v63 + 0x6FA87E4F, 6);
	v68 = v67 + __ROL4__(v91 + (v66 ^ (v67 | ~v65)) + v64 - 0x1D31920, 0xA);
	v69 = v68 + __ROL4__(v82 + (v67 ^ (v68 | ~v66)) - 0x5CFEBCEC + v65, 0xF);
	v70 = v69 + __ROR4__(v89 + (v68 ^ (v69 | ~v67)) + v66 + 0x4E0811A1, 0xB);
	v71 = v70 + __ROL4__(v67 + v80 + (v69 ^ (v70 | ~v68)) - 0x8AC817E, 6);
	v72 = v71 + __ROL4__(v68 + v87 + (v70 ^ (v71 | ~v69)) - 0x42C50DCB, 0xA);
	v73 = v78 + (v71 ^ (v72 | ~v70)) + v69 + 0x2AD7D2BB;
	abuffer->buffer[0] = v71 + v93;
	v74 = v72 + __ROL4__(v73, 0xF);
	abuffer->buffer[2] += v74;
	result = v74 + abuffer->buffer[1] + __ROR4__(v85 + (v72 ^ (v74 | ~v71)) + v70 - 0x14792C6F, 0xB);
	abuffer->buffer[3] += v72;
	abuffer->buffer[1] = result;
	return result;
}
void md5_Update_(BYTE* key, const BYTE* challenge, int len){
	unsigned int* ptr1, * ptr2;
	unsigned int a, b, c;

	ptr1 = (unsigned int*)(key + 16);
	ptr2 = (unsigned int*)(key + 20);

	a = *ptr1;
	b = (a >> 3) & 0x3f;
	a += len * 8;
	*ptr1 = a;

	if (a < (len << 3))
		ptr2 += 4;

	*ptr2 = *ptr2 + (len >> 0x1d);

	a = 64 - b;
	c = 0;

	if (a <= len){
		memcpy(key + b + 24, challenge, a);
		md5_Step(key, key + 24);

		c = a;
		a += 0x3F;

		while (a < len){
			md5_Step(key, challenge + a - 0x3f);
			a += 64;
			c += 64;
		}

		b = 0;
	}

	memcpy(key + b + 24, challenge + c, len - c);
}
char __fastcall md5_Update_2(MD5Context* a1, __int64 a2, unsigned int a3){
	unsigned int v5; // r9d
	unsigned int v7; // ecx
	unsigned int v8; // eax
	unsigned int v9; // ebx
	__int64 v10; // r8
	__int64 v11; // rdx
	_BYTE* v12; // rcx
	__int64 v13; // rdx
	unsigned int v14; // esi
	unsigned __int64 v15; // r8
	char* v16; // rdx
	__int64 v17; // rcx
	__int64 v18; // r8

	v5 = LODWORD(a1->size) + 8 * a3;
	v7 = (LODWORD(a1->size) >> 3) & 0x3F;
	LODWORD(a1->size) = v5;
	if (v5 < 8 * a3)
		++HIDWORD(a1->size);
	v8 = a3 >> 0x1D;
	v9 = 0x40 - v7;
	HIDWORD(a1->size) += a3 >> 0x1D;
	if (a3 < 0x40 - v7){
		v9 = 0;
	} else{
		if (v9){
			v10 = v9;
			v11 = a2 - v7;
			v12 = (char*)&a1[1] + v7;
			v13 = v11 - (_QWORD)a1;
			do{
				*v12 = v12[v13 - 0x18];
				++v12;
				--v10;
			} while (v10);
		}
		md5_Step(a1, (__int64)&a1[1]);
		while (1){
			LOBYTE(v8) = v9 + 0x3F;
			if (v9 + 0x3F >= a3)
				break;
			md5_Step(a1, a2 + v9);
			v9 += 0x40;
		}
		v7 = 0;
	}
	v14 = a3 - v9;
	if (!v14)
		// 05490670 06D53B7Fh = 5
		return v8;
	v15 = v9 - (unsigned __int64)v7;
	v16 = (char*)&a1[1] + v7;
	v17 = v14;
	v18 = a2 + v15 - (_QWORD)a1;
	do{
		LOBYTE(v8) = v16[v18 - 0x18];
		*v16++ = v8;
		--v17;
	} while (v17);
	return v8;
}
char __fastcall md5_Update(MD5* a1, __int64 a2, unsigned int a3){
	md5_Update_(&a1->ctx, a2, a3);
}
void md5_stuff_(BYTE* result, BYTE* field){
	//BYTE buf1[0x80];
	BYTE buf2[0x80];
	int i;

	//memset(buf1, 0, 0x80);

	//*buf1 = 0x80;

	memcpy(buf2, field + 16, 8);
	//i = (int(*((unsigned int*)(buf2))) >> 3) & 0x3f;
	i = (((int)(*((unsigned int*)(buf2)))) >> 3) & 0x3f;

	if (i < 56)
		i = 56 - i;
	else
		i = 120 - i;

	//md5_Update_(field, buf1, i);
	md5_Update_(field, g_MD5PADDING, i);
	md5_Update_(field, buf2, 8);

	memcpy(result, field, 16);
}
void* __fastcall md5_stuff_2(int64_t* PADDING, MD5Context* ctx){
	__int64 v2; // rdi
	__int64 v5; // r10
	unsigned int v6; // r9d
	char* v7; // rdx
	__int64 v8; // r8
	unsigned int v9; // ecx
	unsigned int v10; // r8d
	char* v11; // rdx
	__int64 v12; // r8
	char v13; // al
	char v15[24]; // [rsp+38h] [rbp+10h] BYREF

	v2 = 0i64;
	v5 = 2i64;
	v6 = 0;
	v7 = &v15[2];
	do{
		v8 = v6++;
		v7[-2] = ctx->buffer[v8 + 4];
		v7[-1] = BYTE1(ctx->buffer[v8 + 4]);
		*v7 = BYTE2(ctx->buffer[v8 + 4]);
		v7 += 4;
		v7[-3] = HIBYTE(ctx->buffer[v8 + 4]);
		--v5;
	} while (v5);
	v9 = (LODWORD(ctx->size) >> 3) & 0x3F;
	v10 = 0x78 - v9;
	if (v9 < 0x38)
		v10 = 0x38 - v9;
	md5_Update_(ctx, (__int64)g_MD5PADDING, v10);
	md5_Update_(ctx, (__int64)v15, 8u);
	v11 = (char*)PADDING + 2;
	v12 = 4i64;
	do{
		v11[-2] = ctx->buffer[v2];
		v11[-1] = BYTE1(ctx->buffer[v2]);
		*v11 = BYTE2(ctx->buffer[v2]);
		v13 = HIBYTE(ctx->buffer[v2]);
		v2 = (unsigned int)(v2 + 1);
		v11[1] = v13;
		v11 += 4;
		--v12;
	} while (v12);
	return memset(ctx, 0, 0x58ui64);
}
void* __fastcall md5_stuff(MD5* a1){
	md5_stuff_((int64_t*)a1->padding, &a1->ctx);
}
__int64 ctor_md5_VT(){
	md5_VT* VT; // rax

	VT = (md5_VT*)put_in_buf_0x28(1);
	if (!VT)
		return 1i64;
	VT->ctor = md5_ctor;
	VT->f1_md5_Update = md5_Update;
	VT->f2_md5_Stuff = md5_stuff;
	VT->dtor = md5_dtor;
	return 1i64;
}



#pragma pack(push, 1)
typedef struct MD6Context_{
	uint32_t buffer[22];
	uint64_t size;
} MD6Context;
#pragma pack(pop)
#pragma pack(push, 1)
typedef struct MD6_{
	DWORD unk00;
	uint8_t padding[64];
	MD6Context ctx;
	char unk[64];
} MD6;
#pragma pack(pop)
typedef struct md6_VT_{
	QWORD id;
	QWORD ctor;
	QWORD f1;
	QWORD f2;
	QWORD dtor;
} md6_VT;
void __fastcall md6_Init(MD6Context* a1, uint32_t a2){
	a1->buffer[6] = 0;
	a1->buffer[5] = 0;
	a1->buffer[0] = 0x67452301;
	a1->buffer[1] = 0xEFCDAB89;
	a1->buffer[2] = 0x98BADCFE;
	a1->buffer[3] = 0x10325476;
	a1->buffer[4] = 0xC3D2E1F0;
	HIDWORD(a1->size) = a2;
}
MD6* __fastcall md6_ctor(__int64 a1, uint32_t a2){
	MD6* md6; // rbx

	md6 = (MD6*)HeapAlloc(g_DATA.g_hHeap, 0, 0xE4ui64);
	md6->unk00 = 0xA0;
	md6_Init(&md6->ctx, a2);
	return md6;
}
BOOL __fastcall md6_dtor(void* a1){
	return HeapFree(g_DATA.g_hHeap, 0, a1);
}
__int64 __fastcall md6_step(_DWORD* a1, const void* a2, _DWORD* a3){
	_DWORD* v3; // r15
	int v5; // r9d
	int v6; // r8d
	int v7; // r10d
	int v8; // ecx
	int v9; // r10d
	int v10; // r11d
	int v11; // ebx
	int v12; // edx
	int v13; // r8d
	int v14; // r11d
	int v15; // r8d
	int v16; // r9d
	int v17; // edx
	int v18; // r9d
	int v19; // ecx
	int v20; // r8d
	int v21; // r10d
	int v22; // ecx
	int v23; // r9d
	int v24; // r11d
	int v25; // ecx
	int v26; // r10d
	int v27; // edx
	int v28; // ecx
	int v29; // r11d
	int v30; // r8d
	int v31; // ebx
	int v32; // edx
	int v33; // ebx
	int v34; // edi
	int v35; // r8d
	int v36; // eax
	int v37; // esi
	int v38; // ebx
	int v39; // edi
	int v40; // ecx
	int v41; // eax
	int v42; // edi
	int v43; // esi
	int v44; // r9d
	int v45; // r10d
	int v46; // esi
	int v47; // r10d
	int v48; // r11d
	int v49; // r9d
	int v50; // r11d
	unsigned int v51; // r15d
	int v52; // edx
	int v53; // r10d
	int v54; // edx
	int v55; // r8d
	int v56; // r11d
	int v57; // r8d
	int v58; // ecx
	int v59; // edx
	int v60; // r9d
	int v61; // r12d
	int v62; // ecx
	int v63; // r12d
	int v64; // r8d
	int v65; // r10d
	int v66; // ecx
	int v67; // r9d
	int v68; // ebx
	int v69; // r11d
	int v70; // ecx
	int v71; // r10d
	int v72; // edx
	int v73; // ecx
	int v74; // r11d
	int v75; // r8d
	int v76; // esi
	int v77; // r14d
	int v78; // r15d
	int v79; // ecx
	int v80; // edx
	int v81; // r9d
	int v82; // ecx
	int v83; // r8d
	int v84; // edi
	int v85; // r10d
	int v86; // ecx
	int v87; // r9d
	int v88; // r11d
	int v89; // r13d
	int v90; // edx
	int v91; // r10d
	int v92; // r8d
	int v93; // r11d
	int v94; // eax
	int v95; // ecx
	int v96; // edx
	int v97; // r9d
	int v98; // eax
	int v99; // ecx
	int v100; // r8d
	int v101; // r10d
	int v102; // ebp
	int v103; // ecx
	int v104; // r9d
	int v105; // r11d
	int v106; // eax
	int v107; // ecx
	int v108; // r10d
	int v109; // edx
	int v110; // ecx
	int v111; // r11d
	int v112; // r8d
	int v113; // ecx
	int v114; // ebp
	int v115; // edx
	int v116; // r9d
	int v117; // eax
	int v118; // ecx
	int v119; // r8d
	int v120; // r10d
	int v121; // eax
	int v122; // ecx
	int v123; // r9d
	int v124; // r11d
	int v125; // eax
	int v126; // ebp
	int v127; // ecx
	int v128; // r10d
	int v129; // edx
	int v130; // ecx
	int v131; // r12d
	int v132; // r11d
	int v133; // r8d
	int v134; // r12d
	int v135; // ecx
	int v136; // edx
	int v137; // r9d
	int v138; // ecx
	int v139; // r8d
	int v140; // r12d
	int v141; // r10d
	int v142; // r11d
	int v143; // r9d
	int v144; // ebx
	int v145; // r14d
	int v146; // r10d
	int v147; // r12d
	int v148; // ebx
	int v149; // eax
	int v150; // edi
	int v151; // r13d
	int v152; // eax
	int v153; // eax
	int v154; // ecx
	int v155; // r11d
	int v156; // r8d
	int v157; // ecx
	int v158; // ebx
	int v159; // edi
	int v160; // r9d
	int v161; // ecx
	int v162; // r8d
	int v163; // r10d
	int v164; // r14d
	int v165; // ecx
	int v166; // r9d
	int v167; // r14d
	int v168; // r11d
	int v169; // ebp
	int v170; // ecx
	int v171; // r10d
	int v172; // ebx
	int v173; // r12d
	int v174; // r8d
	int v175; // r11d
	int v176; // ecx
	int v177; // ebx
	int v178; // r9d
	int v179; // ebp
	int v180; // edi
	int v181; // ecx
	int v182; // r12d
	int v183; // eax
	int v184; // r8d
	int v185; // r10d
	int v186; // r11d
	int v187; // r9d
	int v188; // ecx
	int v189; // r10d
	int v190; // ebx
	int v191; // ecx
	int v192; // eax
	int v193; // r11d
	int v194; // r8d
	int v195; // ebp
	int v196; // ecx
	int v197; // ebx
	int v198; // r9d
	int v199; // ecx
	int v200; // r13d
	int v201; // eax
	int v202; // r8d
	int v203; // ebp
	int v204; // r10d
	int v205; // r14d
	int v206; // ecx
	int v207; // r9d
	int v208; // r11d
	int v209; // ecx
	int v210; // eax
	int v211; // r10d
	int v212; // edi
	int v213; // esi
	int v214; // r13d
	int v215; // r14d
	int v216; // ecx
	int v217; // r11d
	int v218; // r13d
	int v219; // ebx
	int v220; // eax
	int v221; // ecx
	int v222; // edi
	int v223; // r9d
	int v224; // ecx
	int v225; // ebx
	int v226; // r10d
	int v227; // eax
	int v228; // ecx
	int v229; // r9d
	int v230; // ecx
	int v231; // eax
	int v232; // r15d
	int v233; // r8d
	int v234; // r14d
	int v235; // ecx
	int v236; // r10d
	int v237; // ecx
	int v238; // r11d
	int v239; // eax
	int v240; // r8d
	int v241; // edx
	int v242; // r9d
	int v243; // r8d
	int v244; // r10d
	int v245; // edx
	int v246; // ebx
	int v247; // eax
	int v248; // r9d
	int v249; // r11d
	int v250; // r13d
	int v251; // r12d
	int v252; // eax
	int v253; // r10d
	int v254; // r8d
	int v255; // eax
	int v256; // r11d
	int v257; // edx
	int v258; // eax
	int v259; // r8d
	int v260; // r9d
	int v261; // eax
	int v262; // edx
	int v263; // ebx
	int v264; // r15d
	int v265; // eax
	int v266; // r9d
	int v267; // r11d
	int v268; // r15d
	int v269; // eax
	int v270; // ebx
	int v271; // r14d
	int v272; // esi
	int v273; // ebp
	int v274; // r10d
	int v275; // r11d
	int v276; // r9d
	int v277; // esi
	int v278; // r8d
	int v279; // eax
	int v280; // r10d
	int v281; // r12d
	int v282; // edi
	int v283; // edx
	int v284; // ebx
	int v285; // r9d
	int v286; // eax
	int v287; // edi
	int v288; // r11d
	int v289; // esi
	int v290; // eax
	int v291; // ebx
	int v292; // r10d
	int v293; // eax
	int v294; // r11d
	int v295; // r9d
	int v296; // r12d
	int v297; // edx
	int v298; // r8d
	unsigned int v299; // r10d
	int v300; // r13d
	int v301; // eax
	int v302; // r9d
	int v303; // edx
	__int64 result; // rax
	_DWORD* v305; // [rsp+20h] [rbp-88h]
	unsigned int v306; // [rsp+28h] [rbp-80h]
	int v307; // [rsp+28h] [rbp-80h]
	int v308; // [rsp+28h] [rbp-80h]
	int v309; // [rsp+28h] [rbp-80h]
	unsigned int v310; // [rsp+2Ch] [rbp-7Ch]
	int v311; // [rsp+2Ch] [rbp-7Ch]
	int v312; // [rsp+2Ch] [rbp-7Ch]
	int v313; // [rsp+2Ch] [rbp-7Ch]
	unsigned int v314; // [rsp+30h] [rbp-78h]
	int v315; // [rsp+30h] [rbp-78h]
	int v316; // [rsp+30h] [rbp-78h]
	int v317; // [rsp+30h] [rbp-78h]
	unsigned int v318; // [rsp+34h] [rbp-74h]
	int v319; // [rsp+34h] [rbp-74h]
	int v320; // [rsp+34h] [rbp-74h]
	int v321; // [rsp+34h] [rbp-74h]
	unsigned int v322; // [rsp+38h] [rbp-70h]
	int v323; // [rsp+38h] [rbp-70h]
	int v324; // [rsp+38h] [rbp-70h]
	int v325; // [rsp+38h] [rbp-70h]
	unsigned int v326; // [rsp+3Ch] [rbp-6Ch]
	int v327; // [rsp+3Ch] [rbp-6Ch]
	int v328; // [rsp+3Ch] [rbp-6Ch]
	int v329; // [rsp+3Ch] [rbp-6Ch]
	unsigned int v330; // [rsp+40h] [rbp-68h]
	int v331; // [rsp+40h] [rbp-68h]
	int v332; // [rsp+40h] [rbp-68h]
	int v333; // [rsp+44h] [rbp-64h]
	int v334; // [rsp+44h] [rbp-64h]
	int v335; // [rsp+44h] [rbp-64h]
	int v336; // [rsp+44h] [rbp-64h]
	unsigned int v337; // [rsp+48h] [rbp-60h]
	int v338; // [rsp+48h] [rbp-60h]
	int v339; // [rsp+48h] [rbp-60h]
	unsigned int v340; // [rsp+4Ch] [rbp-5Ch]
	int v341; // [rsp+4Ch] [rbp-5Ch]
	int v342; // [rsp+4Ch] [rbp-5Ch]
	unsigned int v343; // [rsp+50h] [rbp-58h]
	int v344; // [rsp+50h] [rbp-58h]
	int v345; // [rsp+50h] [rbp-58h]
	unsigned int v346; // [rsp+54h] [rbp-54h]
	int v347; // [rsp+54h] [rbp-54h]
	unsigned int v348; // [rsp+58h] [rbp-50h]
	int v349; // [rsp+58h] [rbp-50h]
	unsigned int v350; // [rsp+5Ch] [rbp-4Ch]
	int v351; // [rsp+5Ch] [rbp-4Ch]
	unsigned int v352; // [rsp+60h] [rbp-48h]
	int v353; // [rsp+60h] [rbp-48h]
	unsigned int v355; // [rsp+C0h] [rbp+18h]
	int v356; // [rsp+C0h] [rbp+18h]
	int v357; // [rsp+C0h] [rbp+18h]
	int v358; // [rsp+C0h] [rbp+18h]
	int v359; // [rsp+C0h] [rbp+18h]
	int v360; // [rsp+C0h] [rbp+18h]
	unsigned int v361; // [rsp+C8h] [rbp+20h]
	int v362; // [rsp+C8h] [rbp+20h]
	int v363; // [rsp+C8h] [rbp+20h]
	int v364; // [rsp+C8h] [rbp+20h]
	int v365; // [rsp+C8h] [rbp+20h]

	v3 = a3;
	v305 = a3;
	if (a3){
		memcpy(a3, a2, 0x40ui64);
	} else{
		v3 = a2;
		v305 = a2;
	}
	v5 = a1[2];
	v6 = a1[3];
	v7 = a1[1];
	v8 = v7 & (v5 ^ v6);
	v9 = __ROR4__(v7, 2);
	v350 = __ROL4__(*v3, 8) & 0xFF00FF | __ROR4__(*v3, 8) & 0xFF00FF00;
	v10 = a1[4] + 0x5A827999 + (v6 ^ v8) + __ROL4__(*a1, 5) + v350;
	v11 = __ROR4__(*a1, 2);
	v326 = __ROL4__(v3[1], 8) & 0xFF00FF | __ROR4__(v3[1], 8) & 0xFF00FF00;
	v12 = v6 + 0x5A827999 + (v5 ^ *a1 & (v9 ^ v5)) + __ROL4__(v10, 5) + v326;
	v13 = v10 & (v11 ^ v9);
	v14 = __ROR4__(v10, 2);
	v314 = __ROL4__(v3[2], 8) & 0xFF00FF | __ROR4__(v3[2], 8) & 0xFF00FF00;
	v15 = v5 + 0x5A827999 + v314 + __ROL4__(v12, 5) + (v9 ^ v13);
	v361 = __ROL4__(v3[3], 8) & 0xFF00FF | __ROR4__(v3[3], 8) & 0xFF00FF00;
	v16 = (v11 ^ v12 & (v11 ^ v14)) + __ROL4__(v15, 5) + v361;
	v17 = __ROR4__(v12, 2);
	v18 = v9 + 0x5A827999 + v16;
	v19 = v14 ^ v15 & (v17 ^ v14);
	v20 = __ROR4__(v15, 2);
	v355 = __ROL4__(v3[4], 8) & 0xFF00FF | __ROR4__(v3[4], 8) & 0xFF00FF00;
	v21 = v11 + 0x5A827999 + v19 + __ROL4__(v18, 5) + v355;
	v22 = v17 ^ v18 & (v20 ^ v17);
	v23 = __ROR4__(v18, 2);
	v343 = __ROL4__(v3[5], 8) & 0xFF00FF | __ROR4__(v3[5], 8) & 0xFF00FF00;
	v24 = v343 + __ROL4__(v21, 5) + 0x5A827999 + v22 + v14;
	v25 = v20 ^ v21 & (v23 ^ v20);
	v340 = __ROL4__(v3[6], 8) & 0xFF00FF | __ROR4__(v3[6], 8) & 0xFF00FF00;
	v26 = __ROR4__(v21, 2);
	v27 = v340 + __ROL4__(v24, 5) + 0x5A827999 + v25 + v17;
	v28 = v23 ^ v24 & (v26 ^ v23);
	v337 = __ROL4__(v3[7], 8) & 0xFF00FF | __ROR4__(v3[7], 8) & 0xFF00FF00;
	v29 = __ROR4__(v24, 2);
	v30 = v337 + __ROL4__(v27, 5) + v28 + v20 + 0x5A827999;
	v352 = __ROL4__(v3[8], 8) & 0xFF00FF | __ROR4__(v3[8], 8) & 0xFF00FF00;
	v31 = v26 ^ v27 & (v26 ^ v29);
	v32 = __ROR4__(v27, 2);
	v33 = v23 + 0x5A827999 + v352 + __ROL4__(v30, 5) + v31;
	v34 = v29 ^ v30 & (v32 ^ v29);
	v35 = __ROR4__(v30, 2);
	v306 = __ROL4__(v3[9], 8) & 0xFF00FF | __ROR4__(v3[9], 8) & 0xFF00FF00;
	v36 = __ROL4__(v33, 5);
	v37 = v32 ^ v33 & (v35 ^ v32);
	v38 = __ROR4__(v33, 2);
	v39 = v26 + v306 + v36 + 0x5A827999 + v34;
	v40 = v35 ^ v39 & (v38 ^ v35);
	v318 = __ROL4__(v3[0xA], 8) & 0xFF00FF | __ROR4__(v3[0xA], 8) & 0xFF00FF00;
	v41 = __ROL4__(v39, 5);
	v42 = __ROR4__(v39, 2);
	v43 = v29 + v318 + v41 + 0x5A827999 + v37;
	v330 = __ROL4__(v3[0xB], 8) & 0xFF00FF | __ROR4__(v3[0xB], 8) & 0xFF00FF00;
	v44 = v32 + 0x5A827999 + v40 + __ROL4__(v43, 5) + v330;
	v322 = __ROL4__(v3[0xC], 8) & 0xFF00FF | __ROR4__(v3[0xC], 8) & 0xFF00FF00;
	v45 = v38 ^ v43 & (v42 ^ v38);
	v46 = __ROR4__(v43, 2);
	v47 = v35 + 0x5A827999 + v322 + __ROL4__(v44, 5) + v45;
	v310 = __ROL4__(v3[0xD], 8) & 0xFF00FF | __ROR4__(v3[0xD], 8) & 0xFF00FF00;
	v48 = v310 + __ROL4__(v47, 5) + (v42 ^ v44 & (v42 ^ v46));
	v49 = __ROR4__(v44, 2);
	v50 = v38 + 0x5A827999 + v48;
	v51 = __ROL4__(v3[0xE], 8) & 0xFF00FF | __ROR4__(v3[0xE], 8) & 0xFF00FF00;
	v333 = __ROL4__(v352 ^ v310 ^ v350 ^ v314, 1);
	*v305 = v333;
	v346 = v51;
	v52 = v51 + __ROL4__(v50, 5) + (v46 ^ v47 & (v49 ^ v46));
	v53 = __ROR4__(v47, 2);
	v54 = v42 + 0x5A827999 + v52;
	v55 = v49 ^ v50 & (v53 ^ v49);
	v348 = __ROL4__(v305[0xF], 8) & 0xFF00FF | __ROR4__(v305[0xF], 8) & 0xFF00FF00;
	v56 = __ROR4__(v50, 2);
	v57 = v46 + 0x5A827999 + v348 + __ROL4__(v54, 5) + v55;
	v58 = v54 & (v56 ^ v53);
	v59 = __ROR4__(v54, 2);
	v60 = v333 + __ROL4__(v57, 5) + 0x5A827999 + (v53 ^ v58) + v49;
	v61 = v306 ^ v51 ^ v326 ^ v361;
	v62 = v56 ^ v57 & (v59 ^ v56);
	v362 = __ROL4__(v343 ^ v330 ^ v333 ^ v361, 1);
	v63 = __ROL4__(v61, 1);
	v305[1] = v63;
	v64 = __ROR4__(v57, 2);
	v65 = v63 + __ROL4__(v60, 5) + 0x5A827999 + v62 + v53;
	v66 = v60 & (v59 ^ v64);
	v67 = __ROR4__(v60, 2);
	v68 = __ROL4__(v318 ^ v348 ^ v314 ^ v355, 1);
	v305[2] = v68;
	v305[3] = v362;
	v69 = v68 + __ROL4__(v65, 5) + 0x5A827999 + (v59 ^ v66) + v56;
	v70 = v362 + 0x5A827999 + __ROL4__(v69, 5) + (v64 ^ v65 & (v67 ^ v64));
	v71 = __ROR4__(v65, 2);
	v72 = v70 + v59;
	v356 = __ROL4__(v340 ^ v322 ^ v63 ^ v355, 1);
	v305[4] = v356;
	v73 = v69 ^ v71 ^ v67;
	v74 = __ROR4__(v69, 2);
	v75 = v356 + 0x6ED9EBA1 + __ROL4__(v72, 5) + v73 + v64;
	v76 = __ROL4__(v343 ^ v337 ^ v310 ^ v68, 1);
	v77 = __ROL4__(v340 ^ v352 ^ v51 ^ v362, 1);
	v305[5] = v76;
	v78 = __ROL4__(v337 ^ v306 ^ v348 ^ v356, 1);
	v79 = v76 + __ROL4__(v75, 5) + 0x6ED9EBA1 + (v72 ^ v74 ^ v71);
	v80 = __ROR4__(v72, 2);
	v81 = v79 + v67;
	v305[6] = v77;
	v82 = v80 ^ v74 ^ v75;
	v83 = __ROR4__(v75, 2);
	v84 = __ROL4__(v76 ^ v352 ^ v318 ^ v333, 1);
	v85 = v77 + __ROL4__(v81, 5) + 0x6ED9EBA1 + v82 + v71;
	v305[7] = v78;
	v86 = v80 ^ v81 ^ v83;
	v87 = __ROR4__(v81, 2);
	v88 = v78 + __ROL4__(v85, 5) + 0x6ED9EBA1 + v86 + v74;
	v305[8] = v84;
	v89 = __ROL4__(v77 ^ v306 ^ v330 ^ v63, 1);
	v90 = v84 + __ROL4__(v88, 5) + 0x6ED9EBA1 + (v85 ^ v87 ^ v83) + v80;
	v305[9] = v89;
	v91 = __ROR4__(v85, 2);
	v92 = v89 + __ROL4__(v90, 5) + 0x6ED9EBA1 + (v88 ^ v91 ^ v87) + v83;
	v93 = __ROR4__(v88, 2);
	v94 = __ROL4__(v78 ^ v318 ^ v322 ^ v68, 1);
	v305[0xA] = v94;
	v315 = v94;
	v95 = v94 + 0x6ED9EBA1 + __ROL4__(v92, 5) + (v90 ^ v93 ^ v91);
	v96 = __ROR4__(v90, 2);
	v97 = v95 + v87;
	v98 = __ROL4__(v84 ^ v330 ^ v310 ^ v362, 1);
	v305[0xB] = v98;
	v307 = v98;
	v99 = v93 ^ v92;
	v100 = __ROR4__(v92, 2);
	v101 = v98 + 0x6ED9EBA1 + __ROL4__(v97, 5) + (v96 ^ v99) + v91;
	v102 = __ROL4__(v89 ^ v322 ^ v346 ^ v356, 1);
	v305[0xC] = v102;
	v319 = v102;
	v103 = v102 + 0x6ED9EBA1 + __ROL4__(v101, 5) + (v96 ^ v97 ^ v100);
	v104 = __ROR4__(v97, 2);
	v105 = v103 + v93;
	v106 = __ROL4__(v76 ^ v315 ^ v310 ^ v348, 1);
	v305[0xD] = v106;
	v327 = v106;
	v107 = v106 + 0x6ED9EBA1 + __ROL4__(v105, 5) + (v101 ^ v104 ^ v100);
	v108 = __ROR4__(v101, 2);
	v109 = v107 + v96;
	v311 = __ROL4__(v77 ^ v307 ^ v346 ^ v333, 1);
	v305[0xE] = v311;
	v110 = v105 ^ v108 ^ v104;
	v111 = __ROR4__(v105, 2);
	v112 = v311 + 0x6ED9EBA1 + __ROL4__(v109, 5) + v110 + v100;
	v113 = v109 ^ v111 ^ v108;
	v114 = __ROL4__(v78 ^ v102 ^ v348 ^ v63, 1);
	v305[0xF] = v114;
	v115 = __ROR4__(v109, 2);
	v349 = v114;
	v116 = v114 + __ROL4__(v112, 5) + 0x6ED9EBA1 + v113 + v104;
	v117 = __ROL4__(v84 ^ v106 ^ v333 ^ v68, 1);
	*v305 = v117;
	v334 = v117;
	v118 = v115 ^ v111 ^ v112;
	v119 = __ROR4__(v112, 2);
	v120 = v117 + __ROL4__(v116, 5) + 0x6ED9EBA1 + v118 + v108;
	v121 = __ROL4__(v89 ^ v311 ^ v63 ^ v362, 1);
	v305[1] = v121;
	v331 = v121;
	v122 = v116 ^ v119;
	v123 = __ROR4__(v116, 2);
	v124 = v121 + 0x6ED9EBA1 + __ROL4__(v120, 5) + (v115 ^ v122) + v111;
	v125 = __ROL4__(v315 ^ v114 ^ v68 ^ v356, 1);
	v305[2] = v125;
	v323 = v125;
	v126 = v307;
	v127 = v120 ^ v123 ^ v119;
	v128 = __ROR4__(v120, 2);
	v129 = v125 + 0x6ED9EBA1 + __ROL4__(v124, 5) + v127 + v115;
	v130 = v124 ^ v128 ^ v123;
	v131 = __ROL4__(v76 ^ v307 ^ v334 ^ v362, 1);
	v305[3] = v131;
	v363 = v131;
	v132 = __ROR4__(v124, 2);
	v133 = v131 + 0x6ED9EBA1 + __ROL4__(v129, 5) + v130 + v119;
	v134 = __ROL4__(v77 ^ v319 ^ v331 ^ v356, 1);
	v135 = v129 ^ v132 ^ v128;
	v305[4] = v134;
	v357 = v134;
	v136 = __ROR4__(v129, 2);
	v137 = v134 + 0x6ED9EBA1 + __ROL4__(v133, 5) + v135 + v123;
	v138 = v132 ^ v133;
	v139 = __ROR4__(v133, 2);
	v140 = __ROL4__(v76 ^ v78 ^ v327 ^ v125, 1);
	v305[5] = v140;
	v338 = v140;
	v344 = __ROL4__(v77 ^ v84 ^ v311 ^ v363, 1);
	v305[6] = v344;
	v141 = v140 + 0x6ED9EBA1 + __ROL4__(v137, 5) + (v136 ^ v138) + v128;
	v142 = v344 + __ROL4__(v141, 5) + 0x6ED9EBA1 + (v136 ^ v137 ^ v139) + v132;
	v143 = __ROR4__(v137, 2);
	v144 = v141 ^ v143 ^ v139;
	v145 = __ROL4__(v78 ^ v89 ^ v349 ^ v357, 1);
	v305[7] = v145;
	v146 = __ROR4__(v141, 2);
	v147 = v315;
	v148 = v136 + 0x6ED9EBA1 + v145 + __ROL4__(v142, 5) + v144;
	v347 = v145;
	v149 = v84 ^ v315 ^ v334;
	v150 = v89 ^ v307 ^ v331;
	v151 = v323;
	v152 = __ROL4__(v338 ^ v149, 1);
	v305[8] = v152;
	v316 = v152;
	v308 = __ROL4__(v344 ^ v150, 1);
	v153 = v142 & v146;
	v154 = v143 & (v142 | v146);
	v155 = __ROR4__(v142, 2);
	v305[9] = v308;
	v156 = v139 + v316 + (v153 | v154) + __ROL4__(v148, 5) - 0x70E44324;
	v157 = v308 + (v148 & v155 | v146 & (v148 | v155));
	v158 = __ROR4__(v148, 2);
	v159 = v319;
	v160 = v143 + v157 + __ROL4__(v156, 5) - 0x70E44324;
	v320 = __ROL4__(v145 ^ v147 ^ v319 ^ v323, 1);
	v161 = v146 + v320 + (v158 & v156 | v155 & (v158 | v156));
	v305[0xA] = v320;
	v162 = __ROR4__(v156, 2);
	v163 = v161 + __ROL4__(v160, 5) - 0x70E44324;
	v164 = __ROL4__(v316 ^ v126 ^ v327 ^ v363, 1);
	v165 = v164 + (v160 & v162 | v158 & (v160 | v162));
	v305[0xB] = v164;
	v166 = __ROR4__(v160, 2);
	v324 = v164;
	v167 = v311;
	v168 = v155 + v165 + __ROL4__(v163, 5) - 0x70E44324;
	v169 = __ROL4__(v308 ^ v159 ^ v311 ^ v357, 1);
	v170 = v169 + (v163 & v166 | v162 & (v163 | v166));
	v305[0xC] = v169;
	v171 = __ROR4__(v163, 2);
	v172 = v158 + v170 + __ROL4__(v168, 5) - 0x70E44324;
	v173 = __ROL4__(v338 ^ v320 ^ v327 ^ v349, 1);
	v174 = v162 + v173 + (v168 & v171 | v166 & (v168 | v171)) + __ROL4__(v172, 5) - 0x70E44324;
	v312 = v169;
	v175 = __ROR4__(v168, 2);
	v328 = v173;
	v305[0xD] = v173;
	v341 = __ROL4__(v344 ^ v324 ^ v167 ^ v334, 1);
	v305[0xE] = v341;
	v176 = v166 + v341 + (v172 & v175 | v171 & (v172 | v175));
	v177 = __ROR4__(v172, 2);
	v178 = v176 + __ROL4__(v174, 5) - 0x70E44324;
	v179 = __ROL4__(v347 ^ v169 ^ v349 ^ v331, 1);
	v305[0xF] = v179;
	v180 = __ROL4__(v316 ^ v173 ^ v334 ^ v151, 1);
	v181 = v175 & (v177 | v174);
	*v305 = v180;
	v182 = __ROL4__(v308 ^ v341 ^ v331 ^ v363, 1);
	v183 = v177 & v174;
	v184 = __ROR4__(v174, 2);
	v305[1] = v182;
	v335 = v179;
	v332 = v180;
	v185 = v171 + v179 + (v183 | v181) + __ROL4__(v178, 5) - 0x70E44324;
	v351 = __ROL4__(v320 ^ v179 ^ v151 ^ v357, 1);
	v305[2] = v351;
	v186 = v175 + v180 + (v178 & v184 | v177 & (v178 | v184)) + __ROL4__(v185, 5) - 0x70E44324;
	v187 = __ROR4__(v178, 2);
	v188 = v182 + (v185 & v187 | v184 & (v185 | v187));
	v189 = __ROR4__(v185, 2);
	v190 = v177 + v188 + __ROL4__(v186, 5) - 0x70E44324;
	v191 = v187 & (v186 | v189);
	v192 = v186 & v189;
	v193 = __ROR4__(v186, 2);
	v194 = v184 + v351 + (v192 | v191) + __ROL4__(v190, 5) - 0x70E44324;
	v195 = __ROL4__(v338 ^ v324 ^ v180 ^ v363, 1);
	v196 = v195 + (v190 & v193 | v189 & (v190 | v193));
	v305[3] = v195;
	v197 = __ROR4__(v190, 2);
	v198 = v187 + v196 + __ROL4__(v194, 5) - 0x70E44324;
	v364 = v195;
	v199 = v193 & (v197 | v194);
	v200 = __ROL4__(v344 ^ v312 ^ v182 ^ v357, 1);
	v305[4] = v200;
	v201 = v194;
	v202 = __ROR4__(v194, 2);
	v203 = __ROL4__(v344 ^ v316 ^ v341 ^ v195, 1);
	v305[6] = v203;
	v358 = v200;
	v204 = v189 + v200 + (v197 & v201 | v199) + __ROL4__(v198, 5) - 0x70E44324;
	v205 = __ROL4__(v338 ^ v347 ^ v328 ^ v351, 1);
	v305[5] = v205;
	v206 = v198 & v202 | v197 & (v198 | v202);
	v207 = __ROR4__(v198, 2);
	v339 = v205;
	v208 = __ROL4__(v204, 5) + v205 + v206 - 0x70E44324 + v193;
	v209 = v202 & (v204 | v207);
	v210 = v204 & v207;
	v211 = __ROR4__(v204, 2);
	v212 = v197 - 0x70E44324 + v203 + (v210 | v209) + __ROL4__(v208, 5);
	v213 = __ROL4__(v347 ^ v308 ^ v335 ^ v200, 1);
	v305[7] = v213;
	v214 = v205 ^ v316 ^ v320 ^ v332;
	v215 = v324;
	v216 = v208 & v211 | v207 & (v208 | v211);
	v217 = __ROR4__(v208, 2);
	v218 = __ROL4__(v214, 1);
	v305[8] = v218;
	v219 = v202 + v213 + v216 - 0x70E44324 + __ROL4__(v212, 5);
	v220 = v212 & v217;
	v345 = v213;
	v317 = v218;
	v221 = v211 & (v212 | v217);
	v222 = __ROR4__(v212, 2);
	v325 = __ROL4__(v203 ^ v308 ^ v324 ^ v182, 1);
	v305[9] = v325;
	v223 = v207 + v218 + (v220 | v221) + __ROL4__(v219, 5) - 0x70E44324;
	v321 = __ROL4__(v213 ^ v320 ^ v312 ^ v351, 1);
	v305[0xA] = v321;
	v224 = v211 + v325 + (v222 & v219 | v217 & (v222 | v219));
	v225 = __ROR4__(v219, 2);
	v226 = v224 + __ROL4__(v223, 5) - 0x70E44324;
	v227 = v223 & v225;
	v228 = v222 & (v223 | v225);
	v229 = __ROR4__(v223, 2);
	v230 = v321 + (v227 | v228);
	v231 = v226 & v229;
	v232 = __ROL4__(v218 ^ v215 ^ v328 ^ v364, 1);
	v233 = v217 + v230 + __ROL4__(v226, 5) - 0x70E44324;
	v234 = __ROL4__(v325 ^ v312 ^ v341 ^ v358, 1);
	v235 = v225 & (v226 | v229);
	v305[0xB] = v232;
	v236 = __ROR4__(v226, 2);
	v305[0xC] = v234;
	v237 = (v231 | v235) - 0x70E44324;
	v238 = __ROR4__(v233, 2);
	v239 = v225 - 0x359D3E2A + v234 + (v233 ^ v236 ^ v229);
	v240 = v222 + v232 + v237 + __ROL4__(v233, 5);
	v309 = v232;
	v313 = v234;
	v329 = __ROL4__(v339 ^ v321 ^ v328 ^ v335, 1);
	v305[0xD] = v329;
	v342 = __ROL4__(v203 ^ v232 ^ v341 ^ v332, 1);
	v241 = v239 + __ROL4__(v240, 5);
	v305[0xE] = v342;
	v242 = v229 + v329 + (v240 ^ v238 ^ v236) + __ROL4__(v241, 5) - 0x359D3E2A;
	v243 = __ROR4__(v240, 2);
	v244 = v236 + v342 + (v243 ^ v238 ^ v241) + __ROL4__(v242, 5) - 0x359D3E2A;
	v245 = __ROR4__(v241, 2);
	v246 = __ROL4__(v213 ^ v234 ^ v335 ^ v182, 1);
	v305[0xF] = v246;
	v247 = v242 ^ v245;
	v336 = v246;
	v248 = __ROR4__(v242, 2);
	v353 = __ROL4__(v218 ^ v329 ^ v332 ^ v351, 1);
	v249 = v238 + v246 + (v243 ^ v247) + __ROL4__(v244, 5) - 0x359D3E2A;
	v250 = __ROL4__(v325 ^ v342 ^ v182 ^ v364, 1);
	*v305 = v353;
	v251 = __ROL4__(v321 ^ v246 ^ v351 ^ v358, 1);
	v252 = v243 + v353 + (v244 ^ v248 ^ v245);
	v253 = __ROR4__(v244, 2);
	v254 = v252 + __ROL4__(v249, 5) - 0x359D3E2A;
	v305[1] = v250;
	v365 = __ROL4__(v339 ^ v232 ^ v353 ^ v364, 1);
	v255 = v250 + (v249 ^ v253 ^ v248);
	v256 = __ROR4__(v249, 2);
	v257 = v245 + v255 + __ROL4__(v254, 5) - 0x359D3E2A;
	v305[2] = v251;
	v258 = v248 + v251 + (v254 ^ v256 ^ v253);
	v259 = __ROR4__(v254, 2);
	v260 = v258 + __ROL4__(v257, 5) - 0x359D3E2A;
	v305[3] = v365;
	v261 = v257;
	v262 = __ROR4__(v257, 2);
	v263 = v253 + v365 + (v259 ^ v256 ^ v261) + __ROL4__(v260, 5) - 0x359D3E2A;
	v264 = __ROL4__(v203 ^ v234 ^ v250 ^ v358, 1);
	v305[4] = v264;
	v359 = v264;
	v265 = v259 ^ v260 ^ v262;
	v266 = __ROR4__(v260, 2);
	v267 = __ROL4__(v263, 5) + v264 - 0x359D3E2A + v265 + v256;
	v268 = __ROL4__(v339 ^ v213 ^ v329 ^ v251, 1);
	v305[5] = v268;
	v269 = v259 + v268 + (v263 ^ v266 ^ v262) - 0x359D3E2A;
	v270 = __ROR4__(v263, 2);
	v271 = __ROL4__(v203 ^ v317 ^ v342 ^ v365, 1);
	v272 = v269 + __ROL4__(v267, 5);
	v305[6] = v271;
	v273 = __ROL4__(v345 ^ v325 ^ v336 ^ v359, 1);
	v305[7] = v273;
	v274 = v262 - 0x359D3E2A + v271 + (v267 ^ v270 ^ v266) + __ROL4__(v272, 5);
	v275 = __ROR4__(v267, 2);
	v276 = __ROL4__(v274, 5) + v273 + (v272 ^ v275 ^ v270) - 0x359D3E2A + v266;
	v277 = __ROR4__(v272, 2);
	v278 = __ROL4__(v268 ^ v317 ^ v321 ^ v353, 1);
	v305[8] = v278;
	v279 = v274;
	v280 = __ROR4__(v274, 2);
	v281 = __ROL4__(v273 ^ v321 ^ v313 ^ v251, 1);
	v282 = v270 - 0x359D3E2A + v278 + (v277 ^ v275 ^ v279) + __ROL4__(v276, 5);
	v283 = __ROL4__(v271 ^ v325 ^ v309 ^ v250, 1);
	v305[9] = v283;
	v284 = v275 - 0x359D3E2A + v283 + (v277 ^ v276 ^ v280) + __ROL4__(v282, 5);
	v285 = __ROR4__(v276, 2);
	v305[0xA] = v281;
	v286 = v281 + (v282 ^ v285 ^ v280);
	v287 = __ROR4__(v282, 2);
	v288 = v277 - 0x359D3E2A + v286 + __ROL4__(v284, 5);
	v289 = __ROL4__(v278 ^ v309 ^ v329 ^ v365, 1);
	v305[0xB] = v289;
	v360 = __ROL4__(v313 ^ v342 ^ v283 ^ v359, 1);
	v290 = v280 + v289 + (v284 ^ v287 ^ v285);
	v291 = __ROR4__(v284, 2);
	v292 = v290 + __ROL4__(v288, 5) - 0x359D3E2A;
	v305[0xC] = v360;
	v293 = v360 + (v288 ^ v291 ^ v287);
	v294 = __ROR4__(v288, 2);
	v295 = v285 + v293 + __ROL4__(v292, 5) - 0x359D3E2A;
	v296 = __ROL4__(v268 ^ v329 ^ v336 ^ v281, 1);
	v305[0xD] = v296;
	v297 = __ROL4__(v271 ^ v342 ^ v289 ^ v353, 1);
	v305[0xE] = v297;
	v298 = v287 + v296 + (v294 ^ v291 ^ v292) - 0x359D3E2A + __ROL4__(v295, 5);
	v299 = __ROR4__(v292, 2);
	v300 = __ROL4__(v360 ^ v273 ^ v336 ^ v250, 1);
	v305[0xF] = v300;
	v301 = v297 + (v294 ^ v295 ^ v299);
	v302 = __ROR4__(v295, 2);
	v303 = v291 + v301 + __ROL4__(v298, 5) - 0x359D3E2A;
	result = v294 + __ROL4__(v303, 5) - 0x359D3E2A + v300 + (v298 ^ v302 ^ v299);
	*a1 += result;
	a1[1] += v303;
	a1[2] += __ROR4__(v298, 2);
	a1[3] += v302;
	a1[4] += v299;
	return result;
}
void* __fastcall md6_Update_(_DWORD* a1, char* a2, unsigned int a3){
	_DWORD* v6; // rbp
	unsigned int v7; // r9d
	unsigned int v8; // ecx
	unsigned int v9; // r9d
	unsigned int v10; // esi
	unsigned int i; // r14d

	if (a1[0x17])
		v6 = a1 + 0x18;
	else
		v6 = 0i64;
	v7 = a1[5];
	v8 = v7 + 8 * a3;
	v9 = (v7 >> 3) & 0x3F;
	a1[5] = v8;
	if (v8 < 8 * a3)
		++a1[6];
	a1[6] += a3 >> 0x1D;
	if (v9 + a3 <= 0x3F){
		v10 = 0;
	} else{
		v10 = 0x40 - v9;
		memcpy((char*)a1 + v9 + 0x1C, a2, 0x40 - v9);
		md6_step(a1, a1 + 7, v6);
		for (i = v10 + 0x3F; i < a3; i += 0x40){
			md6_step(a1, &a2[v10], v6);
			v10 += 0x40;
		}
		v9 = 0;
	}
	return memcpy((char*)a1 + v9 + 0x1C, &a2[v10], a3 - v10);
}
void* __fastcall md6_Update(MD6* a1, __int64 a2, unsigned int a3){
	return md6_Update_(a1->ctx.buffer, (char*)a2, a3);
}
void* __fastcall md6_Stuff_(_BYTE* a1, MD6Context* a2){
	unsigned int v2; // edi
	unsigned int v5; // r8d
	__int64* v6; // r9
	char v7; // cl
	unsigned __int8 v8; // al
	unsigned __int64 v9; // r8
	char v10; // al
	char v11; // cl
	unsigned __int64 v12; // rax
	__int64 v14; // [rsp+48h] [rbp+10h] BYREF

	v2 = 0;
	v5 = 0;
	v6 = &v14;
	do{
		v7 = 8 * (3 - (v5 & 3));
		*(_QWORD*)&v8 = v5++ < 4;
		*(_BYTE*)v6 = a2->buffer[*(_QWORD*)&v8 + 5] >> v7;
		v6 = (__int64*)((char*)v6 + 1);
	} while (v5 < 8);
	md6_Update_(a2, md6_padding, 1u);
	while ((a2->buffer[5] & 0x1F8) != 0x1C0)
		md6_Update_(a2, &md6_padding[4], 1u);
	md6_Update_(a2, (char*)&v14, 8u);
	v9 = 0i64;
	do{
		v10 = v2++;
		v11 = 3 - (v10 & 3);
		v12 = v9++;
		*a1++ = a2->buffer[v12 >> 2] >> (8 * v11);
	} while (v2 < 0x14);
	memset(&a2->buffer[7], 0, 0x40ui64);
	memset(a2, 0, 0x14ui64);
	memset(&a2->buffer[5], 0, 8ui64);
	memset(&v14, 0, sizeof(v14));
	return memset(&a2[1], 0, 0x40ui64);
}
void* __fastcall md6_Stuff(MD6* a1){
	return md6_Stuff_(a1->padding, &a1->ctx);
}
__int64 ctor_md6_VT(){
	md6_VT* VT; // rax

	VT = (md6_VT*)put_in_buf_0x28(3);
	if (!VT)
		return 1i64;
	VT->ctor = (QWORD)md6_ctor;
	VT->f1 = (QWORD)md6_Update;
	VT->f2 = (QWORD)md6_Stuff;
	VT->dtor = (QWORD)md6_dtor;
	return 1i64;
}


char* __fastcall alloc_to_STR_tree(int len, int apos){
	int v3; // [rsp+20h] [rbp-28h]
	strNode* Value; // [rsp+28h] [rbp-20h]
	char* v5; // [rsp+30h] [rbp-18h]

	Value = (strNode*)TlsGetValue(g_dwTlsIndex);
	if (apos == -1)
		apos = Value->slen;
	v3 = Value->slen + 2 * len;
	if (v3 < Value->ssize - 4i64){
		if ((__int64)Value->ssize > 0x100000){
			if (v3 < 0x100000)
				v3 = 0x100000;
			Value->ssize = v3;
			Value->str = (char*)HeapReAlloc(heap_HANDLE, 0, Value->str, Value->ssize + 0xAi64);
		}
	} else{
		Value->ssize = v3 + 0x4000;
		Value->str = (char*)HeapReAlloc(heap_HANDLE, 0, Value->str, Value->ssize + 0xAi64);
	}
	v5 = &Value->str[apos];
	Value->slen = apos + 2i64 * len;
	return v5;
}
char* __fastcall toHexStr(_DWORD* src, int apos){
	int len; // esi
	char* result; // rax
	__int64 strend; // r9
	char* strP; // rdx
	unsigned __int8* v7; // r8
	unsigned __int64 v8; // rcx

	len = 0;
	if (src)
		len = *src / 8;
	result = alloc_to_STR_tree(2 * len, apos);
	strend = len;
	strP = result;
	if (len <= 0){
		*(_WORD*)result = 0;
	} else{
		v7 = (unsigned __int8*)(src + 1);
		do{
			v8 = *v7;
			strP += 4;
			++v7;
			*((_WORD*)strP - 2) = a0123456789abcd[v8 >> 4];
			result = (char*)(unsigned int)a0123456789abcd[v7[-1] & 0xF];
			*((_WORD*)strP - 1) = a0123456789abcd[v7[-1] & 0xF];
			--strend;
		} while (strend);
		*(_WORD*)strP = 0;
	}
	return result;
}
void __fastcall SET_TLS_2(__int64 a1){
	DWORD dwErrCode; // [rsp+38h] [rbp-10h]

	dwErrCode = GetLastError();
	*((_QWORD*)TlsGetValue(g_dwTlsIndex) + 2) = a1;
	SetLastError(dwErrCode);
}
strNode* __fastcall STR_tree_root(){
	return *(strNode**)TlsGetValue(g_dwTlsIndex);
}
__int64 __fastcall GET_STR_IN_tree(wchar_t* a1){
	strNode* Value; // [rsp+20h] [rbp-18h]

	Value = (strNode*)TlsGetValue(g_dwTlsIndex);
	if ((char*)a1 < Value->str || (char*)a1 > &Value->str[Value->slen])
		return 0i64;
	else
		return (char*)a1 - Value->str + 1;
}
__int64 __fastcall GET_CHAR_AT_tree(int a1){
	return *(_QWORD*)TlsGetValue(g_dwTlsIndex) + a1 - 1i64;
}
__int64 STR_tree_root_0(){
	return *(_QWORD*)TlsGetValue(g_dwTlsIndex);
}
void __fastcall SETDW(_DWORD* a1, int a2){
	*a1 = a2;
}
unsigned __int64 __fastcall mywstrlen(wchar_t* a1){
	unsigned __int64 result; // rax

	if (!a1)
		return 0i64;
	result = -1i64;
	do
		++result;
	while (a1[result]);
	return result;
}
LPWSTR __fastcall MyCharUpperW(wchar_t* a1, int apos){
	wchar_t* str; // rbx
	int len; // edi
	int v5; // ebp
	char* v6; // rdi
	signed __int64 v7; // rcx
	wchar_t v8; // ax
	LPWSTR result; // rax

	str = a1;
	len = mywstrlen(a1);
	v5 = GET_STR_IN_tree(str);
	v6 = alloc_to_STR_tree(len, apos);
	if (v5)
		str = (wchar_t*)GET_CHAR_AT_tree(v5);
	if (str){
		v7 = v6 - (char*)str;
		do{
			v8 = *str++;
			*(wchar_t*)((char*)str + v7 - 2) = v8;
		} while (v8);
		return CharUpperW((LPWSTR)v6);
	} else{
		result = 0i64;
		*(_WORD*)v6 = 0;
	}
	return result;
}
unsigned int __fastcall md_Stuff2(__int64 a1, unsigned int a2, int a3, unsigned int a4, int a5){
	MD5* v8; // rbx
	md5_VT* md_vt1; // rax
	md5_VT* md_vt2; // rdi
	MD5* md56; // rax
	unsigned int result; // eax

	v8 = 0i64;
	md_vt1 = (md5_VT*)find_in_buf_0x28(a3);
	md_vt2 = md_vt1;
	if (md_vt1){
		md56 = md_vt1->ctor(a4, 1i64);
		v8 = md56;
		if (md56){
			md_vt2->f1_md5_Update(md56, a1, a2);
			md_vt2->f2_md5_Stuff(v8);
		}
	}
	result = (unsigned int)toHexStr(v8, a5);
	if (v8)
		//return md_vt2->dtor(v8);
		md_vt2->dtor(v8);
	return result;
}
unsigned int __fastcall md_Stuff3(__int64 a1, unsigned int a2, int a3, int a4){
	return md_Stuff2(a1, a2, a3, 0, a4);
}
__int64 __fastcall asm_initMdStuff(__int64 a1, __int64 a2, __int64 a3, __int64 a4, __int64 a5){
	int v5; // eax
	strNode* v6; // rax
	__int64 v8[13]; // [rsp+0h] [rbp-68h] BYREF
	int v9;

	v8[11] = 0i64;
	init_RSO();
	SET_TLS_2(a5);
	LODWORD(v8[0xA]) = *(_DWORD*)&g_salt[4];
	g_DATA.g_cursor = (_QWORD*)(g_salt + 8);
	SETDW(&v8[0xB], *(int*)g_salt);
	SETDW((_DWORD*)&v8[0xB] + 1, v8[0xA]);
	GET_TLS_StrLen();
	GET_TLS_StrLen();
	v9 = GET_TLS_StrLen();
	v5 = GET_TLS_StrLen();
	md_Stuff3((unsigned __int64)&v8[0xB], 8, 1, v5);
	//md_Stuff3((unsigned __int64)v8[0xB], 8, 1, v5);
	v6 = STR_tree_root();
	//MyCharUpperW((wchar_t*)((char*)v6 + v8[0]), v8[1]);
	MyCharUpperW((wchar_t*)&v6->str, v9);
	return v8[3] + STR_tree_root_0();
}
_BYTE* __fastcall myWideCharToMultiByte(LPCWCH lpWideCharStr){
	unsigned __int64 v2; // rbx
	int v4; // eax
	int cbMultiByte; // ebp
	CHAR* lpMultiByteStr; // rax
	CHAR* v7; // rsi
	__int64 v8; // rcx
	_BYTE* result; // rax

	if (!lpWideCharStr)
		goto LABEL_7;
	v2 = -1ui64;
	while (lpWideCharStr[++v2] != 0)
		;
	v4 = WideCharToMultiByte(_MB_CP_UTF8, 0, lpWideCharStr, v2 + 1, 0i64, 0, 0i64, 0i64);
	cbMultiByte = v4;
	if (v4 && (lpMultiByteStr = (CHAR*)malloc(v4 + 1i64), (v7 = lpMultiByteStr) != 0i64)){
		v8 = WideCharToMultiByte(_MB_CP_UTF8, 0, lpWideCharStr, v2 + 1, lpMultiByteStr, cbMultiByte, 0i64, 0i64);
		result = v7;
		v7[v8] = 0;
	} else{
LABEL_7:
		result = malloc(1ui64);
		*result = 0;
	}
	return result;
}
__int64 __fastcall mywcsstr(const wchar_t* a1, const wchar_t* a2){
	wchar_t* v3; // rax

	if (a1 && a2 && *a1 && *a2 && (v3 = wcsstr(a1, a2)) != 0i64)
		return v3 - a1 + 1;
	else
		return 0i64;
}
void __cdecl j_free(void* Block){
	free(Block);
}
unsigned int __fastcall MD_stuff(const WCHAR* awStr, int aMDType, int aPos){
	MD5* md56; // rbx
	md5_VT* md_vt1; // rax
	md5_VT* md_vt2; // rsi
	const WCHAR* wstr; // rdi
	_BYTE* str; // rax
	unsigned __int64 len; // r8
	void* str_1; // rdi
	unsigned int result; // eax

	md56 = 0i64;
	md_vt1 = (md5_VT*)find_in_buf_0x28(aMDType);
	md_vt2 = md_vt1;
	if (md_vt1){
		wstr = (const WCHAR*)&nullstr;
		if (awStr)
			wstr = awStr;
		md56 = md_vt1->ctor(0i64, 1i64);
		if (md56){
			str = myWideCharToMultiByte(wstr);
			len = -1ui64;
			str_1 = str;
			do
				++len;
			while (str[len]);

			md_vt2->f1_md5_Update(md56, (__int64)str, len);
			md_vt2->f2_md5_Stuff(md56);
			j_free(str_1);
		}
	}
	result = (unsigned int)toHexStr(md56, aPos);
	if (md56)
		md_vt2->dtor(md56);
	return result;
}

__int64 __fastcall asm_initMdStuff0(	__int64 a1,__int64 a2,__int64 a3,__int64 a4,__int64 a5){
	int v5; // eax
	strNode* v6; // rax
	__int64 v8; // [rsp+0h] [rbp-68h]
	int v9; // [rsp+8h] [rbp-60h]
	__int64 v10; // [rsp+18h] [rbp-50h]
	int v11; // [rsp+50h] [rbp-18h]
	__int64 v12[2]; // [rsp+58h] [rbp-10h] BYREF

	v12[0] = 0i64;
	init_RSO();
	SET_TLS_2(a5);
	v11 = *(_DWORD*)&g_salt[4];
	g_DATA.g_cursor = (_QWORD*)(g_salt + 8);
	SETDW(v12, *(int*)g_salt);
	SETDW((_DWORD*)v12 + 1, v11);
	GET_TLS_StrLen();
	GET_TLS_StrLen();
	GET_TLS_StrLen();
	v5 = GET_TLS_StrLen();
	// rcx = var10
	// rdx = 8, ...1,0
	md_Stuff3((__int64)v12[0], 8u, 1, v5);
	v6 = STR_tree_root();
	MyCharUpperW((wchar_t*)((char*)v6 + v8), v9);
	return v10 + STR_tree_root_0();
}

__int64 sub_1400021EA();
void sub_14000593C();
void start(){
	__int64 v0; // rcx
	int v1; // eax
	__int64 v2; // rcx
	__int64 v3; // rax
	__int64 v4; // rdx
	__int64 v5; // r8
	__int64 v6; // r9
	__int64 v7; // [rsp-10h] [rbp-38h]
	__int64 v8; // [rsp-8h] [rbp-30h]

	memset(&g_DATA, 0, 0x160ui64);
	g_DATA.g_hModule = GetModuleHandleW(0i64);
	g_DATA.g_hHeap = HeapCreate(0, 0x1000ui64, 0i64);
	g_DATA.g_cursor = (_QWORD*)g_salt;
	create_and_alloc_STRtree();
	initMainVT();
	init_g_stru_0x60_10();
	init_VT_0x60_2();
	init_VT_0x60();
	ZHeapCreate();
	init_g_TLS_8_g_stru60_4();
	MyInitCommonControls();
	InitCriticalSection();
	ctor_md5_VT();
	ctor_md6_VT();
	my_wstrcpy((LPVOID*)&g_DATA.g_copy_of_star, (wchar_t*)"*");
	g_DATA.g_hSTD_OUTPUT_HANDLE = (__int64)GetStdHandle(STD_OUTPUT_HANDLE);
	ctor_0x60(8ui64, 0x15u, 0i64, (stru_602*)&g_DATA.g_stu602_root, 0x200);
	dtor_0x60_2((stru_601*)g_DATA.g_root_601_1);
	ctor_0x60_2(0xCi64, (root_601**)&g_DATA.g_root_601_1, &g_MASK[2], 7u);
	dtor_0x60_2((stru_601*)g_DATA.g_root_601_2);
	ctor_0x60_2(8i64, (root_601**)&g_DATA.g_root_601_2, g_MASK, 8u);
	g_DATA.g_200020 = (QWORD*)fn_alloc_obj1(20ui64, 100001ui64, 7, &g_MASK[4], (void**)&g_DATA.g_200020);
	my_wstrcpy((LPVOID*)&g_DATA.g_copy_of_slash, "\\");

	dtor_0x60_2((stru_601*)g_DATA.g_root_601_3);
	ctor_0x60_2(8i64, (root_601**)&g_DATA.g_root_601_3, g_MASK, 8u);

	//AddVectoredExceptionHandler__((stru0x20*)ShowExeptionMessageBox);

	//v8 = v0;
	v1 = GET_TLS_StrLen();
	//v2 = v8;
	//LODWORD(v8) = v1;
	//v7 = v2;
	v3 = GET_TLS_StrLen();
	//asm_initMdStuff(v7, v4, v5, v6, v3);
	asm_initMdStuff(0, 0, 0, 0, v3);
	dup_from_STR_tree((LPVOID*)&g_DATA.field_78, v1);

	sub_1400021EA();
//	if (g_DATA.g_IsCmdLinesEQ == 1)
//		sub_14000433F();
	sub_14000593C();
}


__int64 __fastcall TLS_cutr_str(int a1){
	__int64 result; // rax
	strNode* Value; // [rsp+20h] [rbp-18h]

	Value = (strNode*)TlsGetValue(g_dwTlsIndex);
	result = Value->slen - 2 * a1;
	Value->slen = result;
	return result;
}
void __fastcall MyGetModuleFileNameW(int apos){
	WCHAR* filename; // rsi
	signed int len; // ebx

	filename = (WCHAR*)alloc_to_STR_tree(0x104, apos);
	len = GetModuleFileNameW(g_DATA.g_hModule, filename, 0x104u);
	if (!wcscmp(filename, L"\\\\?\\")){
		len -= 4;
		memmove(filename, filename + 4, 2i64 * len);
	}
	TLS_cutr_str(0x104 - len);
	filename[len] = 0;
}

QWORD __fastcall stru601_f4(stru_601* a1){
	return a1->f4;
}
__int64 __fastcall stru601_f0f2(stru_601* a601){
	__int64* f2; // rax
	__int64 result; // rax

	f2 = (__int64*)a601->f2;
	if (f2){
		result = *f2;
		if (result){
			++a601->f5;
			a601->f2 = result;
LABEL_5:
			result += 0x10i64;
		}
	} else{
		result = a601->f0;
		a601->f5 = 0i64;
		a601->f2 = result;
		if (result)
			goto LABEL_5;
	}
	a601->root_next->left = a601->f2;
	return result;
}
root_601* __fastcall stru601_root_next(stru_601* a601){
	root_601* result; // rax

	result = a601->root_next;
	a601->f2 = 0i64;
	a601->f5c = 1;
	result->left = 0i64;
	return result;
}
void __fastcall add_to_STR_treeR(wchar_t* a1){
	int v1; // [rsp+20h] [rbp-18h]
	char* v2; // [rsp+28h] [rbp-10h]

	v1 = 0;
	if (a1)
		v1 = wcslen(a1);
	v2 = alloc_to_STR_tree(v1, -1);
	if (a1)
		wstrcpy(v2, a1, v1);
	else
		*(_WORD*)&v2[2 * v1] = 0;
}
__int64 __fastcall wStrReverse(wchar_t* awStr, int aPos){
	wchar_t* wStr; // rbx
	unsigned __int64 len; // rdi
	int v5; // esi
	char* v6; // r14
	wchar_t* v7; // rdx
	signed __int64 v8; // r9
	signed __int64 v9; // r8
	wchar_t v10; // ax
	wchar_t v11; // cx
	__int64 result; // rax

	wStr = (wchar_t*)&nullstr;
	if (awStr)
		wStr = awStr;

	len = -1ui64;
	do
		++len;
	while (wStr[len]);

	v5 = GET_STR_IN_tree(wStr);
	v6 = alloc_to_STR_tree(len, aPos);
	if ((_DWORD)len){
		if (v5)
			wStr = (wchar_t*)GET_CHAR_AT_tree(v5);
		v7 = &wStr[(int)len - 1];
		if (wStr <= v7){
			v8 = v6 - (char*)wStr;
			v9 = &v6[2 * (int)len - 2] - (char*)v7;
			do{
				v10 = *v7;
				v11 = *wStr;
				v7 += -1;
				*(wchar_t*)((char*)wStr + v8) = v10;
				*(wchar_t*)((char*)v7 + v9 + 2) = v11;
				++wStr;
			} while (wStr <= v7);
		}
	}
	result = (int)len;
	*(_WORD*)&v6[2 * (int)len] = 0;
	return result;
}
bool __fastcall mywcscmp(wchar_t* a1, wchar_t* a2){
	wchar_t* String1; // [rsp+30h] [rbp+8h]
	wchar_t* String2; // [rsp+38h] [rbp+10h]

	String2 = a2;
	String1 = a1;
	if (!a1)
		String1 = (wchar_t*)&nullstr1;
	if (!a2)
		String2 = (wchar_t*)&nullstr2;
	return wcscmp(String1, String2) == 0;
}
int __fastcall free_fn(char* lpMem){
	_QWORD* i; // rbx
	__int64(__fastcall * v3)(char*); // rdx
	int result; // eax

	for (i = (_QWORD*)g_root_unk028; i; i = (_QWORD*)*i){
		v3 = (__int64(__fastcall*)(char*))i[4];
		if (v3)
			result = v3(&lpMem[i[2]]);
	}
	if (lpMem)
		return HeapFree(g_DATA.g_hHeap, 0, lpMem);
	return result;
}
__int64 add2_to_StrTreeLen(){
	__int64 result; // rax
	strNode* Value; // [rsp+20h] [rbp-18h]

	Value = (strNode*)TlsGetValue(g_dwTlsIndex);
	result = Value->slen + 2i64;
	Value->slen = result;
	return result;
}
char* __fastcall STR_Tree_Last(int a1){
	strNode* Value; // rax

	Value = (strNode*)TlsGetValue(g_dwTlsIndex);
	Value->slen = a1;
	return &Value->str[Value->slen];
}
char* __fastcall TLS_8_GetLast_or_Recall(__int64 aOfs){
	unk001* Value; // rdi
	unk028* val; // rbx
	void(__fastcall * function)(char*); // rdx

	Value = (unk001*)TlsGetValue(g_TLS_8);
	if (Value)
		return (char*)Value + aOfs;

	Value = (unk001*)HeapAlloc(g_DATA.g_hHeap, HEAP_ZERO_MEMORY, g_TLS_8_allocated_size);
	TlsSetValue(g_TLS_8, Value);

	for (val = (unk028*)g_root_unk028; val; val = (unk028*)val->f0){
		function = (void(__fastcall*)(char*))val->function;
		if (function)
			function((char*)Value + val->offset);
	}
	add_to_rso(free_fn, Value);
	return (char*)Value + aOfs;
}
LPWSTR __stdcall asm_MyGetCommandLine2(_DWORD* a1){
	int v2; // esi
	char* Ptr; // r14
	WCHAR* v4; // rbx
	LPWSTR cmdline; // rax
	WCHAR cmdCH; // dx
	LPWSTR v7; // rcx
	WCHAR v8; // dx
	int v9; // r8d
	WCHAR cmdCH_1; // cx
	__int16 v11; // cx
	WCHAR* v12 = 0; // [rsp+40h] [rbp+8h]

	v2 = -1;
	Ptr = TLS_8_GetLast_or_Recall(g_TLS_8_pos);
	v4 = 0i64;
	cmdline = GetCommandLineW();
	cmdCH = *cmdline;
	if (!*cmdline){
LABEL_27:
		if (!a1)
			return (LPWSTR)v2;
		goto LABEL_31;
	}
	v7 = v12;
	while (1){
		if (cmdCH == 0x20){
			do
				++cmdline;
			while (*cmdline == 0x20);
		}
		v8 = *cmdline;
		v9 = 1;
		if (*cmdline == 0x22){
			v4 = ++cmdline;
			cmdCH_1 = *cmdline;
			if (!*cmdline)
				goto LABEL_20;
			do{
				if (cmdCH_1 == 0x22)
					break;
				cmdCH_1 = *++cmdline;
			} while (*cmdline);
		} else{
			if (!v8){
				v9 = 0;
				goto LABEL_22;
			}
			v4 = cmdline;
			do{
				if (v8 == 0x20)
					break;
				if (*++cmdline == 0x22){
					v11 = *++cmdline;
					if (!*cmdline)
						goto LABEL_20;
					do{
						if (v11 == 0x22)
							break;
						v11 = *++cmdline;
					} while (*cmdline);
				}
				v8 = *cmdline;
			} while (*cmdline);
		}
		if (!*cmdline){
LABEL_20:
			v7 = cmdline;
			goto LABEL_22;
		}
		v7 = cmdline++;
LABEL_22:
		if (*(_DWORD*)Ptr == v2 && a1)
			break;
		if (v9)
			++v2;
		cmdCH = *cmdline;
		v4 = 0i64;
		if (!*cmdline)
			goto LABEL_27;
	}
	if (v4){
		cmdline = v4;
		*a1 = v7 - v4;
		++* (_DWORD*)Ptr;
		return cmdline;
	}
LABEL_31:
	*a1 = 0;
	return cmdline;
}
LPWSTR __fastcall asm_MyGetCommandLine_TLS_8(){
	TLS_8_GetLast_or_Recall(g_TLS_8_pos);
	return asm_MyGetCommandLine2(0i64);
}
__int64 __fastcall cmdline_to_STR_Tree(int ecx0, int aPos){
	char* Last_or_Recall; // rax
	LPWSTR CommandLine2; // rax
	int v6; // edi
	LPWSTR v7; // rbx
	char* v8; // rax
	int v9; // ecx
	int a1; // [rsp+30h] [rbp+8h] BYREF

	a1 = 0;
	Last_or_Recall = TLS_8_GetLast_or_Recall(g_TLS_8_pos);
	if (ecx0 >= 0)
		*(_DWORD*)Last_or_Recall = ecx0;
	CommandLine2 = asm_MyGetCommandLine2(&a1);
	v6 = a1;
	v7 = CommandLine2;
	v8 = alloc_to_STR_tree(a1, aPos);
	v9 = 0;
	while (*v7 && v6){
		if (*v7 == '"'){
			++v9;
		} else{
			*(_WORD*)v8 = *v7;
			v8 += 2;
		}
		++v7;
		--v6;
	}
	*(_WORD*)v8 = 0;
	return TLS_cutr_str(v9);
}
_WORD* __fastcall add_to_STR_tree_AT(wchar_t* Src, int apos){
	__int64 len; // rbx
	_WORD* result; // rax
	_WORD* v5; // rsi

	LODWORD(len) = 0;
	if (Src){
		len = -1i64;
		do
			++len;
		while (Src[len]);
	}

	result = alloc_to_STR_tree(len, apos);
	v5 = result;
	if ((_DWORD)len)
		result = memcpy(result, Src, 2i64 * (int)len);
	v5[(int)len] = 0;
	return result;
}
__int64 __stdcall EnumResNameW(__int64 hModule, __int64 lpType, wchar_t* lpName, __int64 lParam){
	int v4; // eax
	int v6; // [rsp-38h] [rbp-40h]

	init_RSO();
	fn_stru601((stru_601*)g_DATA.g_root_601_3);
	v6 = GET_TLS_StrLen();
	v4 = GET_TLS_StrLen();
	add_to_STR_tree_AT(lpName, v4);
	dup_from_STR_tree((LPVOID*)(g_DATA.field_150 + 0x10), v6);
	return 1i64;
}
__int64 __stdcall EnumResTypeW(HMODULE hModule, __int64 lpType, __int64 lParam){
	init_RSO();
	if (lpType == RT_RCDATA)
		EnumResourceNamesW(hModule, (LPCWSTR)RT_RCDATA, (ENUMRESNAMEPROCW)EnumResNameW, 0i64);
	return 1i64;
}
_DWORD* __fastcall wstrstuff(wchar_t* awStr, int a2, int aPos){
	wchar_t* v5; // rsi
	int v6; // eax
	int v7; // ebp
	int v8; // r14d
	_DWORD* result; // rax
	_DWORD* v10; // rbx

	v5 = awStr;
	v6 = mywstrlen(awStr);
	if (a2 < 0)
		a2 = 0;
	v7 = v6;
	if (v6 > a2)
		v7 = a2;
	v8 = GET_STR_IN_tree(v5);
	result = alloc_to_STR_tree(v7, aPos);
	v10 = result;
	if (v8){
		result = (_DWORD*)GET_CHAR_AT_tree(v8);
		v5 = (wchar_t*)result;
	}
	if (v5 && v7 > 0)
		return (_DWORD*)wstrcpy(v10, v5, v7);
	*(_WORD*)v10 = 0;
	return result;
}
__int64 sub_1400021EA(){
	int at; // eax
	strNode* v1; // rax
	HMODULE hmod1; // rax
	__int64 v3; // rcx
	int v4; // eax
	wchar_t* v5; // rcx
	int v6; // eax
	wchar_t* v7; // rcx
	int v8; // eax
	wchar_t* v9; // rcx
	int v10; // eax
	strNode* v11; // rax
	strNode* v12; // rax
	int v13; // eax
	wchar_t* v14; // rcx
	int v15; // eax
	strNode* v16; // rax
	int v17; // eax
	__int64 CommandLine_TLS_8; // rax
	int v19; // eax
	int v20; // edx
	char* v21; // rax
	int v22; // eax
	__int64 v24; // [rsp+0h] [rbp-A0h]
	int v25; // [rsp+8h] [rbp-98h]
	__int64 v26; // [rsp+10h] [rbp-90h]
	int v27; // [rsp+10h] [rbp-90h]
	HANDLE v28; // [rsp+18h] [rbp-88h]
	__int64 v29; // [rsp+18h] [rbp-88h]
	__int64 v30; // [rsp+18h] [rbp-88h]
	DWORD v31; // [rsp+20h] [rbp-80h]
	int v32; // [rsp+20h] [rbp-80h]
	int v33; // [rsp+20h] [rbp-80h]
	QWORD v34; // [rsp+30h] [rbp-70h]
	HMODULE hmod2; // [rsp+30h] [rbp-70h]
	wchar_t* v36; // [rsp+30h] [rbp-70h]
	wchar_t* v37; // [rsp+30h] [rbp-70h]
	wchar_t* v38; // [rsp+30h] [rbp-70h]
	int v39; // [rsp+30h] [rbp-70h]
	WCHAR* v40; // [rsp+30h] [rbp-70h]
	int v41; // [rsp+30h] [rbp-70h]
	wchar_t* v42; // [rsp+30h] [rbp-70h]
	int v43; // [rsp+30h] [rbp-70h]
	__int64 v44; // [rsp+30h] [rbp-70h]
	wchar_t* v45; // [rsp+68h] [rbp-38h] BYREF
	wchar_t* v46; // [rsp+70h] [rbp-30h] BYREF
	wchar_t* v47; // [rsp+78h] [rbp-28h] BYREF
	WCHAR* v48; // [rsp+80h] [rbp-20h] BYREF
	wchar_t* v49; // [rsp+88h] [rbp-18h] BYREF

	v49 = 0i64;
	v48 = 0i64;
	v47 = 0i64;
	v46 = 0i64;
	v45 = 0i64;
	init_RSO();
	v34 = GET_TLS_StrLen();
	GET_TLS_StrLen();
	at = GET_TLS_StrLen();
	MyGetModuleFileNameW(at);

	v1 = STR_tree_root();
	//hmod1 = LoadLibraryExW((LPCWSTR)((char*)v1 + v26), 0, LOAD_LIBRARY_AS_DATAFILE/*v31*/);
	//hmod1 = LoadLibraryExW((LPCWSTR)v1, 0, LOAD_LIBRARY_AS_DATAFILE/*v31*/);
	hmod1 = LoadLibraryExW(L"ASRES.DLL", 0, LOAD_LIBRARY_AS_DATAFILE/*v31*/);

	v3 = v34;
	hmod2 = hmod1;
	SET_TLS_2(v3);
	EnumResourceTypesW(hmod2, (ENUMRESTYPEPROCW)EnumResTypeW, 0i64);
	FreeLibrary(hmod2);

	if ((__int64)stru601_f4((stru_601*)g_DATA.g_root_601_3) <= 0)
		goto LABEL_12;
	stru601_root_next((stru_601*)g_DATA.g_root_601_3);
	while (stru601_f0f2((stru_601*)g_DATA.g_root_601_3)){
		v36 = *(wchar_t**)(g_DATA.field_150 + 0x10);
		v4 = GET_TLS_StrLen();
		v5 = v36;
		LODWORD(v36) = v4;
		add_to_STR_treeR(v5);
		dup_from_STR_tree((LPVOID*)&v45, (int)v36);
		if ((__int64)mywstrlen(v45) <= 0xA){
			v38 = v45;
			v8 = GET_TLS_StrLen();
			v9 = v38;
			LODWORD(v38) = v8;
			add_to_STR_treeR(v9);
			dup_from_STR_tree((LPVOID*)&v47, (int)v38);
		} else{
			v37 = v46;
			v6 = GET_TLS_StrLen();
			v7 = v37;
			LODWORD(v37) = v6;
			add_to_STR_treeR(v7);
			add_to_STR_treeR(v45);
			dup_from_STR_tree((LPVOID*)&v46, (int)v37);
		}
	}
	stru601_dtor((stru_601*)g_DATA.g_root_601_3);
	v39 = GET_TLS_StrLen();
	GET_TLS_StrLen();
	GET_TLS_StrLen();
	GET_TLS_StrLen();
	v27 = GET_TLS_StrLen();
	v10 = GET_TLS_StrLen();
	int x = wStrReverse(v46, v10);
	v11 = STR_tree_root();
	// wStrReverse + v11, 1, strlen
	//MD_stuff((const WCHAR*)((char*)v11 + v24), v25, v27);
	//MD_stuff((const WCHAR*)((char*)v11 + x), 1, v27);
	MD_stuff((const WCHAR*)((char*)v11), 1, v27);
	v12 = STR_tree_root();
	//MyCharUpperW((wchar_t*)((char*)v12 + v29), v32);
	MyCharUpperW((wchar_t*)((char*)v12), v27);
	dup_from_STR_tree((LPVOID*)&v48, v39);
	v40 = v48;
	v13 = GET_TLS_StrLen();
	v14 = v40;
	LODWORD(v40) = v13;
	add_to_STR_treeR(v14);
	dup_from_STR_tree((LPVOID*)&v49, (int)v40);
	LODWORD(v40) = GET_TLS_StrLen();
	v33 = GET_TLS_StrLen();
	v30 = GET_TLS_StrLen();
	v15 = GET_TLS_StrLen();
	MD_stuff(v48, 1, v15);
	v16 = STR_tree_root();
	MyCharUpperW((wchar_t*)((char*)v16 + v30), v33);
	dup_from_STR_tree((LPVOID*)&v48, (int)v40);
	LODWORD(v40) = GET_TLS_StrLen();
	v17 = GET_TLS_StrLen();
	wstrstuff(v48, 0xA, v17);
	dup_from_STR_tree((LPVOID*)&v48, (int)v40);
	if (!mywcscmp(v48, v47)) {
LABEL_12:
		exit(0);//JUMPOUT(0x14000123Bi64);
	}
	CommandLine_TLS_8 = (__int64)asm_MyGetCommandLine_TLS_8();
	if (CommandLine_TLS_8){
		GET_TLS_StrLen();
		v19 = GET_TLS_StrLen();
		cmdline_to_STR_Tree(0, v19);
		add2_to_StrTreeLen();
		v20 = v41;
		v42 = v49;
		v21 = STR_Tree_Last(v20);
		CommandLine_TLS_8 = mywcscmp(v42, (wchar_t*)v21);
		if (CommandLine_TLS_8){
			g_DATA.g_IsCmdLinesEQ = 1i64;
			v43 = GET_TLS_StrLen();
			v22 = GET_TLS_StrLen();
			cmdline_to_STR_Tree(1, v22);
			CommandLine_TLS_8 = dup_from_STR_tree((LPVOID*)&g_DATA.g_wCommandLine, v43);
		}
	}
	v44 = CommandLine_TLS_8;
	HeapFree__0(v45);
	HeapFree__0(v47);
	HeapFree__0(v46);
	HeapFree__0(v49);
	HeapFree__0(v48);
	return v44;
}


//------
// overflow flag of addition (x+y)
//template<class T, class U> int8 __OFADD__(T x, U y){
int8  __SETS__ (/*T,*/ int64 x){
	if (sizeof(int64) == 1)
		return (int8)x < 0;			
	if (sizeof(int64) == 2)
		return (int16)x < 0;		
	if (sizeof(int64) == 4)
		return (int32)x < 0;		
	return (int64)x < 0;			
}

#undef __OFADD__
int8 __OFADD__(int64/*T*/ x, int64/*U*/ y){
	if (sizeof(int64) < sizeof(int64)){
		int64 x2 = x;
		int8 sx = __SETS__(x2);
		return ((1 ^ sx) ^ __SETS__(y)) & (sx ^ __SETS__((int64)(x2 + y)));
	} else{
		int64 y2 = y;
		int8 sx = __SETS__(x);
		return ((1 ^ sx) ^ __SETS__(y2)) & (sx ^ __SETS__((int64)(x + y2)));
	}
}
__int64 __fastcall myCmpItem(__int16* a1, __int16* a2){
	int Result; // r9d
	__int16 item2; // bx
	__int16 item1; // ax
	__int16 item1_2; // dx
	__int16* item2_2; // rax
	__int16* v8; // r10

	Result = 0;
	if (!a1)
		return Result;
	if (!a2)
		return Result;
	item2 = *a2;
	if (!*a2)
		return Result;
	item1 = *a1;
	while (*a1){
		++a1;
		if (item1 == item2){
			item1_2 = *a1;
			item2_2 = a2 + 1;
			v8 = a1;
			if (*a1){
				while (*item2_2){
					if (item1_2 == *item2_2){
						item1_2 = a1[1];
						++a1;
						++item2_2;
						if (item1_2)
							continue;
					}
					goto LABEL_10;
				}
			} else{
LABEL_10:
				if (*item2_2){
					a1 = v8;
					goto LABEL_13;
				}
			}
			++Result;
		}
LABEL_13:
		item1 = *a1;
	}
	return Result;
}
HANDLE* __fastcall ResizeStru60(stru_0x60* a1, __int64 numel){
	struct _RTL_CRITICAL_SECTION* p_lpCriticalSection; // rsi
	HANDLE* v5; // rbx
	void* mem; // r8
	QWORD v7; // r9
	void(__fastcall * fn_free)(__int64); // rax

	p_lpCriticalSection = &a1->lpCriticalSection;
	EnterCriticalSection(&a1->lpCriticalSection);
	if (numel == -1){
		v5 = add_to_tree((stru0x20*)&a1->fld03, a1->itemsize + 0x10);
	} else{
		if (numel >= (signed __int64)a1->qallocatedx8){
			mem = (void*)a1->mem;
			v7 = numel + (int)a1->sizex8;
			a1->qallocatedx8 = v7;
			a1->mem = (QWORD)HeapReAlloc(g_DATA.g_hHeap, 8u, mem, 8 * v7);
		}

		if (*(_QWORD*)(a1->mem + 8 * numel)){
			fn_free = (void(__fastcall*)(__int64))a1->fn_free;
			if (fn_free)
				fn_free(numel);
		} else{
			*(_QWORD*)(a1->mem + 8 * numel) = HeapAlloc(g_DATA.g_hHeap, 8u, (int)a1->itemsize);
		}

		v5 = *(HANDLE**)(a1->mem + 8 * numel);
	}
	LeaveCriticalSection(p_lpCriticalSection);
	return v5;
}
file_holder* __fastcall CreateFileW_0(__int64 aAT, const WCHAR* lpFN, int aMoveMethod, int aFlags){
	__int64 at; // rbp
	HANDLE handle_1; // rbx
	int cd; // eax
	file_holder* fileholder; // rdi
	DWORD dwSM0; // r8d
	HANDLE handle; // rsi
	DWORD dwSM1; // r8d
	DWORD dwSM2; // r14d
	LONG DistanceToMoveHigh[2]; // [rsp+40h] [rbp-38h] BYREF
	DWORD CreationDisposition; // [rsp+98h] [rbp+20h]

	at = aAT;
	handle_1 = 0i64;
	cd = aFlags & 0x1F;
	if ((aFlags & 0x1F) == 0)
		cd = CREATE_ALWAYS;
	CreationDisposition = cd;
	fileholder = (file_holder*)ResizeStru60(g_stru_0x60_10, aAT);
	if (!fileholder)
		return 0i64;
	switch (aMoveMethod){
		case 1:
			dwSM0 = (aFlags & 0x20000) != 0;
			if ((aFlags & 0x40000) != 0)
				dwSM0 |= 7u;
			handle = CreateFileW(lpFN, GENERIC_READ, dwSM0, 0i64, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, 0i64);
			break;
		case 2:
			dwSM1 = (aFlags & 0x20000) != 0;
			if ((aFlags & 0x40000) != 0)
				dwSM1 |= 7u;
			handle = CreateFileW(lpFN, GENERIC_WRITE | GENERIC_READ, dwSM1, 0i64, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, 0i64);
			break;
		case 3:
			dwSM2 = (aFlags & 0x20000) != 0;
			if ((aFlags & 0x40000) != 0)
				dwSM2 |= 7u;
			handle = CreateFileW(lpFN, GENERIC_WRITE | GENERIC_READ, dwSM2, 0i64, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, 0i64);
			if (handle != (HANDLE)-1i64){
LABEL_19:
				if (handle){
					if (!g_dw_1000 || (aFlags & 0x80000) != 0)
						fileholder->lpBuffer = 0i64;
					else
						fileholder->lpBuffer = HeapAlloc(g_DATA.g_hHeap, 0, g_dw_1000);
					fileholder->handle = handle;
					fileholder->alloc_size = g_dw_1000;
					fileholder->seekpos = 0;
					fileholder->dwCreationDisposition = CreationDisposition;
					fileholder->IsSeekCur = aMoveMethod == SEEK_CUR;
					fileholder->doSeek = 1;
					if (aMoveMethod == SEEK_END && (aFlags & 0x100000) != 0){
						DistanceToMoveHigh[0] = 0;
						SetFilePointer(handle, 0, DistanceToMoveHigh, SEEK_END);
					}
					handle_1 = handle;
					if (at == -1)
						return fileholder;
					return (file_holder*)handle_1;
				}
LABEL_30:
				if (at == -1)
					at = (__int64)fileholder;
				stru60_zeroAt(g_stru_0x60_10, at);
				return (file_holder*)handle_1;
			}
			handle = CreateFileW(lpFN, GENERIC_WRITE, dwSM2, 0i64, 5u, 0, 0i64);
			break;
		default:
			handle = *(HANDLE*)DistanceToMoveHigh;
			break;
	}
	if (handle == (HANDLE)-1i64)
		goto LABEL_30;
	goto LABEL_19;
}
file_holder* __fastcall OpenExistingFileW(__int64 aAT, const WCHAR* lpFN, int aFlags){
	return CreateFileW_0(aAT, lpFN, 1, aFlags);
}
CHAR* __fastcall wtoc_alloc(LPCWCH lpWideCharStr){
	const WCHAR* v1; // rdi
	int cbMultiByte; // esi
	CHAR* result; // rax
	CHAR* v4; // rbx

	v1 = (const WCHAR*)&nullstr;
	if (lpWideCharStr)
		v1 = lpWideCharStr;
	cbMultiByte = WideCharToMultiByte(_MB_CP_UTF8, 0, v1, 0xFFFFFFFF, 0i64, 0, 0i64, 0i64);
	result = (CHAR*)ZHeapAlloc(cbMultiByte);
	v4 = result;
	if (!result)
		return result;
	WideCharToMultiByte(_MB_CP_UTF8, 0, v1, 0xFFFFFFFF, result, cbMultiByte, 0i64, 0i64);
	return v4;
}
void __fastcall add_to_STR_tree_AT2(wchar_t* alpszShortPath, __int64 alen, int apos){
	__int64 len; // rdi
	wchar_t* v5; // rax
	wchar_t* v6; // rbx
	wchar_t* v7; // rsi
	wchar_t v8; // ax

	len = alen;
	if (alen == -1){
		add_to_STR_tree_AT(alpszShortPath, apos);
	} else{

		if (alen < 0)
			len = 0i64;

		v5 = (wchar_t*)alloc_to_STR_tree(len, apos);
		v6 = v5;
		if (alpszShortPath){
			if (len){
				v7 = (wchar_t*)((char*)alpszShortPath - (char*)v5);
				do{
					v8 = *(wchar_t*)((char*)v6 + (_QWORD)v7);
					if (!v8)
						break;
					*v6++ = v8;
					--len;
				} while (len);
			}
		}
		TLS_cutr_str(len);
		*v6 = 0;
	}
}
char* str_get_lpszShortPath(wchar_t* lpszLongPath_1, __int64 alen){
	int v2; // eax
	int v4; // [rsp-30h] [rbp-50h]
	wchar_t* v5; // [rsp-30h] [rbp-50h]
	char* v6; // [rsp-30h] [rbp-50h]
	WCHAR* lpszLongPath; // [rsp+0h] [rbp-20h] BYREF
	wchar_t* lpszShortPath; // [rsp+8h] [rbp-18h]
	wchar_t* v9; // [rsp+10h] [rbp-10h] BYREF
	__int64 v10; // [rsp+18h] [rbp-8h]

	v10 = 0i64;
	v9 = 0i64;
	lpszShortPath = 0i64;
	lpszLongPath = 0i64;
	init_RSO();
	SET_TLS_2(alen);
	wstrdup_10((LPVOID*)&lpszLongPath, lpszLongPath_1);
	lpszShortPath = (wchar_t*)ZHeapAlloc(10000ui64);
	GetShortPathNameW(lpszLongPath, lpszShortPath, 10000u);
	v4 = GET_TLS_StrLen();
	v2 = GET_TLS_StrLen();
	add_to_STR_tree_AT2(lpszShortPath, -1i64, v2);
	dup_from_STR_tree((LPVOID*)&v9, v4);
	ZHeapFree(lpszShortPath);
	v5 = v9;
	GET_TLS_StrLen();
	add_to_STR_treeR(v5);
	v6 = (char*)v5 + STR_tree_root_0();
	HeapFree__0(lpszLongPath);
	HeapFree__0(v9);
	return v6;
}
__int64 __fastcall OpenExistingFileW_0(wchar_t* aFileName){
	__int64 Result; // [rsp-30h] [rbp-50h]
	WCHAR* filename; // [rsp+0h] [rbp-20h] BYREF
	file_holder* aAT; // [rsp+8h] [rbp-18h]
	__int64 io; // [rsp+10h] [rbp-10h]
	__int64 v6; // [rsp+18h] [rbp-8h]

	v6 = 0i64;
	io = 0i64;
	aAT = 0i64;
	filename = 0i64;
	wstrdup_10((LPVOID*)&filename, aFileName);
	aAT = OpenExistingFileW(-1i64, filename, 0x20000);
	if (aAT){
		fn_free_obj_0x60_0((__int64)aAT);
		io = 1i64;
	}
	Result = io;
	HeapFree__0(filename);
	return Result;
}
__int64 __fastcall STR_TREE_AT(int a1){
	return *(_QWORD*)TlsGetValue(g_dwTlsIndex) + a1;
}
__int64 __fastcall str_setz(int a1){
	__int64 result; // rax
	strNode* Value; // [rsp+20h] [rbp-18h]

	Value = (strNode*)TlsGetValue(g_dwTlsIndex);
	Value->slen = a1;
	result = a1;
	*(_WORD*)&Value->str[a1] = 0;
	return result;
}
wchar_t* __fastcall STR_TREE_MOVE_COPY(wchar_t* Source, int a2, DWORD* a3, int a4){
	__int64 len=0; // rbp
	DWORD* v7; // r14
	wchar_t* v8; // rbx
	int v9; // edi
	wchar_t* Src; // rsi
	unsigned __int64 v11=0; // rax
	size_t v12 = 0; // r15
	int v13; // edi
	void* v14; // rax
	wchar_t* result; // rax
	wchar_t* v16; // rbx
	wchar_t v17; // ax

	LODWORD(len) = 0;
	if (a2 < 1)
		return (wchar_t*)str_setz(a4);
	v7 = &nullstr;
	v8 = (wchar_t*)&nullstr;
	v9 = 0;
	if (Source)
		v8 = Source;
	if (a3)
		v7 = a3;
	Src = v8;
	if (!*(_WORD*)v7 || !*((_WORD*)v7 + 1)){
		while (1){
			v17 = *v8;
			if (*v8 == *(_WORD*)v7 || !v17){
				if (++v9 == a2){
					len = v8 - Src;
					goto LABEL_18;
				}
				if (!v17)
					goto LABEL_18;
				Src = v8 + 1;
			}
			++v8;
		}
	}
	v11 = -1ui64;
	do
		++v11;
	while (*((_WORD*)v7 + v11));
	v12 = (int)v11;
	while (1){
		while (wcsncmp(v8, (const wchar_t*)v7, v12) && *v8)
			++v8;
		if (++v9 == a2)
			break;
		if (!*v8)
			goto LABEL_18;
		v8 += v12;
		Src = v8;
	}
	len = v8 - Src;
LABEL_18:
	v13 = GET_STR_IN_tree(v8);
	if (v13){
		v14 = (void*)STR_TREE_AT(a4);
		memmove(v14, Src, 2i64 * (int)len);
	}
	result = (wchar_t*)alloc_to_STR_tree(len, a4);
	v16 = result;
	if (!v13)
		result = wcsncpy(result, Src, (int)len);
	v16[(int)len] = 0;
	return result;
}
__int64 __fastcall MySetFileAttributesW(const WCHAR* a1, DWORD a2){
	__int64 result; // rax

	LODWORD(result) = 0;
	if (a1)
		LODWORD(result) = SetFileAttributesW(a1, a2);
	return (int)result;
}
bool __fastcall CreateDirectoryW1(wchar_t* Source){
	wchar_t* end; // rcx
	wchar_t* v2; // rdx
	unsigned __int64 v3; // rax
	__int64 v4; // r8
	wchar_t Destination[268]; // [rsp+20h] [rbp-218h] BYREF

	if (!Source)
		return 0i64;
	wcsncpy(Destination, Source, 0x104ui64);
	Destination[0x104] = 0;
	end = &Destination[wcslen(Destination)];
	if (end > Destination){
		do{
			v2 = end - 1;
			v3 = *(end - 1);
			LOWORD(v3) = v3 - ' ';
			if ((unsigned __int16)v3 > 0x3Cu)
				break;
			v4 = 0x1000000000008001i64;
			if (!_bittest64(&v4, v3))
				break;
			--end;
		} while (v2 > Destination);
	}
	*end = 0;
	wprintf(L"%s\n", &Destination[0]);
	//return CreateDirectoryW(Destination, 0i64);
	return 1;
}
__int64* __fastcall stu602_add_if_not_exists(stru_602* a602, wchar_t* awstr){
	__int64* result; // rax

	result = stu602_get_by_name(a602, awstr);
	if (!result)
		return (__int64*)stu602_add(a602, awstr, 0);
	return result;
}
__int64 __fastcall put_to602_dupToRMDIR(wchar_t* awstr){
	int v1; // eax
	wchar_t* v2; // rcx
	__int64 v3; // rbp
	wchar_t* v5; // [rsp-30h] [rbp-50h]
	wchar_t* wstr; // [rsp+0h] [rbp-20h] BYREF
	__int64 v7; // [rsp+8h] [rbp-18h]

	v7 = 0i64;
	wstr = 0i64;
	init_RSO();
	wstrdup_10((LPVOID*)&wstr, awstr);
	if (*stu602_add_if_not_exists((stru_602*)g_DATA.g_stu602_root, wstr) < 1){
		*stu602_add_if_not_exists((stru_602*)g_DATA.g_stu602_root, wstr) = 1i64;
		fn_stru601((stru_601*)g_DATA.g_root_601_1);
		v5 = wstr;
		v1 = GET_TLS_StrLen();
		v2 = v5;
		LODWORD(v5) = v1;
		add_to_STR_treeR(v2);

		v3 = g_DATA.field_130;
		dup_from_STR_tree((LPVOID*)(g_DATA.field_130 + 0x14), (int)v5);
		*(_DWORD*)(v3 + 0x10) = g_DATA.field_100;
		++g_DATA.field_100;

	}
	HeapFree__0(wstr);
	return 0i64;
}
_DWORD* __fastcall act_mywstrcpy(wchar_t* a1, int a2, int aPos){
	wchar_t* v5; // rsi
	int v6; // eax
	int v7; // r14d
	int v8; // ebp
	int v9; // r15d
	_DWORD* result; // rax
	_DWORD* v11; // rbx

	v5 = a1;
	v6 = mywstrlen(a1);
	if (a2 < 0)
		a2 = 0;
	v7 = v6;
	v8 = v6;
	if (v6 > a2)
		v7 = a2;
	v9 = GET_STR_IN_tree(v5);
	result = alloc_to_STR_tree(v7, aPos);
	v11 = result;
	if (v9){
		result = (_DWORD*)GET_CHAR_AT_tree(v9);
		v5 = (wchar_t*)result;
	}
	if (v5)
		return (_DWORD*)wstrcpy(v11, &v5[v8 - v7], v7);
	*(_WORD*)v11 = 0;
	return result;
}
__int64 __fastcall act_wcsncmp2(wchar_t* Source, wchar_t* a2, char a3, int a4, int a5, int a6){
	__int64 v6; // r15
	const wchar_t* v8; // rbx
	__int64 v9=0; // rbp
	int v10; // edi
	int v11; // r12d
	char* v12; // r14
	wchar_t* v13; // rax
	wchar_t* v14; // r13
	signed __int64 v15; // rdx
	wchar_t v16; // cx
	int(__cdecl * Pwcsncmp)(const wchar_t*, const wchar_t*, size_t); // r12
	size_t v18; // rdi
	wchar_t v20; // ax
	signed __int64 v21; // rcx
	wchar_t v22; // ax
	__int64 result; // rax
	const wchar_t* v24; // [rsp+20h] [rbp-48h]
	char* v25; // [rsp+28h] [rbp-40h]
	wchar_t* v26=0; // [rsp+70h] [rbp+8h]

	v6 = -1i64;
	v8 = Source;
	if (Source){
		v9 = -1i64;
		do
			++v9;
		while (Source[v9]);
	} else{
		LODWORD(v9) = 0;
	}
	v10 = GET_STR_IN_tree(Source);
	v11 = GET_STR_IN_tree(a2);
	LODWORD(v26) = v11;
	v12 = alloc_to_STR_tree(v9, a6);
	if (v10)
		v8 = (const wchar_t*)GET_CHAR_AT_tree(v10);
	if (v11)
		a2 = (wchar_t*)GET_CHAR_AT_tree(v11);
	v25 = v12;
	if (v8 && *v8){
		if (a2 && *a2){
			v24 = v8;
			do
				++v6;
			while (a2[v6]);
			if (v11){
				v13 = (wchar_t*)HeapAlloc(g_DATA.g_hHeap, 0, 2i64 * ((int)v6 + 1));
				v14 = v13;
				v15 = (char*)v13 - (char*)a2;
				do{
					v16 = *a2++;
					*(wchar_t*)((char*)a2 + v15 - 2) = v16;
				} while (v16);
				a2 = v13;
			} else{
				v14 = v26;
			}
			Pwcsncmp = wcsncmp;
			if ((a3 & 1) != 0)
				Pwcsncmp = wcsnicmp;
			if (a4 > 1){
				v18 = a4 - 1;
				wcsncpy((wchar_t*)v12, v8, v18);
				v12 += 2 * v18;
				v8 += v18;
			}
			while (*v8){
				if (Pwcsncmp(v8, a2, (int)v6)){
					v20 = *v8;
					v12 += 2;
					++v8;
					*((_WORD*)v12 - 1) = v20;
				} else{
					v8 += (int)v6;
					if (a5 != -1 && --a5 <= 0){
						wcsncpy((wchar_t*)v12, v8, (int)v9 - (v8 - v24));
						v12 += 2 * ((int)v9 - (v8 - v24));
						break;
					}
				}
			}
			if ((_DWORD)v26)
				HeapFree(g_DATA.g_hHeap, 0, v14);
		} else{
			v21 = v12 - (char*)v8;
			do{
				v22 = *v8++;
				*(wchar_t*)((char*)v8 + v21 - 2) = v22;
			} while (v22);
			v12 += 2 * (int)v9;
		}
	}
	TLS_cutr_str(v9 - ((v12 - v25) >> 1));
	result = 0i64;
	*(_WORD*)v12 = 0;
	return result;
}
__int64 __fastcall act_wcsncmp(wchar_t* a1, wchar_t* a2, int a3){
	return act_wcsncmp2(a1, a2, 0, 1, -1, a3);
}
__int64 __fastcall act_itoa(unsigned __int16* a1){
	__int64 v1; // rdx
	int v2; // r9d
	unsigned __int16 v3; // ax
	__int64 v4; // r10
	int v5; // r8d
	__int64 v6; // rdx
	__int64 v7; // rdx
	unsigned __int16 v8; // ax
	unsigned __int16* v9; // rcx

	v1 = 0i64;
	if (!a1)
		return v1;
	while (*a1 == 32 || *a1 == 9)
		++a1;
	if (*a1 == 0x2D){
		v2 = 1;
	} else{
		v2 = 0;
		if (*a1 != 0x2B){
LABEL_9:
			v3 = *a1;
			if (*a1 == 0x24){
				v4 = 0x7E0000007E03FFi64;
				while (1){
					v5 = a1[1];
					++a1;
					if ((unsigned __int16)(v5 - 0x30) > 0x36u || !_bittest64(&v4, (unsigned int)(v5 - 0x30)))
						break;
					if ((unsigned __int16)(v5 - 0x30) > 9u){
						v6 = 0x10 * v1;
						if ((unsigned __int16)v5 < 0x61u)
							v7 = v6 - 0x37;
						else
							v7 = v6 - 0x57;
						v1 = (unsigned __int16)v5 + v7;
					} else{
						v1 = (unsigned __int16)v5 + 0x10 * (v1 - 3);
					}
				}
			} else if (v3 == 0x25){
				v8 = a1[1];
				v9 = a1 + 1;
				if (v8 >= 0x30u){
					do{
						if (v8 > 0x31u)
							break;
						++v9;
						v1 = v8 + 2 * (v1 - 0x18);
						v8 = *v9;
					} while (*v9 >= 0x30u);
				}
			} else if (v3 >= 0x30u){
				do{
					if (v3 > 0x39u)
						break;
					++a1;
					v1 = v3 + 2 * (5 * v1 - 0x18);
					v3 = *a1;
				} while (*a1 >= 0x30u);
			}
			if (v2)
				return -v1;
			return v1;
		}
	}
	++a1;
	goto LABEL_9;
}
size_t file_action_sub(){
	size_t v0; // rax
	int v1; // eax
	__int64 v2; // rax
	__int64 v3; // rdx
	__int64 v4; // r8
	__int64 v5; // r9
	int v6; // eax
	wchar_t* v7; // rcx
	DWORD buffer_size; // eax
	int v10; // eax
	int v11; // eax
	int v12; // eax
	int v13; // eax
	char* v14; // rax
	int v15; // eax
	wchar_t* v16; // rcx
	int v17; // eax
	DWORD v18; // eax
	int v19; // eax
	wchar_t* v20; // rcx
	int v21; // eax
	int v22; // eax
	wchar_t* v23; // rcx
	int v24; // eax
	wchar_t* v25; // rcx
	int v27; // [rsp-30h] [rbp-A0h]
	int v28; // [rsp-30h] [rbp-A0h]
	WCHAR* v29; // [rsp-30h] [rbp-A0h]
	int v30; // [rsp-30h] [rbp-A0h]
	int v31; // [rsp-30h] [rbp-A0h]
	int v32; // [rsp-30h] [rbp-A0h]
	int v33=0; // [rsp-30h] [rbp-A0h]
	wchar_t* g_path01; // [rsp-30h] [rbp-A0h]
	__int64 v35; // [rsp-30h] [rbp-A0h]
	int v36; // [rsp-30h] [rbp-A0h]
	WCHAR* v37; // [rsp-30h] [rbp-A0h]
	__int64 v38=0; // [rsp-30h] [rbp-A0h]
	size_t v39; // [rsp-30h] [rbp-A0h]
	__int64 v40; // [rsp+0h] [rbp-70h]
	size_t v41=0; // [rsp+8h] [rbp-68h]
	__int64 v42; // [rsp+8h] [rbp-68h]
	wchar_t* v43=0; // [rsp+10h] [rbp-60h] BYREF
	wchar_t* v44=0; // [rsp+18h] [rbp-58h] BYREF
	WCHAR* lpWideCharStr=0; // [rsp+20h] [rbp-50h] BYREF
	CHAR* buffer; // [rsp+28h] [rbp-48h]
	DWORD lpNumberOfBytesWritten = 0; // [rsp+30h] [rbp-40h] BYREF
	__int64 i; // [rsp+38h] [rbp-38h]
	unsigned __int16* v50=0; // [rsp+48h] [rbp-28h] BYREF
	wchar_t* v51 = 0; // [rsp+50h] [rbp-20h] BYREF

	init_RSO();
	if (g_DATA.g_flag_main == 1){
		v0 = g_DATA.field_E0 == 1 && g_DATA.field_B8 != 1;
		if (v0){
			v40 = myCmpItem((__int16*)g_DATA.field_108, (__int16*)&g_PrefixString[1]);
			v42 = 1i64;
			do{
				if (v40 < v42)
					break;
				v27 = GET_TLS_StrLen();
				v1 = GET_TLS_StrLen();
				STR_TREE_MOVE_COPY((wchar_t*)g_DATA.field_108, v42, NL, v1);
				dup_from_STR_tree((LPVOID*)&v43, v27);
				if (OpenExistingFileW_0(v43)){
					v28 = GET_TLS_StrLen();
					v2 = GET_TLS_StrLen();
					//str_get_lpszShortPath(v43, v3, v4, v5, v2);
					str_get_lpszShortPath(v43, v2);
					dup_from_STR_tree((LPVOID*)&v44, v28);
					v29 = lpWideCharStr;
					v6 = GET_TLS_StrLen();
					v7 = v29;
					LODWORD(v29) = v6;
					add_to_STR_treeR(v7);
					add_to_STR_treeR(v44);
					add_to_STR_treeR(NL);
					dup_from_STR_tree((LPVOID*)&lpWideCharStr, (int)v29);
				}
			} while (!__OFADD__(1i64, v42++));
			buffer = wtoc_alloc(lpWideCharStr);
			buffer_size = ZHeapSize(buffer);
			WriteFile((HANDLE)g_DATA.g_hSTD_OUTPUT_HANDLE, buffer, buffer_size, &lpNumberOfBytesWritten, 0i64);
			ZHeapFree(buffer);
			v0 = my_wstrcpy((LPVOID*)&g_DATA.field_108, g_PrefixString);
		}
	} else{
		g_DATA.g_flag_main = 1i64;
		for (i = 1i64; ; ++i){
			v30 = GET_TLS_StrLen();
			v10 = GET_TLS_StrLen();
			STR_TREE_MOVE_COPY((wchar_t*)g_DATA.script1, i, (const wchar_t*)"*", v10);
			dup_from_STR_tree((LPVOID*)&lpWideCharStr, v30);
			if (mywcsstr(lpWideCharStr, L":")){
				v31 = GET_TLS_StrLen();
				v11 = GET_TLS_StrLen();
				STR_TREE_MOVE_COPY(lpWideCharStr, 2, L":", v11);
				dup_from_STR_tree((LPVOID*)&v50, v31);
				v32 = GET_TLS_StrLen();
				v12 = GET_TLS_StrLen();
				STR_TREE_MOVE_COPY(lpWideCharStr, 1, L":", v12);
				dup_from_STR_tree((LPVOID*)&lpWideCharStr, v32);
			}
			if (mywcscmp(lpWideCharStr, 0i64))
				break;
			if (i % 2){
				v33 = GET_TLS_StrLen();
				v13 = GET_TLS_StrLen();
				act_mywstrcpy(lpWideCharStr, 1, v13);
				add2_to_StrTreeLen();
				v14 = STR_Tree_Last(v33);
				if (mywcscmp(L"?", (wchar_t*)v14)){
					g_path01 = g_DATA.g_path01;
					v15 = GET_TLS_StrLen();
					v16 = g_path01;
					LODWORD(g_path01) = v15;
					add_to_STR_treeR(v16);
					add_to_STR_treeR(g_DATA.g_copy_of_slash);
					GET_TLS_StrLen();
					v17 = GET_TLS_StrLen();
					act_wcsncmp(lpWideCharStr, L"?", v17);
					dup_from_STR_tree((LPVOID*)&v51, (int)g_path01);
					CreateDirectoryW1(v51);
					if (g_DATA.field_F0 == 1){
						v18 = act_itoa(v50);
						MySetFileAttributesW(v51, v18);
					}
					put_to602_dupToRMDIR(v51);
					v35 = g_DATA.field_108;
					v19 = GET_TLS_StrLen();
					v20 = (wchar_t*)v35;
					//LODWORD(v35) = v19;
					v35 = v19;
					add_to_STR_treeR(v20);
					add_to_STR_treeR(v51);
					add_to_STR_treeR(NL);
					dup_from_STR_tree((LPVOID*)&g_DATA.field_108, v35);
				} else{
					v36 = GET_TLS_StrLen();
					v21 = GET_TLS_StrLen();
					act_wcsncmp(lpWideCharStr, L"?", v21);
					dup_from_STR_tree((LPVOID*)&lpWideCharStr, v36);
					v37 = lpWideCharStr;
					v22 = GET_TLS_StrLen();
					v23 = v37;
					LODWORD(v37) = v22;
					add_to_STR_treeR(v23);
					dup_from_STR_tree((LPVOID*)((char*)g_DATA.g_200020 + 0x14 * v41 + 8), (int)v37);
					*(QWORD*)((char*)g_DATA.g_200020 + 0x14 * v41) = act_itoa(v50);
					v38 = g_DATA.field_108;
					v24 = GET_TLS_StrLen();
					v25 = (wchar_t*)v38;
					//LODWORD(v38) = v24;
					v38 = v24;
					add_to_STR_treeR(v25);
					add_to_STR_treeR(g_DATA.g_path01);
					add_to_STR_treeR(g_DATA.g_copy_of_slash);
					add_to_STR_treeR(lpWideCharStr);
					add_to_STR_treeR(NL);
					dup_from_STR_tree((LPVOID*)&g_DATA.field_108, v38);
				}
			} else{
				*((_DWORD*)g_DATA.g_200020 + 5 * v41++ + 4) = act_itoa(lpWideCharStr);
			}
		}
		v0 = v41;
	}
	v39 = v0;
	HeapFree__0(v43);
	HeapFree__0(v51);
	HeapFree__0(lpWideCharStr);
	HeapFree__0(v50);
	HeapFree__0(v44);
	return v39;
}
char* __fastcall memcpy_end(void* Src, char* Dst, size_t size){
	memcpy(Dst, Src, size);
	return &Dst[size];
}
char* __fastcall Alloc_LoadResource(HMODULE hModule, HRSRC hResInfo){
	SIZE_T sizeofres; // rax
	HGLOBAL Resource; // [rsp+0h] [rbp-10h]
	char* buf; // [rsp+8h] [rbp-8h]

	init_RSO();
	Resource = LoadResource(hModule, hResInfo);
	sizeofres = SizeofResource(hModule, hResInfo);
	g_DATA.g_sizeofres = sizeofres;
	buf = (char*)ZHeapAlloc(sizeofres);
	memcpy_end(Resource, buf, g_DATA.g_sizeofres);
	FreeResource(Resource);
	return buf;
}
HANDLE __fastcall MyCreateFileW(__int64 aAT, const WCHAR* afn){
	__int64 AT; // rsi
	HANDLE Result; // rbx
	file_holder* fileholder; // rdi
	HANDLE handle; // rbp
	int allocsize; // eax

	AT = aAT;
	Result = 0i64;
	fileholder = (file_holder*)ResizeStru60(g_stru_0x60_10, aAT);
	if (!fileholder)
		return 0i64;
	handle = CreateFileW(afn, GENERIC_WRITE | GENERIC_READ, 0, 0i64, CREATE_ALWAYS, 0x80u, 0i64);
	if (handle == (HANDLE)-1i64
		&& (handle = CreateFileW(afn, GENERIC_WRITE, 0, 0i64, 5u, 0, 0i64), handle == (HANDLE)-1i64)
		|| !handle){
		if (AT == -1ui64)
			AT = (__int64)fileholder;
		stru60_zeroAt(g_stru_0x60_10, AT);
	} else{
		if (g_dw_1000)
			fileholder->lpBuffer = HeapAlloc(g_DATA.g_hHeap, 0, g_dw_1000);
		else
			fileholder->lpBuffer = 0i64;
		fileholder->handle = handle;
		allocsize = g_dw_1000;
		fileholder->seekpos = 0;
		Result = handle;
		fileholder->doSeek = 1;
		if (AT == -1ui64)
			Result = fileholder;
		fileholder->alloc_size = allocsize;
		*(_QWORD*)&fileholder->dwCreationDisposition = 2i64;
	}
	return Result;
}
size_t __fastcall MyWriteFile2(file_holder* afileholder, _BYTE* aSrc, int aSize){
	size_t Size; // rdi
	DWORD seekpos; // eax
	HANDLE handle; // rcx
	DWORD alloc_size; // eax
	signed int v9; // ecx
	_BYTE* v10; // rcx
	signed int v12; // eax
	DWORD NumberOfBytesWritten; // [rsp+50h] [rbp+8h] BYREF
	__int64 seekpos_1; // [rsp+68h] [rbp+20h] BYREF

	Size = aSize;
	NumberOfBytesWritten = 0;
	if (afileholder->IsSeekCur)
		return 0i64;
	if (afileholder->doSeek == 1){
		seekpos = afileholder->seekpos;
		handle = afileholder->handle;
		seekpos_1 = -seekpos;
		SetFilePointer(handle, -seekpos, (PLONG)&seekpos_1 + 1, SEEK_CUR);
		alloc_size = afileholder->alloc_size;
		afileholder->doSeek = 0;
		afileholder->seekpos = alloc_size;
	}
	v9 = afileholder->seekpos;
	if (v9 <= (int)Size){
		MyWriteFile(afileholder);
		v12 = afileholder->alloc_size;
		if ((int)Size < v12){
			memcpy((char*)afileholder->lpBuffer + v12 - afileholder->seekpos, aSrc, Size);
			afileholder->seekpos -= Size;
			return Size;
		} else{
			WriteFile(afileholder->handle, aSrc, Size, &NumberOfBytesWritten, 0i64);
			return (int)NumberOfBytesWritten;
		}
	} else{
		v10 = (char*)afileholder->lpBuffer + afileholder->alloc_size - v9;
		if ((_DWORD)Size == 1){
			*v10 = *aSrc;
			--afileholder->seekpos;
			return Size;
		} else if ((_DWORD)Size == 2){
			*(_WORD*)v10 = *(_WORD*)aSrc;
			afileholder->seekpos -= 2;
			return Size;
		} else{
			if ((_DWORD)Size == 4)
				*(_DWORD*)v10 = *(_DWORD*)aSrc;
			else
				memcpy(v10, aSrc, Size);
			afileholder->seekpos -= Size;
			return Size;
		}
	}
}
__int64 __fastcall MyWriteFile3(__int64 aAT, _BYTE* aSrc, DWORD aSize){
	int v3; // ebx
	file_holder* fileholder; // rax
	DWORD NumberOfBytesWritten; // [rsp+48h] [rbp+10h] BYREF

	v3 = 0;
	NumberOfBytesWritten = 0;
	if (!aSrc || !aSize)
		return v3;
	fileholder = (file_holder*)stru60_get_at(g_stru_0x60_10, aAT);
	if (!fileholder)
		return (int)NumberOfBytesWritten;
	if (fileholder->lpBuffer)
		return (int)MyWriteFile2(fileholder, aSrc, aSize);
	WriteFile(fileholder->handle, aSrc, aSize, &NumberOfBytesWritten, 0i64);
	return (int)NumberOfBytesWritten;
}
_BYTE __fastcall MyWriteFile5(wchar_t* aFileName, _BYTE* aSRC, __int64 aSize){
	_BYTE flag; // rax
	_BYTE Result; // [rsp-30h] [rbp-60h]
	wchar_t* filename; // [rsp+0h] [rbp-30h] BYREF
	HANDLE aAT; // [rsp+8h] [rbp-28h]
	__int64 aNW; // [rsp+10h] [rbp-20h]
	_BYTE io; // [rsp+18h] [rbp-18h]
	__int64 v10; // [rsp+20h] [rbp-10h]

	v10 = 0i64;
	io = 0i64;
	aNW = 0i64;
	aAT = 0i64;
	filename = 0i64;
	init_RSO();
	wstrdup_10((LPVOID*)&filename, aFileName);
	flag = g_DATA.field_80 != 1 && OpenExistingFileW_0(filename);
	if (!flag){
		aAT = MyCreateFileW(-1i64, filename);
		if (aAT){
			if (aSize > 0)
				aNW = MyWriteFile3((__int64)aAT, aSRC, aSize);
			fn_free_obj_0x60_0((__int64)aAT);
			io = aNW == aSize;
		}
		flag = io;
	}
	Result = flag;
	HeapFree__0(filename);
	return Result;
}
void __fastcall MySetEnvironmentVariableW(const WCHAR* lpName, const WCHAR* lpValue){
	const WCHAR* v3; // rdx

	if (lpName){
		v3 = (const WCHAR*)&nullstr;
		if (lpValue)
			v3 = lpValue;
		SetEnvironmentVariableW(lpName, v3);
	}
}
__int64 __fastcall xorfn(char* a1, int a2, wchar_t* wstr){
	bool v3; // of
	unsigned __int8* v4; // rbp
	unsigned __int8* v5; // rbp
	WCHAR* v7; // [rsp+0h] [rbp-A0h] BYREF
	CHAR* v8; // [rsp+8h] [rbp-98h]
	int zsize; // [rsp+10h] [rbp-90h]
	unsigned __int8* V1=0; // [rsp+18h] [rbp-88h] BYREF
	unsigned __int8* V2=0; // [rsp+28h] [rbp-78h] BYREF
	int v12; // [rsp+38h] [rbp-68h]
	int v13; // [rsp+40h] [rbp-60h]
	int v14; // [rsp+48h] [rbp-58h]
	int v15; // [rsp+50h] [rbp-50h]
	int v16; // [rsp+58h] [rbp-48h]
	int v17; // [rsp+60h] [rbp-40h]
	unsigned __int8* v1p; // [rsp+68h] [rbp-38h]
	CHAR* v19; // [rsp+70h] [rbp-30h]
	char* v20; // [rsp+78h] [rbp-28h]

	wstrdup_10((LPVOID*)&v7, wstr);
	v8 = wtoc_alloc(v7);
	zsize = ZHeapSize(v8);
	V1 = (unsigned __int8*)fn_alloc_obj1(4ui64, 0x100ui64, 5, 0i64, (void**)&V1);
	V2 = (unsigned __int8*)fn_alloc_obj1(4ui64, 0x100ui64, 5, 0i64, (void**)&V2);
	v14 = 0;
	v15 = 0;
	v16 = 0;
	v17 = 0;
	v13 = 1;
	zsize = 0x20;
	v1p = V1;
	v19 = v8;
	v12 = 0;
	do{
		if (v12 > 0xFF)
			break;
		*(_DWORD*)v1p = v12;

		v1p += 4;
		if (!*v19)
			v19 = v8;
		*(_DWORD*)&V2[4 * v12] = *v19++;
		v3 = __OFADD__(1, v12++);
	} while (!v3);

	v13 = 0;
	v12 = 0;
	do{
		if (v12 > 0xFF)
			break;
		v13 = (unsigned __int8)(*(_DWORD*)&V2[4 * v12] + *(_DWORD*)&V1[4 * v12] + v13);
		v4 = V1;
		v16 = *(_DWORD*)&V1[4 * v12];
		*(_DWORD*)&V1[4 * v12] = *(_DWORD*)&V1[4 * v13];
		*(_DWORD*)&v4[4 * v13] = v16;
		v3 = __OFADD__(1, v12++);
	} while (!v3);
	v12 = 0;
	v13 = 0;
	//v20 = (char*)(int)a1;
	v20 = (char*)a1;
	v15 = 0;
	do{
		if (a2 - 1 < v15)
			break;
		v12 = (unsigned __int8)(v12 + 1);
		v5 = V1;
		v13 = (unsigned __int8)(*(_DWORD*)&V1[4 * v12] + v13);
		v16 = *(_DWORD*)&V1[4 * v12];
		*(_DWORD*)&V1[4 * v12] = *(_DWORD*)&V1[4 * v13];
		*(_DWORD*)&v5[4 * v13] = v16;
		v14 = (unsigned __int8)(*(_DWORD*)&v5[4 * v13] + *(_DWORD*)&v5[4 * v12]);
		v17 = *(_DWORD*)&v5[4 * v14];
		*v20++ ^= v17;
		v3 = __OFADD__(1, v15++);
	} while (!v3);
	V1 = (unsigned __int8*)fn_alloc_obj1(4ui64, 1ui64, 5, 0i64, (void**)&V1);
	V2 = (unsigned __int8*)fn_alloc_obj1(4ui64, 1ui64, 5, 0i64, (void**)&V2);
	ZHeapFree(v8);
	HeapFree__0(v7);
	fn_free_obj1_((stru_602*)V1);
	fn_free_obj1_((stru_602*)V2);
	return (__int64)a1;
}
__int64 __fastcall ptr64(__int64 a1){
	return *(_QWORD*)a1;
}
_WORD* __fastcall my_atoi3(_WORD* a1, unsigned __int64 a2){
	_WORD* v3; // r8
	char* v4; // r9
	char v6[72]; // [rsp+0h] [rbp-48h] BYREF

	v3 = a1;
	v4 = v6;
	do{
		*(_WORD*)v4 = a2 % 0xA + 0x30;
		v4 += 2;
		a2 /= 0xAui64;
	} while (a2);
	do{
		v4 -= 2;
		*v3++ = *(_WORD*)v4;
	} while (v4 != v6);
	*v3 = 0;
	return a1;
}
_WORD* __fastcall my_atoi2(_WORD* a1, __int64 a2){
	_WORD* v2; // rbx

	v2 = a1;
	if (a2 < 0){
		*a1++ = 0x2D;
		a2 = -a2;
	}
	my_atoi3(a1, a2);
	return v2;
}
__int64 __fastcall my_atoi(__int64 a1, int a2){
	char* v3; // rdi
	__int64 v4; // rdx

	v3 = alloc_to_STR_tree(0x40, a2);
	my_atoi2(v3, a1);
	v4 = -1i64;
	do
		++v4;
	while (*(_WORD*)&v3[2 * v4]);
	return TLS_cutr_str(0x40 - (int)v4);
}
void* __fastcall m_zalloc(__int64 a1, int a2, int a3){
	return malloc((unsigned int)(a3 * a2));
}
void __fastcall m_zfree(__int64 a1, void *a2)
{
  free(a2);
}
//unsigned __int64 __fastcall inflateInit2_(z_streamp strm, __int64 windowBits, _BYTE* version, int stream_size){
//	int windowBits_1; // esi
//	inflate_state* state_mem; // rax
//	inflate_state* p; // rdi
//	__int64 v9; // rsi
//
//	windowBits_1 = windowBits;
//	if (!version || *version != '1' || stream_size != 0x58)
//		return Z_VERSION_ERROR;
//	if (!strm)
//		return Z_STREAM_ERROR;
//	strm->msg = 0i64;
//	if (!strm->zalloc){
//		strm->opaque = 0i64;
//		strm->zalloc = (alloc_func)m_zalloc;
//	}
//	if (!strm->zfree)
//		strm->zfree = (free_func)m_zfree;
//	state_mem = (inflate_state*)((__int64(__fastcall*)(void*, __int64, __int64))strm->zalloc)(
//		strm->opaque,
//		1i64,
//		0x1BF0i64);
//	p = state_mem;
//	if (!state_mem)
//		return Z_MEM_ERROR;
//	strm->state = (struct internal_state*)state_mem;
//	state_mem->strm = strm;
//	state_mem->window = 0i64;
//	state_mem->mode = HEAD;
//	LODWORD(v9) = inflateReset2(strm, windowBits_1);
//	if (!(_DWORD)v9)
//		return (unsigned __int64)(unsigned int)v9;
//	((void(__fastcall*)(void*, inflate_state*))strm->zfree)(strm->opaque, p);
//	strm->state = 0i64;
//	return (unsigned __int64)(unsigned int)v9;
//}
//unsigned __int64 __fastcall inflateInit_(z_stream* strm, _BYTE* ver, int stream_size){
//	return inflateInit2_(strm, 15i64, ver, stream_size);
//}
unsigned __int64 __fastcall inf_(char* out, unsigned int* total_out, z_stream* buf, unsigned int* a4){
	unsigned int ptotal_out; // ebx
	unsigned int v5; // esi
	unsigned int v6; // ebp
	unsigned __int64 result; // rax
	unsigned int avail_out; // eax
	unsigned __int64 zerr; // rdi
	char v13[16]; // [rsp+20h] [rbp-98h] BYREF
	z_stream strm; // [rsp+30h] [rbp-88h] BYREF

	ptotal_out = *total_out;
	v5 = *a4;
	v6 = 0;
	if (*total_out){
		*total_out = 0;
	} else{
		ptotal_out = 1;
		out = v13;
	}
	strm.next_in = (char*)buf;
	strm.avail_in = 0;
	memset(&strm.zalloc, 0, 0x18);
	// ret = inflateInit_(&strm, ZLIB_VERSION - 1, (int)sizeof(z_stream));
	//                                                 assert(ret == Z_VERSION_ERROR); 
	result = inflateInit_(&strm, "1.2.11", 0x58);
	if ((_DWORD)result)
		return result;
	avail_out = 0;
	strm.next_out = (unsigned __int8*)out;
	for (strm.avail_out = 0; ; avail_out = strm.avail_out){
		if (!avail_out){
			strm.avail_out = ptotal_out;
			ptotal_out = 0;
		}
		if (!strm.avail_in){
			strm.avail_in = v5;
			v5 = 0;
		}
		LODWORD(zerr) = inflate((z_streamp*)&strm, 0);
		if ((_DWORD)zerr)
			break;
	}
	*a4 -= v5 + strm.avail_in;
	if (out == v13){
		if (strm.total_out){
			if ((_DWORD)zerr == Z_BUF_ERROR)
				ptotal_out = 1;
		}
	} else{
		*total_out = strm.total_out;
	}
	inflateEnd(&strm);
	if ((_DWORD)zerr == Z_STREAM_END)
		return (unsigned __int64)v6;
	if ((_DWORD)zerr == Z_NEED_DICT){
		return (unsigned __int64)Z_DATA_ERROR;
	} else{
		if ((_DWORD)zerr != Z_BUF_ERROR)
			return (unsigned __int64)(unsigned int)zerr;
		v6 = Z_DATA_ERROR;
		if (!(ptotal_out + strm.avail_out))
			return (unsigned __int64)(unsigned int)zerr;
	}
	return (unsigned __int64)v6;
}
unsigned __int64 __fastcall inf(char* out, unsigned int* total_out, char* buf, int size_1){
	int size; // [rsp+48h] [rbp+20h] BYREF

	size = size_1;
	return inf_(out, total_out, (z_stream*)buf, (unsigned int*)&size);
}

DWORD __stdcall m_PTHREAD_START_ROUTINE(LPVOID lpThreadParameter){
	int v1; // eax
	strNode* v2; // rax
	int v3; // eax
	int v4; // eax
	wchar_t* v5; // rcx
	int v6; // eax
	wchar_t* v7; // rcx
	int v8; // eax
	wchar_t* v9; // rcx
	__int64 v10; // rax
	__int64 v11; // rdx
	__int64 v12; // r8
	__int64 v13; // r9
	int v14; // eax
	strNode* v15; // rax
	int v16; // eax
	wchar_t* v17; // rcx
	int v19; // eax
	strNode* v20; // rax
	__int64 v22=0; // [rsp+0h] [rbp-C8h]
	wchar_t* v23; // [rsp+0h] [rbp-C8h]
	const WCHAR* v24=0; // [rsp+0h] [rbp-C8h]
	const WCHAR* v25=0; // [rsp+0h] [rbp-C8h]
	int v26=0; // [rsp+8h] [rbp-C0h]
	__int64 v27=0; // [rsp+8h] [rbp-C0h]
	__int64 v28=0; // [rsp+8h] [rbp-C0h]
	int v29; // [rsp+18h] [rbp-B0h]
	int v30; // [rsp+18h] [rbp-B0h]
	wchar_t* g_path01 = 0; // [rsp+18h] [rbp-B0h]
	wchar_t* v32=0; // [rsp+18h] [rbp-B0h]
	wchar_t* v33=0; // [rsp+18h] [rbp-B0h]
	__int64 v34=0; // [rsp+18h] [rbp-B0h]
	wchar_t* v35; // [rsp+18h] [rbp-B0h]
	__int64 v36=0; // [rsp+18h] [rbp-B0h]
	LPVOID v37=0; // [rsp+48h] [rbp-80h] BYREF
	__int64 v38; // [rsp+50h] [rbp-78h]
	__int64 total_out; // [rsp+58h] [rbp-70h] BYREF
	__int64 size; // [rsp+60h] [rbp-68h]
	__int64 v41; // [rsp+68h] [rbp-60h]
	__int64 v42; // [rsp+70h] [rbp-58h]
	wchar_t* v43=0; // [rsp+78h] [rbp-50h] BYREF
	WCHAR* v44=0; // [rsp+80h] [rbp-48h] BYREF
	HRSRC ResourceW; // [rsp+88h] [rbp-40h]
	HRSRC v46; // [rsp+90h] [rbp-38h]
	char* Resource; // [rsp+98h] [rbp-30h]
	wchar_t* v48=0; // [rsp+A0h] [rbp-28h] BYREF
	char* buf; // [rsp+A8h] [rbp-20h]
	unsigned __int64 v50; // [rsp+B0h] [rbp-18h]

	init_RSO();
	wstrdup_10(&v37, (wchar_t*)lpThreadParameter);
	v41 = file_action_sub();
	v42 = 0i64;
	do{
		if (v41 < v42)
			break;
		v29 = GET_TLS_StrLen();
		GET_TLS_StrLen();
		GET_TLS_StrLen();
		v1 = GET_TLS_StrLen();
		MD_stuff(*(const WCHAR**)((char*)g_DATA.g_200020 + 0x14 * v42 + 8), 3, v1);
		v2 = STR_tree_root();
		MyCharUpperW((wchar_t*)((char*)v2 + v22), v26);
		dup_from_STR_tree((LPVOID*)&v43, v29);
		v30 = GET_TLS_StrLen();
		v3 = GET_TLS_StrLen();
		wStrReverse(v43, v3);
		dup_from_STR_tree((LPVOID*)&v44, v30);
		ResourceW = FindResourceW(g_DATA.g_module0handle, v43, (LPCWSTR)0xA);
		v46 = FindResourceW(g_DATA.g_module0handle, v44, (LPCWSTR)0xA);
		if (ResourceW){
			Resource = Alloc_LoadResource(g_DATA.g_module0handle, ResourceW);
			v38 = HeapSize__0((__int64)Resource);
			g_path01 = g_DATA.g_path01;
			v4 = GET_TLS_StrLen();
			v5 = g_path01;
			LODWORD(g_path01) = v4;
			add_to_STR_treeR(v5);
			add_to_STR_treeR(g_DATA.g_copy_of_slash);
			add_to_STR_treeR(*(wchar_t**)((char*)g_DATA.g_200020 + 0x14 * v42 + 8));
			dup_from_STR_tree((LPVOID*)&v48, (int)g_path01);
			xorfn((int)Resource, v38, (wchar_t*)g_DATA.field_78);
			MyWriteFile5(v48, Resource, v38);
			if (g_DATA.field_F0 == 1)
				MySetFileAttributesW(v48, *(QWORD*)((char*)g_DATA.g_200020 + 0x14 * v42));
		} else if (v46){
			Resource = Alloc_LoadResource(g_DATA.g_module0handle, v46);
			v38 = HeapSize__0((__int64)Resource);
			xorfn(Resource, v38, (wchar_t*)g_DATA.field_78);
			size = ptr64((__int64)Resource);
			total_out = ptr64((__int64)(Resource + 8));
			buf = (char*)ZHeapAlloc(total_out);
			v32 = g_DATA.g_path01;
			v6 = GET_TLS_StrLen();
			v7 = v32;
			LODWORD(v32) = v6;
			add_to_STR_treeR(v7);
			add_to_STR_treeR(g_DATA.g_copy_of_slash);
			add_to_STR_treeR(*(wchar_t**)((char*)g_DATA.g_200020 + 0x14 * v42 + 8));
			dup_from_STR_tree((LPVOID*)&v48, (int)v32);
			if (buf){
				v50 = inf(buf, (unsigned int*)&total_out, Resource + 0x10, size);
				MyWriteFile5(v48, buf, total_out);
				if (g_DATA.field_F0 == 1)
					MySetFileAttributesW(v48, *(QWORD*)((char*)g_DATA.g_200020 + 0x14 * v42));
				ZHeapFree(buf);
			}
		} else{
			v33 = g_DATA.g_path01;
			v8 = GET_TLS_StrLen();
			v9 = v33;
			LODWORD(v33) = v8;
			add_to_STR_treeR(v9);
			add_to_STR_treeR(g_DATA.g_copy_of_slash);
			add_to_STR_treeR(*(wchar_t**)((char*)g_DATA.g_200020 + 0x14 * v42 + 8));
			dup_from_STR_tree((LPVOID*)&v48, (int)v33);
			MyWriteFile5(v48, buf, 0i64);
			if (g_DATA.field_F0 == 1)
				MySetFileAttributesW(v48, *(QWORD*)((char*)g_DATA.g_200020 + 0x14 * v42));
		}
		if (OpenExistingFileW_0(v48)){
			++g_DATA.field_E8;
			v34 = GET_TLS_StrLen();
			v27 = GET_TLS_StrLen();
			v10 = GET_TLS_StrLen();
			str_get_lpszShortPath(v48, v10);
			add2_to_StrTreeLen();
			v23 = (wchar_t*)g_DATA.field_F8;
			GET_TLS_StrLen();
			add_to_STR_treeR(v23);
			GET_TLS_StrLen();
			v14 = GET_TLS_StrLen();
			my_atoi(g_DATA.field_E8, v14);
			v24 = STR_tree_root();
			v15 = STR_tree_root();
			MySetEnvironmentVariableW(v23, (const WCHAR*)((char*)v15 + v27));
			SET_TLS_2(v34);
			fn_stru601((stru_601*)g_DATA.g_root_601_2);
			v35 = v48;
			v16 = GET_TLS_StrLen();
			v17 = v35;
			LODWORD(v35) = v16;
			add_to_STR_treeR(v17);
			dup_from_STR_tree((LPVOID*)(g_DATA.field_140 + 0x10), (int)v35);
		}
	} while (!__OFADD__(1i64, v42++));
	ZHeapFree(Resource);
	v28 = GET_TLS_StrLen();
	v36 = GET_TLS_StrLen();
	v19 = GET_TLS_StrLen();
	my_atoi(g_DATA.field_E8, v19);
	add2_to_StrTreeLen();
	v20 = STR_tree_root();
	v25 = (wchar_t*)g_DATA.field_F8;
	MySetEnvironmentVariableW(v25, (const WCHAR*)((char*)v20 + v28));
	SET_TLS_2(v36);
	file_action_sub();
	HeapFree__0(v43);
	HeapFree__0(v44);
	HeapFree__0(v48);
	HeapFree__0(v37);
	return 1;
}
QWORD __fastcall add_results_to_tree(LPTHREAD_START_ROUTINE lpStartAddress, LPVOID lpParameter){
	QWORD v2; // rdi
	HANDLE* v3; // rbp
	stru0x20* v4; // rbx
	HANDLE* p_hObject; // rsi
	stru0x20* node; // rax
	DWORD v8; // [rsp+50h] [rbp+18h] BYREF

	v2 = 0i64;
	v3 = (HANDLE*)CreateThread(0i64, 0x1000ui64, lpStartAddress, lpParameter, 0, &v8);
	if (!v3)
		return v2;
	EnterCriticalSection(&CriticalSection);
	v4 = g_tree_stru0x20__;
	while (v4){
		p_hObject = &v4->hObject;
		if (WaitForSingleObject(v4->hObject, 0)){
			v4 = v4->left;
		} else{
			CloseHandle(*p_hObject);
			v4 = v4->left;
			del_fr_tree(&g_tree_stru0x20__, p_hObject);
		}
	}
	v2 = g_tree_node_counter++;
	//     stru0x20* __shifted(stru0x20, 0x10) node; // rax
	//     
	//       node = (stru0x20 *__shifted(stru0x20,0x10))add_to_tree((stru0x20 *)&g_tree_stru0x20__, 0x20);
	//   ADJ(node)->hObject = v3;
	//   ADJ(node)->index = v2;

	node = (stru0x20*)add_to_tree((stru0x20*)&g_tree_stru0x20__, 0x20);
	node->left = (stru0x20*)v3;
	node->right = (stru0x20*)v2;
	LeaveCriticalSection(&CriticalSection);
	return v2;
}
__int64 __fastcall sub_140003DDC(wchar_t* a1){
	int v1; // eax
	int v2; // eax
	strNode* v3; // rax
	int v4; // eax
	int v5; // eax
	__int64 v6; // rax
	__int64 v8=0; // [rsp+0h] [rbp-88h]
	int v9=0; // [rsp+8h] [rbp-80h]
	int v10; // [rsp+18h] [rbp-70h]
	int v11; // [rsp+18h] [rbp-70h]
	int v12; // [rsp+18h] [rbp-70h]
	int v13; // [rsp+18h] [rbp-70h]
	__int64 v14; // [rsp+18h] [rbp-70h]
	wchar_t* v15=0; // [rsp+48h] [rbp-40h] BYREF
	__int64 v16=0; // [rsp+50h] [rbp-38h]
	WCHAR* v17=0; // [rsp+58h] [rbp-30h] BYREF
	HRSRC ResourceW; // [rsp+60h] [rbp-28h]
	wchar_t* Resource; // [rsp+68h] [rbp-20h]
	__int64 v20; // [rsp+70h] [rbp-18h]

	init_RSO();
	wstrdup_10((LPVOID*)&v15, a1);
	if (v16 == 1){
		v10 = GET_TLS_StrLen();
		v1 = GET_TLS_StrLen();
		add_to_STR_tree_AT(v15, v1);
		dup_from_STR_tree((LPVOID*)&v15, v10);
	}
	v11 = GET_TLS_StrLen();
	GET_TLS_StrLen();
	GET_TLS_StrLen();
	v2 = GET_TLS_StrLen();
	MD_stuff(v15, 1, v2);
	v3 = STR_tree_root();
	//MyCharUpperW((wchar_t*)((char*)v3 + v8), v9);
	MyCharUpperW((wchar_t*)((char*)v3 + v2), v2);
	dup_from_STR_tree((LPVOID*)&v17, v11);
	ResourceW = FindResourceW(g_DATA.g_module0handle, v17, (LPCWSTR)0xA);
	if (ResourceW){
		Resource = (wchar_t*)Alloc_LoadResource(g_DATA.g_module0handle, ResourceW);
		g_DATA.g_sizeofres = HeapSize__0((__int64)Resource);
		xorfn(Resource, g_DATA.g_sizeofres, (wchar_t*)g_DATA.field_78);
		v12 = GET_TLS_StrLen();
		v4 = GET_TLS_StrLen();
		add_to_STR_tree_AT2(Resource, g_DATA.g_sizeofres, v4);
		dup_from_STR_tree((LPVOID*)&g_DATA.script1, v12);
		ZHeapFree(Resource);
		v20 = mywcsstr((const wchar_t*)g_DATA.script1, L"|");
		v13 = GET_TLS_StrLen();
		v5 = GET_TLS_StrLen();
		wstrstuff((wchar_t*)g_DATA.script1, v20 - 1, v5);
		dup_from_STR_tree((LPVOID*)&g_DATA.script1, v13);
	}
	v6 = mywcscmp((wchar_t*)g_DATA.script1, 0i64);
	if (!v6){
		if (v16 == 1){
			v6 = add_results_to_tree((LPTHREAD_START_ROUTINE)m_PTHREAD_START_ROUTINE, v15);
			g_DATA.field_18 = v6;
		} else{
			//LODWORD(v6) = m_PTHREAD_START_ROUTINE(v15);
			v6 = m_PTHREAD_START_ROUTINE(v15);
		}
	}
	v14 = v6;
	HeapFree__0(v15);
	HeapFree__0(v17);
	return v14;
}
char* __fastcall add_to_STR_tree_CHAR(__int16 a1, int a2){
	char* result; // rax

	result = alloc_to_STR_tree(1, a2);
	*(_WORD*)result = a1;
	*((_WORD*)result + 1) = 0;
	return result;
}
wchar_t* __fastcall alloc_to_STR_SPACE_tree(int aSize, int aAT){
	unsigned int size; // edi
	wchar_t* result; // rax
	wchar_t* v4; // r8
	__int64 len; // rdx
	wchar_t* iterator; // rdi
	__int64 i; // rcx

	size = aSize;
	if (aSize < 0)
		size = 0;
	result = (wchar_t*)alloc_to_STR_tree(size, aAT);
	v4 = result;
	if (size){
		len = size;
		iterator = result;
		result = (wchar_t*)0x20;
		for (i = (unsigned int)len; i; --i)
			*iterator++ = 0x20;
		v4[len] = 0;
	} else{
		*result = 0;
	}
	return result;
}
char* __fastcall add_SystemDirectory_to_STR_tree(wchar_t* a1, wchar_t* a2, __int64 a3, __int64 a4, __int64 aAT){
	int v5; // eax
	int v7; // [rsp-30h] [rbp-50h]
	wchar_t* v8; // [rsp-30h] [rbp-50h]
	char* v9; // [rsp-30h] [rbp-50h]
	LPVOID v10; // [rsp+0h] [rbp-20h] BYREF
	LPVOID v11; // [rsp+8h] [rbp-18h] BYREF
	LPWSTR v12; // [rsp+10h] [rbp-10h] BYREF
	__int64 v13; // [rsp+18h] [rbp-8h]

	v13 = 0i64;
	v12 = 0i64;
	v11 = 0i64;
	v10 = 0i64;
	init_RSO();
	SET_TLS_2(aAT);
	wstrdup_10(&v10, a1);
	wstrdup_10(&v11, a2);
	v7 = GET_TLS_StrLen();
	v5 = GET_TLS_StrLen();
	alloc_to_STR_SPACE_tree(0x800, v5);
	dup_from_STR_tree((LPVOID*)&v12, v7);
	GetSystemDirectoryW(v12, 0x800u);
	PathAddBackslashW(v12);
	v8 = v12;
	GET_TLS_StrLen();
	add_to_STR_treeR(v8);
	v9 = (char*)v8 + STR_tree_root_0();
	HeapFree__0(v10);
	HeapFree__0(v11);
	HeapFree__0(v12);
	return v9;
}
__int64 __fastcall TempPathW_to_tree(int a1){
	char* v1; // rdi
	signed int TempPathW; // esi
	HMODULE LibraryW; // rax
	HMODULE v4; // rbp
	DWORD(__stdcall * GetLongPathNameW)(LPCWSTR, LPWSTR, DWORD); // rax
	__int64 result; // rax

	v1 = alloc_to_STR_tree(260, a1);
	TempPathW = GetTempPathW(260u, (LPWSTR)v1);
	LibraryW = LoadLibraryW(L"Kernel32.DLL");
	v4 = LibraryW;
	if (LibraryW){
		GetLongPathNameW = (DWORD(__stdcall*)(LPCWSTR, LPWSTR, DWORD))GetProcAddress(LibraryW, "GetLongPathNameW");
		if (GetLongPathNameW)
			TempPathW = ((__int64(__fastcall*)(char*, char*, __int64))GetLongPathNameW)(v1, v1, 260i64);
		FreeLibrary(v4);
	}
	TLS_cutr_str(260 - TempPathW);
	result = TempPathW;
	*(_WORD*)&v1[2 * TempPathW] = 0;
	return result;
}
BYTE __fastcall DeleteFileW1(LPCWSTR lpFileName, char a2){
	if (!lpFileName)
		return 0i64;
	if ((a2 & 2) != 0)
		SetFileAttributesW(lpFileName, 0x80u);
	return DeleteFileW(lpFileName);
}
BYTE __fastcall DeleteFileW2(const WCHAR* a1){
	return DeleteFileW1(a1, 0);
}
void __stdcall create_tmp_paths(){
	int v0; // eax
	int v1; // eax
	wchar_t* v2; // rcx
	int v4; // eax
	int v5; // eax
	int v6; // eax
	int v7; // eax
	int v8; // eax
	int v9; // [rsp-30h] [rbp-70h]
	WCHAR* v10; // [rsp-30h] [rbp-70h]
	int v11; // [rsp-30h] [rbp-70h]
	int v12; // [rsp-30h] [rbp-70h]
	int v13; // [rsp-30h] [rbp-70h]
	int v14; // [rsp-30h] [rbp-70h]
	int v15; // [rsp-30h] [rbp-70h]
	__int64 v16; // [rsp+0h] [rbp-40h]
	__int16 v17; // [rsp+8h] [rbp-38h]
	wchar_t* v18=0; // [rsp+10h] [rbp-30h] BYREF
	WCHAR* lpszExt=0; // [rsp+18h] [rbp-28h] BYREF
	wchar_t* temp_file_name; // [rsp+20h] [rbp-20h]
	WCHAR* TEMP_PATH=0; // [rsp+28h] [rbp-18h] BYREF

	init_RSO();
	
	//.bat
	g_DATA.g_cursor = (_QWORD*)(g_salt + 0x83);
	v16 = 0i64;
	do{
		if (v16 > 3)
			break;
		v17 = *((char*)g_DATA.g_cursor)++;
		v9 = GET_TLS_StrLen();
		v0 = GET_TLS_StrLen();
		add_to_STR_tree_CHAR(-v17, v0);
		dup_from_STR_tree((LPVOID*)&v18, v9);
		v10 = lpszExt;
		v1 = GET_TLS_StrLen();
		v2 = v10;
		LODWORD(v10) = v1;
		add_to_STR_treeR(v2);
		add_to_STR_treeR(v18);
		dup_from_STR_tree((LPVOID*)&lpszExt, (int)v10);
	} while (!__OFADD__(1i64, v16++));

	temp_file_name = (wchar_t*)ZHeapAlloc(0x400ui64);
	v11 = GET_TLS_StrLen();
	v4 = GET_TLS_StrLen();
	TempPathW_to_tree(v4);
	dup_from_STR_tree((LPVOID*)&TEMP_PATH, v11);

	GetTempFileNameW(TEMP_PATH, g_PrefixString, 0, temp_file_name);
	v12 = GET_TLS_StrLen();
	v5 = GET_TLS_StrLen();
	add_to_STR_tree_AT(temp_file_name, v5);
	dup_from_STR_tree((LPVOID*)&g_DATA.g_temp_fn01, v12);
	//C:\Users\adm\AppData\Local\Temp\ABDA.tmp
	DeleteFileW2((const WCHAR*)g_DATA.g_temp_fn01);
	CreateDirectoryW1((wchar_t*)g_DATA.g_temp_fn01);

	GetTempFileNameW((LPCWSTR)g_DATA.g_temp_fn01, g_PrefixString, 0, temp_file_name);
	v13 = GET_TLS_StrLen();
	v6 = GET_TLS_StrLen();
	add_to_STR_tree_AT(temp_file_name, v6);
	dup_from_STR_tree((LPVOID*)&g_DATA.g_temp_fn02, v13);
	/* C:\Users\adm\AppData\Local\Temp\ABDA.tmp\189A.tmp\ */
	DeleteFileW2((const WCHAR*)g_DATA.g_temp_fn02);
	CreateDirectoryW1((wchar_t*)g_DATA.g_temp_fn02);

	GetTempFileNameW((LPCWSTR)g_DATA.g_temp_fn02, g_PrefixString, 0, temp_file_name);
	PathAddBackslashW((LPWSTR)g_DATA.g_temp_fn02);
	v14 = GET_TLS_StrLen();
	v7 = GET_TLS_StrLen();
	add_to_STR_tree_AT(temp_file_name, v7);
	dup_from_STR_tree((LPVOID*)&g_DATA.g_temp_fn03, v14);
	//C:\Users\adm\AppData\Local\Temp\ABDA.tmp\189A.tmp\1DA7.bat
	DeleteFileW2((const WCHAR*)g_DATA.g_temp_fn03);
	PathRenameExtensionW((LPWSTR)g_DATA.g_temp_fn03, lpszExt);

	GetTempFileNameW((LPCWSTR)g_DATA.g_temp_fn02, g_PrefixString, 0, temp_file_name);
	v15 = GET_TLS_StrLen();
	v8 = GET_TLS_StrLen();
	add_to_STR_tree_AT(temp_file_name, v8);
	dup_from_STR_tree((LPVOID*)&g_DATA.g_temp_fn04, v15);
	//C:\Users\adm\AppData\Local\Temp\ABDA.tmp\189A.tmp\CD02.tmp

	ZHeapFree(temp_file_name);
	HeapFree__0(TEMP_PATH);
	HeapFree__0(v18);
	HeapFree__0(lpszExt);
}
__int64 __fastcall MyGetCurrentDirectoryW(int apos){
	char* v1; // rdi
	signed int CurrentDirectoryW; // eax
	signed int v3; // ebx
	__int64 result; // rax

	v1 = alloc_to_STR_tree(0x104, apos);
	CurrentDirectoryW = GetCurrentDirectoryW(0x104u, (LPWSTR)v1);
	v3 = CurrentDirectoryW;
	if (CurrentDirectoryW){
		if (*(_WORD*)&v1[2 * CurrentDirectoryW - 2] != 0x5C){
			*(_WORD*)&v1[2 * CurrentDirectoryW] = 0x5C;
			v3 = CurrentDirectoryW + 1;
		}
	}
	TLS_cutr_str(0x104 - v3);
	result = v3;
	*(_WORD*)&v1[2 * v3] = 0;
	return result;
}
__int64 __fastcall mySHGetFolderLocation(int csidl, wchar_t* String){
	unsigned int v3; // ebx
	unsigned int v4; // eax
	LPCITEMIDLIST pidl; // [rsp+48h] [rbp+10h] BYREF

	v3 = 0;
	if (!SHGetFolderLocation(0i64, csidl, 0i64, 0, (LPITEMIDLIST*)&pidl)){
		if (SHGetPathFromIDListW(pidl, String)){
			v4 = wcslen(String);
			v3 = v4;
			if (v4){
				if (String[v4 - 1] != '\\'){
					String[v4] = '\\';
					v3 = v4 + 1;
				}
			}
		}
		CoTaskMemFree((LPVOID)pidl);
	}
	String[v3] = 0;
	return v3;
}
__int64 __fastcall GetKnownFolderPath(int a1, int a2){
	int len; // edi
	wchar_t* SHpath; // rax
	wchar_t* SHpath_ptr; // rsi
	HMODULE hmod; // rax
	HMODULE hmod_1; // rbx
	HRESULT(__stdcall * SHGetKnownFolderPath)(const KNOWNFOLDERID* const, DWORD, HANDLE, PWSTR*); // rax
	int v9; // eax
	int v10; // ebx
	int v11; // ebx
	int v12; // ebx
	int v13; // ebx
	int v14; // ebx
	int v15; // ebx
	int v16; // ebx
	int csidl; // ecx
	__int64 result; // rax
	wchar_t* Source; // [rsp+50h] [rbp+18h] BYREF

	len = CSIDL_DESKTOP;
	SHpath = (wchar_t*)alloc_to_STR_tree(0x104, a2);
	SHpath_ptr = SHpath;
	if (a1 != 2){
		if (a1){
			v10 = a1 - 1;
			if (v10){
				v11 = v10 - 2;
				if (v11){
					v12 = v11 - 1;
					if (v12){
						v13 = v12 - 1;
						if (v13){
							v14 = v13 - 1;
							if (v14){
								v15 = v14 - 1;
								if (v15){
									v16 = v15 - 1;
									if (v16){
										if (v16 != 1)
											goto LABEL_28;
										csidl = CSIDL_COMMON_DOCUMENTS;
									} else{
										csidl = CSIDL_MYPICTURES;
									}
								} else{
									csidl = CSIDL_MYMUSIC;
								}
							} else{
								csidl = CSIDL_MYVIDEO;
							}
						} else{
							csidl = CSIDL_COMMON_APPDATA;
						}
					} else{
						csidl = CSIDL_APPDATA;
					}
				} else{
					csidl = CSIDL_MYDOCUMENTS;
				}
			} else{
				csidl = CSIDL_PROGRAM_FILES;
			}
		} else{
			csidl = CSIDL_DESKTOP;
		}
		v9 = mySHGetFolderLocation(csidl, SHpath);
		goto LABEL_27;
	}
	hmod = LoadLibraryW(L"Shell32.DLL");
	hmod_1 = hmod;
	if (!hmod)
		goto LABEL_7;
	SHGetKnownFolderPath = (HRESULT(__stdcall*)(const KNOWNFOLDERID* const, DWORD, HANDLE, PWSTR*))GetProcAddress(hmod, "SHGetKnownFolderPath");
	p_SHGetKnownFolderPath = SHGetKnownFolderPath;
	if (SHGetKnownFolderPath){
		if (!SHGetKnownFolderPath(&g_cFOLDERID_Downloads, 0, 0i64, &Source)){
			wcscpy(SHpath_ptr, Source);
			wcscat(SHpath_ptr, slash);
			len = wcslen(SHpath_ptr);
			CoTaskMemFree(Source);
		}
	}
	FreeLibrary(hmod_1);
	if (!len){
LABEL_7:
		mySHGetFolderLocation(CSIDL_PROFILE, SHpath_ptr);
		wcscat(SHpath_ptr, L"Downloads\\");
		v9 = wcslen(SHpath_ptr);
LABEL_27:
		len = v9;
	}
LABEL_28:
	TLS_cutr_str(0x104 - len);
	result = len;
	SHpath_ptr[len] = CSIDL_DESKTOP;
	return result;
}
void __fastcall MySleep(DWORD a1){
	if (!g_timeBeginPeriod_flag){
		timeBeginPeriod(1u);
		g_timeBeginPeriod_flag = 1;
	}
	Sleep(a1);
}
HWND MyProcess_ForegroundWindow(){
	HWND ForegroundWindow; // rax
	HWND v1; // rbx
	DWORD dwProcessId; // [rsp+30h] [rbp+8h] BYREF

	ForegroundWindow = GetForegroundWindow();
	v1 = ForegroundWindow;
	if (!ForegroundWindow)
		return v1;
	GetWindowThreadProcessId(ForegroundWindow, &dwProcessId);
	if (dwProcessId != GetCurrentProcessId())
		return 0i64;
	return v1;
}
int __stdcall BrowseCallbackProc(HWND hwnd, UINT uMsg, LPARAM lParam, LPARAM lpData){
	if (uMsg != 1)
		return 0;
	if (!lpData)
		return 0;
	SendMessageW(hwnd, BFFM_SETSELECTIONW, 1ui64, lpData);
	Sleep(200u);
	PostMessageW(hwnd, BFFM_SETSELECTIONW, 1ui64, lpData);
	return 0;
}
__int64 __fastcall EnumFunc(HWND a1){
	DWORD WindowThreadProcessId; // ebx
	stru0x28* node; // rbx
	DWORD CurrentThreadId; // eax

	WindowThreadProcessId = GetWindowThreadProcessId(a1, 0i64);
	if (WindowThreadProcessId != GetCurrentThreadId())
		return 1i64;
	if (!IsWindowVisible(a1))
		return 1i64;
	// stru0x28 *__shifted(stru0x28,0x10) node; // rbx
	node = (stru0x28*)add_to_tree(&g_tree_stru0x28.s20, 0x28);
	node->s20.right = (stru0x20*)a1;
	CurrentThreadId = GetCurrentThreadId();
	LOWORD(node->s20.hObject) = 0;
	LODWORD(node->s20.left) = CurrentThreadId;
	if ((GetWindowLongPtrW(a1, GWL_EXSTYLE) & WS_EX_TOPMOST) != 0)
		LOBYTE(node->s20.hObject) = 1;
	if (a1 == GetForegroundWindow())
		return 1i64;
	if (!IsWindowEnabled(a1))
		return 1i64;

	BYTE1(node->s20.hObject) = 1;
	EnableWindow(a1, 0);
	return 1i64;
}
void __fastcall wnd_set_back(int lparam){
	stru0x28* left; // rbx
	stru0x28* v2; // rdi
	stru0x28* v3; // rbx
	stru0x28* v4; // rdi

	if (lparam){
		EnumWindows((WNDENUMPROC)EnumFunc, lparam);
		left = (stru0x28*)g_tree_stru0x28.s20.left;
		if (g_tree_stru0x28.s20.left){
			do{
				v2 = (stru0x28*)left->s20.left;
				if (LODWORD(left->s20.hObject) == GetCurrentThreadId()){
					if (LOBYTE(left->fld04))
						SetWindowPos((HWND)left->s20.index, (HWND)HWND_NOTOPMOST, 0, 0, 0, 0, 3u);
				}
				left = v2;
			} while (v2);
		}
	} else{
		v3 = (stru0x28*)g_tree_stru0x28.s20.left;
		if (g_tree_stru0x28.s20.left){
			do{
				v4 = (stru0x28*)v3->s20.left;
				if (LODWORD(v3->s20.hObject) == GetCurrentThreadId()){
					if (BYTE1(v3->fld04))
						EnableWindow((HWND)v3->s20.index, 1);
					if (LOBYTE(v3->fld04))
						SetWindowPos((HWND)v3->s20.index, (HWND)-1ui64, 0, 0, 0, 0, 3u);
					del_fr_tree(&g_tree_stru0x28.s20.left, &v3->s20.hObject);
				}
				v3 = v4;
			} while (v4);
		}
	}
}
__int64 __fastcall mySHBrowseForFolderW(const CHAR* aTitle, const wchar_t* aPath, int aPos){
	int v6; // ebx
	HMODULE LibraryW; // rax
	HMODULE v8; // r14
	LPITEMIDLIST(__stdcall * SHBrowseForFolderW)(LPBROWSEINFOW); // r13
	BOOL(__stdcall * SHGetPathFromIDListW1)(LPCITEMIDLIST, LPWSTR); // rax
	const wchar_t* path; // rdx
	int len; // eax
	ITEMIDLIST* itemlist; // r15
	WCHAR* szPath; // rsi
	int v15; // eax
	BROWSEINFOW bi; // [rsp+28h] [rbp-E0h] BYREF
	wchar_t Destination[264]; // [rsp+68h] [rbp-A0h] BYREF
	void(__stdcall * SHGetPathFromIDListW2)(LPCITEMIDLIST, LPWSTR); // [rsp+2C0h] [rbp+1B8h]

	if (!g_IsCoInitialized){
		g_IsCoInitialized = 1;
		CoInitialize(0i64);
	}
	memset(&bi, 0, sizeof(bi));
	v6 = 0;
	LibraryW = LoadLibraryW(L"SHELL32.DLL");
	v8 = LibraryW;
	if (!LibraryW)
		goto LABEL_13;
	SHBrowseForFolderW = (LPITEMIDLIST(__stdcall*)(LPBROWSEINFOW))GetProcAddress(LibraryW, "SHBrowseForFolderW");
	SHGetPathFromIDListW1 = (BOOL(__stdcall*)(LPCITEMIDLIST, LPWSTR))GetProcAddress(v8, "SHGetPathFromIDListW");
	path = (const wchar_t*)&nullstr;
	if (aPath)
		path = aPath;
	SHGetPathFromIDListW2 = (void(__stdcall*)(LPCITEMIDLIST, LPWSTR))SHGetPathFromIDListW1;
	wcsncpy(Destination, path, 259ui64);
	Destination[259] = 0;
	len = wcslen(Destination);

	if (len > 3 && *((_WORD*)&bi.iImage + len + 3) == '\\')
		*((_WORD*)&bi.iImage + len + 3) = 0;

	bi.lpszTitle = (LPCWSTR)aTitle;
	bi.hwndOwner = MyProcess_ForegroundWindow();
	bi.ulFlags = BIF_USENEWUI;
	bi.lpfn = BrowseCallbackProc;
	bi.lParam = (LPARAM)Destination;
	wnd_set_back(1);
	itemlist = SHBrowseForFolderW(&bi);
	wnd_set_back(0);
	if (itemlist){
		szPath = (WCHAR*)alloc_to_STR_tree(0x104, aPos);
		*szPath = 0;
		SHGetPathFromIDListW2(itemlist, szPath);
		CoTaskMemFree(itemlist);
		v15 = wcslen(szPath);
		v6 = v15;
		if (szPath[v15 - 1] != 0x5C){
			*(_DWORD*)&szPath[v15] = 0x5C;
			v6 = v15 + 1;
		}
	}
	FreeLibrary(v8);
	if (!v6)
		LABEL_13:
	*(_WORD*)alloc_to_STR_tree(0x104, aPos) = 0;
	return TLS_cutr_str(0x104 - v6);
}
char* __fastcall MyBrowseForFolder(__int64 aKnownPathID, wchar_t* aTitle, __int64 a3, __int64 a4, __int64 aPos){
	int v5; // eax
	wchar_t* v6; // rcx
	int v7; // eax
	int v8; // eax
	int v9; // eax
	int v10; // eax
	int v11; // eax
	int v12; // eax
	int v13; // eax
	int v14; // eax
	int v15; // eax
	int v16; // eax
	__int64 g_temp_fn01; // [rsp-8h] [rbp-58h]
	int v19; // [rsp-8h] [rbp-58h]
	int v20; // [rsp-8h] [rbp-58h]
	int v21; // [rsp-8h] [rbp-58h]
	int v22; // [rsp-8h] [rbp-58h]
	int v23; // [rsp-8h] [rbp-58h]
	int v24; // [rsp-8h] [rbp-58h]
	int v25; // [rsp-8h] [rbp-58h]
	int v26; // [rsp-8h] [rbp-58h]
	int v27; // [rsp-8h] [rbp-58h]
	int v28; // [rsp-8h] [rbp-58h]
	wchar_t* v29; // [rsp+0h] [rbp-50h]
	char* v30; // [rsp+0h] [rbp-50h]
	CHAR* v31; // [rsp+30h] [rbp-20h] BYREF
	void* v32[3]; // [rsp+38h] [rbp-18h] BYREF

	v32[1] = 0i64;
	v32[0] = 0i64;
	v31 = 0i64;
	init_RSO();
	SET_TLS_2(aPos);
	wstrdup_10((LPVOID*)&v31, aTitle);
	switch (aKnownPathID){
		case 0i64:
			goto LABEL_24;
		case 1i64:
			g_temp_fn01 = g_DATA.g_temp_fn01;
			v5 = GET_TLS_StrLen();
			v6 = (wchar_t*)g_temp_fn01;
			LODWORD(g_temp_fn01) = v5;
			add_to_STR_treeR(v6);
			dup_from_STR_tree(v32, g_temp_fn01);
			goto LABEL_25;
		case 2i64:
			v19 = GET_TLS_StrLen();
			v7 = GET_TLS_StrLen();
			GetKnownFolderPath(4, v7);
			dup_from_STR_tree(v32, v19);
			goto LABEL_25;
		case 3i64:
			v20 = GET_TLS_StrLen();
			v8 = GET_TLS_StrLen();
			GetKnownFolderPath(0, v8);
			dup_from_STR_tree(v32, v20);
			goto LABEL_25;
		case 4i64:
			v21 = GET_TLS_StrLen();
			v9 = GET_TLS_StrLen();
			GetKnownFolderPath(3, v9);
			dup_from_STR_tree(v32, v21);
			goto LABEL_25;
		case 5i64:
			v22 = GET_TLS_StrLen();
			v10 = GET_TLS_StrLen();
			GetKnownFolderPath(8, v10);
			dup_from_STR_tree(v32, v22);
			goto LABEL_25;
		case 6i64:
			v23 = GET_TLS_StrLen();
			v11 = GET_TLS_StrLen();
			GetKnownFolderPath(7, v11);
			dup_from_STR_tree(v32, v23);
			goto LABEL_25;
		case 7i64:
			v24 = GET_TLS_StrLen();
			v12 = GET_TLS_StrLen();
			GetKnownFolderPath(6, v12);
			dup_from_STR_tree(v32, v24);
			goto LABEL_25;
		case 8i64:
			v25 = GET_TLS_StrLen();
			v13 = GET_TLS_StrLen();
			GetKnownFolderPath(2, v13);
			dup_from_STR_tree(v32, v25);
			goto LABEL_25;
		case 9i64:
			v26 = GET_TLS_StrLen();
			v14 = GET_TLS_StrLen();
			GetKnownFolderPath(1, v14);
			dup_from_STR_tree(v32, v26);
			goto LABEL_25;
	}
	if (aKnownPathID != 0xA){
LABEL_24:
		v28 = GET_TLS_StrLen();
		v16 = GET_TLS_StrLen();
		MyGetCurrentDirectoryW(v16);
		dup_from_STR_tree(v32, v28);
		goto LABEL_25;
	}
	v27 = GET_TLS_StrLen();
	v15 = GET_TLS_StrLen();
	mySHBrowseForFolderW(v31, g_PrefixString, v15);
	dup_from_STR_tree(v32, v27);
	if (mywcscmp((wchar_t*)v32[0], 0i64)) {
		//asm_CLEAR_TEMP_AND_EXIT(0i64);
		exit(0);
	}
	MySleep(1u);
LABEL_25:
	v29 = (wchar_t*)v32[0];
	GET_TLS_StrLen();
	add_to_STR_treeR(v29);
	v30 = (char*)v29 + STR_tree_root_0();
	HeapFree__0(v32[0]);
	HeapFree__0(v31);
	return v30;
}
void __fastcall MyShellExecuteOpen(wchar_t* aFile, wchar_t* aDir, wchar_t* aParams){
	__int64 v3; // rax
	__int64 v4; // rax
	WCHAR* file; // [rsp+0h] [rbp-B0h] BYREF
	WCHAR* dir; // [rsp+8h] [rbp-A8h] BYREF
	WCHAR* params; // [rsp+10h] [rbp-A0h] BYREF
	SHELLEXECUTEINFOW v8; // [rsp+18h] [rbp-98h] BYREF
	__int64 v9; // [rsp+88h] [rbp-28h]
	__int64 v10[4]; // [rsp+90h] [rbp-20h] BYREF

	init_RSO();
	wstrdup_10((LPVOID*)&file, aFile);
	wstrdup_10((LPVOID*)&dir, aDir);
	wstrdup_10((LPVOID*)&params, aParams);
	v8.cbSize = 0x70;
	v8.fMask = 0x140;
	v8.nShow = 0;
	v8.lpVerb = L"open\x00**";
	v8.lpFile = file;
	v8.lpParameters = params;
	v8.lpDirectory = dir;
	LODWORD(v3) = ShellExecuteExW(&v8);
	v9 = v3;
	do{
		do{
			MySleep(0x19u);
			LODWORD(v4) = GetExitCodeProcess(v8.hProcess, (LPDWORD)v10);
		} while (!v4);
	} while (v10[0] == 0x103);
	HeapFree__0(file);
	HeapFree__0(dir);
	HeapFree__0(params);
}
__int64 __fastcall ptr(__int16* a1){
	return *a1;
}
char* __fastcall decode(wchar_t* name){
	char* v2; // [rsp-30h] [rbp-60h]
	WCHAR* lpName; // [rsp+0h] [rbp-30h] BYREF
	HRSRC ResourceW; // [rsp+8h] [rbp-28h]
	char* Resource; // [rsp+10h] [rbp-20h]
	char* out; // [rsp+18h] [rbp-18h]
	__int64 total_out; // [rsp+20h] [rbp-10h] BYREF
	unsigned __int64 err; // [rsp+28h] [rbp-8h]

	err = Z_OK;
	total_out = 0i64;
	out = 0i64;
	Resource = 0i64;
	ResourceW = 0i64;
	lpName = 0i64;
	init_RSO();
	wstrdup_10((LPVOID*)&lpName, name);
	ResourceW = FindResourceW(g_DATA.g_module0handle, lpName, (LPCWSTR)RT_RCDATA);
	if (ResourceW){
		Resource = Alloc_LoadResource(g_DATA.g_module0handle, ResourceW);
		g_DATA.g_sizeofres = HeapSize__0(Resource);
	}
	out = (char*)ZHeapAlloc(0x200ui64);
	total_out = 0x200i64;
	err = inf(out, (unsigned int*)&total_out, Resource, g_DATA.g_sizeofres);
	v2 = out;
	HeapFree__0(lpName);
	return v2;
}
BYTE __fastcall MySetCurrentDirectoryW(const WCHAR* a1){
	return a1 && SetCurrentDirectoryW(a1);
}
__int64 __fastcall salt_MyBrowseForFolder(__int16* a1){
	int v1; // eax
	int v2; // eax
	wchar_t* v3; // rcx
	__int64 v5; // rax
	__int64 v6; // r8
	__int64 v7; // r9
	wchar_t* v9; // [rsp-40h] [rbp-70h]
	__int64 v10; // [rsp-38h] [rbp-68h]
	int v11; // [rsp-30h] [rbp-60h]
	wchar_t* v12; // [rsp-30h] [rbp-60h]
	int v13; // [rsp-30h] [rbp-60h]
	__int64 v14; // [rsp+0h] [rbp-30h]
	__int16 v15; // [rsp+8h] [rbp-28h]
	wchar_t* v16; // [rsp+10h] [rbp-20h] BYREF
	wchar_t* v17; // [rsp+18h] [rbp-18h] BYREF
	WCHAR* v18; // [rsp+20h] [rbp-10h] BYREF

	v18 = 0i64;
	v17 = 0i64;
	v16 = 0i64;
	init_RSO();

	//Select the working directory
	g_DATA.g_cursor = (_QWORD*)(g_salt + 0x30);
	v14 = 0i64;
	do{
		if (v14 > 0x1B)
			break;
		v15 = *((char*)g_DATA.g_cursor)++;
		v11 = GET_TLS_StrLen();
		v1 = GET_TLS_StrLen();
		add_to_STR_tree_CHAR(-v15, v1);
		dup_from_STR_tree((LPVOID*)&v16, v11);
		v12 = v17;
		v2 = GET_TLS_StrLen();
		v3 = v12;
		LODWORD(v12) = v2;
		add_to_STR_treeR(v3);
		add_to_STR_treeR(v16);
		dup_from_STR_tree((LPVOID*)&v17, (int)v12);
	} while (!__OFADD__(1i64, v14++));
	v13 = GET_TLS_StrLen();
	v10 = GET_TLS_StrLen();
	v9 = v17;
	v5 = ptr(a1);
	MyBrowseForFolder(v5, v9, 0, 0, v10);
	dup_from_STR_tree((LPVOID*)&v18, v13);
	MySetCurrentDirectoryW(v18);
	HeapFree__0(v17);
	HeapFree__0(v16);
	HeapFree__0(v18);
	return 0i64;
}

LRESULT __fastcall wndproc(HWND hWnd, UINT a2, WPARAM a3, LPARAM a4){
	wchar_t* strUserData; // rdi
	int len; // ebx
	WCHAR* mem; // rax
	HWND lhWnd_edit_ctrl; // rcx

	if (a2 == 2){
		UnregisterClassW(g_lpClassName, g_DATA.g_hModule);
		g_wndProcExit = 1;
		return 0i64;
	}
	if (a2 == 0x10){
LABEL_9:
		if (g_isWindowEnabled)
			EnableWindow(g_fgWnd, 1);
		wnd_set_back(0);
		DestroyWindow(hWnd);
		return 0i64;
	}
	if (a2 != 0x111)
		return DefWindowProcW(hWnd, a2, a3, a4);
	if ((unsigned __int16)a3 == 0x3E8){
		strUserData = (wchar_t*)GetWindowLongPtrW(hWnd, GWLP_USERDATA);
		len = GetWindowTextLengthW(hWnd_edit_ctrl) + 1;
		mem = (WCHAR*)HeapAlloc(g_DATA.g_hHeap, 0, 2i64 * len);
		lhWnd_edit_ctrl = hWnd_edit_ctrl;
		*(_QWORD*)strUserData = mem;
		GetWindowTextW(lhWnd_edit_ctrl, mem, len);
		goto LABEL_9;
	}
	if ((unsigned __int16)a3 == 0x3E9)
		goto LABEL_9;
	return 0i64;
}
int __fastcall create_InputRequester(wchar_t* wndname, wchar_t* labelname, wchar_t* edit_value, char a4, int a5){
	wchar_t* lpname; // r14
	wchar_t* lpstaticname; // r15
	wchar_t* lptextvalue; // rsi
	HCURSOR CursorW; // rax
	HWND hWndParent; // rdi
	int Y; // ebx
	int X; // eax
	HWND _hwnd; // rax
	HWND _hwnd_1; // rdi
	int v17; // r9d
	LPARAM v18; // rbx
	WPARAM v19; // rax
	HACCEL v20; // rbx
	int len; // eax
	char* v22; // rax
	struct tagACCEL paccel; // [rsp+68h] [rbp-61h] BYREF
	char v25; // [rsp+6Eh] [rbp-5Bh]
	int v26; // [rsp+70h] [rbp-59h]
	WNDCLASSEXW wnd; // [rsp+78h] [rbp-51h] BYREF
	struct tagMSG Msg; // [rsp+C8h] [rbp-1h] BYREF
	LONG_PTR strUserData; // [rsp+128h] [rbp+5Fh] BYREF

	strUserData = 0i64;
	lpname = wcscpy_heap_alloc(wndname);
	lpstaticname = wcscpy_heap_alloc(labelname);
	lptextvalue = wcscpy_heap_alloc(edit_value);

	if (!g_default_font)
		g_default_font = GetStockObject(DEFAULT_GUI_FONT);
	wnd.cbSize = 0x50;
	wnd.style = 3;
	wnd.hInstance = g_DATA.g_hModule;
	wnd.lpfnWndProc = (WNDPROC)wndproc;
	*(_QWORD*)&wnd.cbClsExtra = 0i64;
	wnd.hIcon = LoadIconW(g_DATA.g_hModule, (LPCWSTR)1);
	CursorW = LoadCursorW(0i64, (LPCWSTR)0x7F00);
	*(__m128i*)& wnd.hbrBackground = _mm_load_si128(&stru_1400196A0);
	wnd.hCursor = CursorW;
	wnd.hIconSm = 0i64;
	wnd.lpszClassName = g_lpClassName;
	RegisterClassExW(&wnd);

	g_wndProcExit = 0;
	g_fgWnd = MyProcess_ForegroundWindow();
	wnd_set_back(1);
	if (g_fgWnd && IsWindowEnabled(g_fgWnd)){
		EnableWindow(g_fgWnd, 0);
		g_isWindowEnabled = 1;
	} else{
		g_isWindowEnabled = 0;
	}
	hWndParent = MyProcess_ForegroundWindow();
	Y = GetSystemMetrics(1) / 2 - 65;
	X = GetSystemMetrics(0);
	_hwnd = CreateWindowExW(
		0,
		g_lpClassName,
		lpname,
		0x10C80000u,
		X / 2 - 0x96,
		Y,
		0x12C,
		0x82,
		hWndParent,
		0i64,
		g_DATA.g_hModule,
		0i64);
	_hwnd_1 = _hwnd;
	if (!_hwnd){
LABEL_21:
		if (strUserData)
			goto LABEL_23;
		goto LABEL_22;
	}
	SetWindowLongPtrW(_hwnd, GWLP_USERDATA, (LONG_PTR)&strUserData);
	static_control_hwnd = CreateWindowExW(
		0,
		L"STATIC",
		lpstaticname,
		0x5000000Bu,
		0xA,
		0xA,
		0x118,
		0x16,
		_hwnd_1,
		0i64,
		g_DATA.g_hModule,
		0i64);
	SendMessageW(static_control_hwnd, WM_SETFONT, (WPARAM)g_default_font, 1i64);
	v17 = 0;
	if ((a4 & 1) != 0)
		v17 = 0x20;
	hWnd_edit_ctrl = CreateWindowExW(
		0x200u,
		L"EDIT",
		0i64,
		v17 | 0x50010080u,
		0xA,
		0x20,
		0x113,
		0x15,
		_hwnd_1,
		(HMENU)0xA,
		g_DATA.g_hModule,
		0i64);
	SendMessageW(hWnd_edit_ctrl, WM_SETFONT, (WPARAM)g_default_font, 1i64);
	SetFocus(hWnd_edit_ctrl);
	if (lptextvalue){
		SendMessageW(hWnd_edit_ctrl, WM_SETTEXT, 0i64, (LPARAM)lptextvalue);
		v18 = wcslen(lptextvalue);
		v19 = wcslen(lptextvalue);
		SendMessageW(hWnd_edit_ctrl, EM_SETSEL, v19, v18);
	}
	hWnd_btnOK_ctrl = (__int64)CreateWindowExW(
		0,
		L"BUTTON",
		L"OK",
		0x50010001u,
		0x6E,
		0x43,
		0x50,
		0x19,
		_hwnd_1,
		(HMENU)0x3E8,
		g_DATA.g_hModule,
		0i64);
	SendMessageW((HWND)hWnd_btnOK_ctrl, WM_SETFONT, (WPARAM)g_default_font, 1i64);

	paccel.fVirt = 1;
	*(_DWORD*)&paccel.key = 0x3E8000D;
	v25 = 1;
	v26 = 0x3E9001B;
	v20 = CreateAcceleratorTableW(&paccel, 2);
	SetForegroundWindow(_hwnd_1);
	BringWindowToTop(_hwnd_1);
	while (!g_wndProcExit && GetMessageW(&Msg, 0i64, 0, 0)){
		if (!TranslateAcceleratorW(_hwnd_1, v20, &Msg)){
			TranslateMessage(&Msg);
			DispatchMessageW(&Msg);
		}
	}

	if (v20)
		DestroyAcceleratorTable(v20);

	if (strUserData){
		len = wcslen((const wchar_t*)strUserData);
		v22 = alloc_to_STR_tree(len, a5);
		wcscpy((wchar_t*)v22, (const wchar_t*)strUserData);
		LODWORD(_hwnd) = HeapFree(g_DATA.g_hHeap, 0, (LPVOID)strUserData);
		goto LABEL_21;
	}
LABEL_22:
	LODWORD(_hwnd) = str_setz(a5);
LABEL_23:
	if (lpname)
		LODWORD(_hwnd) = HeapFree(g_DATA.g_hHeap, 0, lpname);
	if (lpstaticname)
		LODWORD(_hwnd) = HeapFree(g_DATA.g_hHeap, 0, lpstaticname);
	if (lptextvalue)
		LODWORD(_hwnd) = HeapFree(g_DATA.g_hHeap, 0, lptextvalue);
	return (int)_hwnd;
}
__int64 __stdcall MyMessageBox(LPCWSTR lpCaption, LPCWSTR lpText, UINT uType){
	HWND v6; // rbx
	__int64 v7; // rbx

	v6 = MyProcess_ForegroundWindow();
	wnd_set_back(1);
	v7 = MessageBoxW(v6, lpText, lpCaption, uType);
	wnd_set_back(0);
	return v7;
}
void __fastcall mywstrcpy_space2(wchar_t* a1, unsigned __int16* a2, int a3){
	wchar_t* v3; // rbx
	int v4; // edi
	int v6; // eax
	int v7; // r14d
	wchar_t* v8; // rsi
	int v9; // ecx
	__int64 v10; // rbx
	__int64 v11; // rdx
	wchar_t* v12; // rcx
	int v13; // eax
	int v14; // r15d
	char* v15; // rdi
	int v16; // [rsp+50h] [rbp+8h]

	v3 = a1;
	v4 = 0x20;
	if (a2)
		v4 = *a2;
	v6 = mywstrlen(a1);
	v7 = v6;
	if (v3){
		v8 = v3;
		if (*v3 == v4){
			do{
				v9 = v3[1];
				++v3;
			} while (v9 == v4);
		}
		v10 = v3 - v8;
		if ((int)v10 >= v6){
			v7 = v6 - v10;
		} else{
			v11 = v6;
			v12 = &v8[v11 - 1];
			if (*v12 == v4){
				do
					v13 = *--v12;
				while (v13 == v4);
			}
			v7 -= v10 + (((__int64)v8 + v11 * 2 - (__int64)v12 - 2) >> 1);
		}
	} else{
		LODWORD(v10) = v16;
		v8 = 0i64;
	}
	v14 = GET_STR_IN_tree(v8);
	v15 = alloc_to_STR_tree(v7, a3);
	if (v14)
		v8 = (wchar_t*)GET_CHAR_AT_tree(v14);
	if (v8)
		wstrcpy(v15, &v8[(int)v10], v7);
	else
		*(_WORD*)v15 = 0;
}
void __fastcall mywstrcpy_space(wchar_t* a1, int a2){
	mywstrcpy_space2(a1, g_SPACE, a2);
}
char* __fastcall MyInputRequester(__int64 a1, __int64 a2, __int64 a3, __int64 a4, __int64 a5){
	int v5; // eax
	strNode* v6; // rax
	int v7; // eax
	strNode* v8; // rax
	int v9; // eax
	int v10; // eax
	strNode* v11; // rax
	int v12; // eax
	strNode* v13; // rax
	int v14; // eax
	strNode* v15; // rax
	wchar_t* v17; // [rsp+0h] [rbp-88h]
	__int64 v18; // [rsp+8h] [rbp-80h]
	__int64 v19; // [rsp+8h] [rbp-80h]
	LPCWSTR v20; // [rsp+8h] [rbp-80h]
	__int64 v21; // [rsp+10h] [rbp-78h]
	__int64 v22; // [rsp+10h] [rbp-78h]
	wchar_t* v23; // [rsp+10h] [rbp-78h]
	int v24; // [rsp+10h] [rbp-78h]
	__int64 v25; // [rsp+10h] [rbp-78h]
	int v26; // [rsp+18h] [rbp-70h]
	int v27; // [rsp+18h] [rbp-70h]
	char v28; // [rsp+18h] [rbp-70h]
	int v29; // [rsp+18h] [rbp-70h]
	UINT v30; // [rsp+18h] [rbp-70h]
	int v31; // [rsp+20h] [rbp-68h]
	int v32; // [rsp+28h] [rbp-60h]
	int v33; // [rsp+28h] [rbp-60h]
	int v34; // [rsp+28h] [rbp-60h]
	int v35; // [rsp+28h] [rbp-60h]
	__int64 v36; // [rsp+28h] [rbp-60h]
	wchar_t* v37; // [rsp+28h] [rbp-60h]
	char* v38; // [rsp+28h] [rbp-60h]
	wchar_t* v39; // [rsp+58h] [rbp-30h] BYREF
	wchar_t* v40; // [rsp+60h] [rbp-28h] BYREF
	wchar_t* v41; // [rsp+68h] [rbp-20h] BYREF
	void* v42[3]; // [rsp+70h] [rbp-18h] BYREF

	v42[1] = 0i64;
	v42[0] = 0i64;
	v41 = 0i64;
	v40 = 0i64;
	v39 = 0i64;
	init_RSO();
	SET_TLS_2(a5);
	if (ptr((__int16*)(a1 + 2)) == 1){
		v32 = GET_TLS_StrLen();
		GET_TLS_StrLen();
		GET_TLS_StrLen();
		v5 = GET_TLS_StrLen();
		add_to_STR_tree_AT2((wchar_t*)(a1 + 0x40), 0x28i64, v5);
		v6 = STR_tree_root();
		mywstrcpy_space((wchar_t*)((char*)v6 + v21), v26);
		dup_from_STR_tree((LPVOID*)&v39, v32);
		v33 = GET_TLS_StrLen();
		GET_TLS_StrLen();
		GET_TLS_StrLen();
		v7 = GET_TLS_StrLen();
		add_to_STR_tree_AT2((wchar_t*)(a1 + 0x12C), 0x64i64, v7);
		v8 = STR_tree_root();
		mywstrcpy_space((wchar_t*)((char*)v8 + v22), v27);
		dup_from_STR_tree((LPVOID*)&v40, v33);
		v34 = GET_TLS_StrLen();
		GET_TLS_StrLen();
		GET_TLS_StrLen();
		v9 = GET_TLS_StrLen();
		STR_TREE_MOVE_COPY(v40, 2, (DWORD*)g_DATA.g_copy_of_star, v9);
		add2_to_StrTreeLen();
		GET_TLS_StrLen();
		v10 = GET_TLS_StrLen();
		STR_TREE_MOVE_COPY(v40, 1, (DWORD*)g_DATA.g_copy_of_star, v10);
		STR_tree_root();
		v11 = STR_tree_root();
		create_InputRequester(v17, (wchar_t*)((char*)v11 + v18), v23, v28, v31);
		dup_from_STR_tree((LPVOID*)&v41, v34);
		if (mywcscmp(v41, 0i64)) {
			//asm_CLEAR_TEMP_AND_EXIT(0i64);
			exit(0);
		}
		v35 = GET_TLS_StrLen();
		GET_TLS_StrLen();
		GET_TLS_StrLen();
		v12 = GET_TLS_StrLen();
		mywstrcpy_space(v41, v12);
		v13 = STR_tree_root();
		MD_stuff((const WCHAR*)((char*)v13 + v19), v24, v29);
		dup_from_STR_tree(v42, v35);
		if (!mywcscmp(v39, (wchar_t*)v42[0])){
			GET_TLS_StrLen();
			GET_TLS_StrLen();
			v14 = GET_TLS_StrLen();
			STR_TREE_MOVE_COPY(v40, 3, (DWORD*)g_DATA.g_copy_of_star, v14);
			add2_to_StrTreeLen();
			v15 = STR_tree_root();
			MyMessageBox(v20, (LPCWSTR)((char*)v15 + v25), v30);
			SET_TLS_2(v36); 
			//asm_CLEAR_TEMP_AND_EXIT(0i64);
			exit(0);
		}
	}
	v37 = (wchar_t*)v42[0];
	GET_TLS_StrLen();
	add_to_STR_treeR(v37);
	v38 = (char*)v37 + STR_tree_root_0();
	HeapFree__0(v40);
	HeapFree__0(v41);
	HeapFree__0(v39);
	HeapFree__0(v42[0]);
	return v38;
}
void __fastcall tree_stuff01(wchar_t* asrc, int a2, int alen, int a4){
	int len; // ebp
	wchar_t* cur; // rbx
	int v8; // r14d
	char* v9; // rdi
	wchar_t v10; // ax
	signed __int64 v11; // rbx

	len = alen;
	cur = asrc;
	if (alen < 0)
		len = 0;

	v8 = GET_STR_IN_tree(asrc);
	v9 = alloc_to_STR_tree(len, a4);
	if (v8)
		cur = (wchar_t*)GET_CHAR_AT_tree(v8);
	if (cur){
		if (a2 <= 1){
LABEL_9:
			v10 = *cur;
			if (*cur){
				v11 = (char*)cur - v9;
				do{
					if (!len)
						break;
					*(_WORD*)v9 = v10;
					v10 = *(_WORD*)&v9[v11 + 2];
					v9 += 2;
					--len;
				} while (v10);
			}
		} else{
			while (*cur){
				--a2;
				++cur;
				if (a2 <= 1)
					goto LABEL_9;
			}
		}
	}
	TLS_cutr_str(len);
	*(_WORD*)v9 = 0;
}
void __fastcall tree_stuff02(wchar_t* src, __int64 a2, int a3){
	unsigned __int64 len; // rax

	if (src){
		len = -1ui64;
		do
			++len;
		while (src[len]);

		tree_stuff01(src, a2, 1 - a2 + len, a3);
	} else{
		str_setz(a3);
	}
}
void __fastcall set_env_vars(__int64 a1, __int64 a2, __int64 a3, __int64 a4, __int64 a5){
	int v5; // eax
	int v6; // eax
	wchar_t* v7; // rcx
	wchar_t* CommandLineW; // rax
	int v10; // eax
	wchar_t* v11; // rcx
	__int64 v12; // rax
	int v13; // eax
	strNode* v14; // rax
	__int64 v15; // [rsp+0h] [rbp-98h]
	int v16; // [rsp+8h] [rbp-90h]
	int v17; // [rsp+8h] [rbp-90h]
	int v18; // [rsp+18h] [rbp-80h]
	WCHAR* v19; // [rsp+18h] [rbp-80h]
	int v20; // [rsp+18h] [rbp-80h]
	wchar_t* v21; // [rsp+18h] [rbp-80h]
	int v22; // [rsp+18h] [rbp-80h]
	wchar_t* v23; // [rsp+18h] [rbp-80h]
	__int64 v24; // [rsp+48h] [rbp-50h]
	__int16 v25; // [rsp+50h] [rbp-48h]
	wchar_t* v26; // [rsp+58h] [rbp-40h] BYREF
	WCHAR* v27; // [rsp+60h] [rbp-38h] BYREF
	wchar_t* v28; // [rsp+68h] [rbp-30h] BYREF
	wchar_t* v29; // [rsp+70h] [rbp-28h] BYREF
	__int64 v30; // [rsp+78h] [rbp-20h]
	__int64 v31; // [rsp+80h] [rbp-18h]
	WCHAR* v32; // [rsp+88h] [rbp-10h] BYREF

	init_RSO();
	SET_TLS_2(a5);
	g_DATA.g_cursor = (_QWORD*)(g_salt + 0x4C);
	v24 = 0i64;
	do{
		if (v24 > 6)
			break;
		v25 = *((char*)g_DATA.g_cursor)++;
		v18 = GET_TLS_StrLen();
		v5 = GET_TLS_StrLen();
		add_to_STR_tree_CHAR(-v25, v5);
		dup_from_STR_tree((LPVOID*)&v26, v18);
		v19 = v27;
		v6 = GET_TLS_StrLen();
		v7 = v19;
		LODWORD(v19) = v6;
		add_to_STR_treeR(v7);
		add_to_STR_treeR(v26);
		dup_from_STR_tree((LPVOID*)&v27, (int)v19);
	} while (!__OFADD__(1i64, v24++));
	v20 = GET_TLS_StrLen();
	v16 = GET_TLS_StrLen();

	CommandLineW = GetCommandLineW();
	add_to_STR_tree_AT(CommandLineW, v16);
	dup_from_STR_tree((LPVOID*)&v28, v20);
	v21 = v28;
	v10 = GET_TLS_StrLen();
	v11 = v21;
	LODWORD(v21) = v10;
	add_to_STR_treeR(v11);
	dup_from_STR_tree((LPVOID*)&v29, (int)v21);
	PathRemoveArgsW(v29);
	v30 = v12;
	v31 = mywstrlen(v29);
	if (v31 > 0){
		v22 = GET_TLS_StrLen();
		add_to_STR_treeR(L" ");
		GET_TLS_StrLen();
		GET_TLS_StrLen();
		GET_TLS_StrLen();
		v13 = GET_TLS_StrLen();
		tree_stuff02(v28, v31 + 1, v13);
		v14 = STR_tree_root();
		mywstrcpy_space((wchar_t*)((char*)v14 + v15), v17);
		dup_from_STR_tree((LPVOID*)&v32, v22);
	}
	MySetEnvironmentVariableW(v27, v32);
	v23 = v32;
	GET_TLS_StrLen();
	add_to_STR_treeR(v23);
	STR_tree_root_0();
	HeapFree__0(v29);
	HeapFree__0(v26);
	HeapFree__0(v28);
	HeapFree__0(v27);
	HeapFree__0(v32);
}
char* __fastcall myset_env_vars(__int64 a1, __int64 a2, __int64 a3, __int64 a4, __int64 a5){
	int v5; // eax
	__int64 v6; // rcx
	int v7; // eax
	__int64 v8; // rcx
	__int64 v9; // rax
	__int64 v10; // rdx
	__int64 v11; // r8
	__int64 v12; // r9
	int v13; // eax
	wchar_t* v14; // rcx
	int v15; // eax
	wchar_t* v16; // rcx
	__int64 v18; // [rsp-38h] [rbp-58h]
	int v19; // [rsp-30h] [rbp-50h]
	__int64 v20; // [rsp-30h] [rbp-50h]
	WCHAR* v21; // [rsp-30h] [rbp-50h]
	int v22; // [rsp-30h] [rbp-50h]
	WCHAR* v23; // [rsp-30h] [rbp-50h]
	wchar_t* v24; // [rsp-30h] [rbp-50h]
	char* v25; // [rsp-30h] [rbp-50h]
	WCHAR* v26; // [rsp+0h] [rbp-20h] BYREF
	void* v27[3]; // [rsp+8h] [rbp-18h] BYREF

	v27[1] = 0i64;
	v27[0] = 0i64;
	v26 = 0i64;
	init_RSO();
	SET_TLS_2(a5);
	v19 = GET_TLS_StrLen();
	v5 = GET_TLS_StrLen();
	MyGetModuleFileNameW(v5);
	dup_from_STR_tree((LPVOID*)&v26, v19);
	PathQuoteSpacesW(v26);
	if (a1 <= 0){
		v23 = v26;
		v15 = GET_TLS_StrLen();
		v16 = v23;
		v22 = v15;
		add_to_STR_treeR(v16);
	} else{
		v20 = v6;
		v7 = GET_TLS_StrLen();
		v8 = v20;
		LODWORD(v20) = v7;
		v18 = v8;
		v9 = GET_TLS_StrLen();
		set_env_vars(v18, v10, v11, v12, v9);
		dup_from_STR_tree(v27, v20);
		v21 = v26;
		v13 = GET_TLS_StrLen();
		v14 = v21;
		v22 = v13;
		add_to_STR_treeR(v14);
		add_to_STR_treeR(L" ");
		add_to_STR_treeR((wchar_t*)v27[0]);
	}
	dup_from_STR_tree(v27, v22);
	v24 = (wchar_t*)v27[0];
	GET_TLS_StrLen();
	add_to_STR_treeR(v24);
	v25 = (char*)v24 + STR_tree_root_0();
	HeapFree__0(v26);
	HeapFree__0(v27[0]);
	return v25;
}
CHAR* __fastcall MyWideCharToMultiByte(UINT CodePage, LPCWCH lpWideCharStr, int* aOutLen){
	int StrLen; // eax
	CHAR* result; // rax
	CHAR* result_1; // rbx

	StrLen = WideCharToMultiByte(CodePage, 0, lpWideCharStr, 0xFFFFFFFF, 0i64, 0, 0i64, 0i64);
	*(_QWORD*)aOutLen = StrLen;
	if (!StrLen)
		return 0i64;
	result = (CHAR*)HeapAlloc(g_DATA.g_hHeap, 0, StrLen + 1i64);
	result_1 = result;
	if (!result)
		return result;
	WideCharToMultiByte(CodePage, 0, lpWideCharStr, 0xFFFFFFFF, result, *aOutLen, 0i64, 0i64);
	--* (_QWORD*)aOutLen;
	return result_1;
}
__int64 __fastcall MyWriteFileText_UTF8(file_holder* afile_holder, WCHAR* aBuffer, int a3){
	__int64 anw; // rax
	bool isend; // zf
	UINT codepage; // ecx
	CHAR* Buffer; // rax
	CHAR* Buffer_1; // rdi
	DWORD NumberOfBytesWritten; // [rsp+48h] [rbp+10h] BYREF
	QWORD nNumberOfBytesToWrite=0; // [rsp+58h] [rbp+20h] BYREF

	NumberOfBytesWritten = 0;

	if (!aBuffer || !*aBuffer)
		return (int)NumberOfBytesWritten;

	if (a3 != 0x19){
		codepage = 0;
		if (a3 == 2)
			codepage = _MB_CP_UTF8;
		Buffer = MyWideCharToMultiByte(codepage, aBuffer, (int*)&nNumberOfBytesToWrite);
		Buffer_1 = Buffer;
		if (!Buffer)
			return (int)NumberOfBytesWritten;
		if (afile_holder->lpBuffer)
			NumberOfBytesWritten = MyWriteFile2(afile_holder, Buffer, nNumberOfBytesToWrite);
		else
			WriteFile(afile_holder->handle, Buffer, nNumberOfBytesToWrite, &NumberOfBytesWritten, 0i64);
		HeapFree(g_DATA.g_hHeap, 0, Buffer_1);
		return (int)NumberOfBytesWritten;
	}

	anw = -1i64;
	if (afile_holder->lpBuffer){
		do
			isend = aBuffer[++anw] == 0;
		while (!isend);
		return (int)MyWriteFile2(afile_holder, aBuffer, 2 * (int)anw);
	} else{
		do
			isend = aBuffer[++anw] == 0;
		while (!isend);
		WriteFile(afile_holder->handle, aBuffer, 2 * anw, &NumberOfBytesWritten, 0i64);
		return (int)NumberOfBytesWritten;
	}
}
file_holder* __fastcall MyWriteFileText_UTF8_AT(__int64 aAT, WCHAR* aBuffer){
	file_holder* fileholder; // rax

	fileholder = (file_holder*)stru60_get_at(g_stru_0x60_10, aAT);
	if (fileholder)
		return (file_holder*)MyWriteFileText_UTF8(fileholder, aBuffer, fileholder->dwCreationDisposition);
	return fileholder;
}
file_holder* __fastcall CreateFileW_CREATE_ALWAYS(__int64 aAT, const WCHAR* lpFN, int aFlags){
	return CreateFileW_0(aAT, lpFN, 3, aFlags);
}
void __fastcall MyWriteFileText(wchar_t* aFileName, wchar_t* aBuffer){
	WCHAR* FileName; // [rsp+0h] [rbp-30h] BYREF
	WCHAR* Buffer; // [rsp+8h] [rbp-28h] BYREF
	HANDLE* h; // [rsp+10h] [rbp-20h]
	__int64 v5; // [rsp+18h] [rbp-18h]
	__int64 v6; // [rsp+20h] [rbp-10h]

	v6 = 0i64;
	v5 = 0i64;
	h = 0i64;
	Buffer = 0i64;
	FileName = 0i64;
	wstrdup_10((LPVOID*)&FileName, aFileName);
	wstrdup_10((LPVOID*)&Buffer, aBuffer);
	h = (HANDLE*)CreateFileW_CREATE_ALWAYS(-1i64, FileName, 0x18);
	if (h){
		v5 = (__int64)MyWriteFileText_UTF8_AT((__int64)h, Buffer);
		fn_free_obj_0x60_0((__int64)h);
	}
	if (!mywstrlen(Buffer))
		v5 = 1i64;
	HeapFree__0(FileName);
	HeapFree__0(Buffer);
}
void __fastcall my_wcsn_cmpcpy2(wchar_t* String, wchar_t* Block, wchar_t* a3, char a4, int a5, int a6, int a7){
	wchar_t* v7; // rdi
	int v8; // ebp
	wchar_t* v9; // rbx
	wchar_t* v10; // r14
	int(__cdecl * P_wcsnicmp)(const wchar_t*, const wchar_t*, size_t); // r12
	int v12; // eax
	__int64 v13; // rsi
	__int64 v14; // r15
	__int64 v15; // r13
	wchar_t* v16; // rdi
	wchar_t* v17; // rsi
	const wchar_t* v18; // rbx
	wchar_t i; // ax
	__int64 v20; // rdi
	wchar_t* v21; // rbx
	char* v22; // rax
	wchar_t* v23; // rdi
	wchar_t* v24; // rax
	signed __int64 v25; // rdi
	wchar_t v26; // cx
	const wchar_t* v27; // rsi
	__int64 v28; // rcx
	wchar_t v29; // ax
	__int64 v30; // r12
	wchar_t v31; // ax
	wchar_t* Source; // [rsp+20h] [rbp-68h]
	int(__cdecl * P_wcsnicmp_1)(const wchar_t*, const wchar_t*, size_t); // [rsp+28h] [rbp-60h]
	wchar_t* v34; // [rsp+30h] [rbp-58h]
	int v35; // [rsp+90h] [rbp+8h]
	int v36; // [rsp+98h] [rbp+10h]
	int v37; // [rsp+A0h] [rbp+18h]
	int v38; // [rsp+A8h] [rbp+20h]
	int v39; // [rsp+B0h] [rbp+28h]

	v7 = (wchar_t*)&nullstr;
	v8 = 0;
	v9 = (wchar_t*)&nullstr;
	v10 = (wchar_t*)&nullstr;
	if (String)
		v9 = String;
	if (Block)
		v10 = Block;
	P_wcsnicmp = wcsncmp;
	if (a3)
		v7 = a3;
	v38 = a4 & 1;
	v34 = v9;
	if ((a4 & 1) != 0)
		P_wcsnicmp = wcsnicmp;
	v12 = a5;
	Source = v7;
	P_wcsnicmp_1 = P_wcsnicmp;
	if (a5 <= 0)
		v12 = 1;
	v13 = -1i64;
	v14 = -1i64;
	v39 = v12;
	do
		++v14;
	while (v10[v14]);
	v15 = -1i64;
	do
		++v15;
	while (v7[v15]);
	if ((a4 & 2) != 0){
		if (!(_DWORD)v14)
			return;
		if (!a6)
			return;
		v16 = &v9[v12 - 1];
		v17 = v16;
		while (*v17){
			if (a6 != -1 && a6 <= v8)
				break;
			if (P_wcsnicmp(v16, v10, (int)v14)){
				++v16;
				++v17;
			} else{
				wcsncpy(v16, Source, (int)v15);
				v16 += (int)v15;
				v17 += (int)v14;
				++v8;
			}
		}
		return;
	}
	v35 = GET_STR_IN_tree(v9);
	if (v35){
		v9 = wcsdup(v9);
		v34 = v9;
	}
	v36 = GET_STR_IN_tree(v10);
	if (v36)
		v10 = wcsdup(v10);
	v37 = GET_STR_IN_tree(v7);
	if (v37)
		Source = wcsdup(v7);
	v18 = &v9[v39 - 1];
	if (a6){
		for (i = *v18; *v18; i = *v18){
			if (v38){
				v20 = (int)v14;
				if (P_wcsnicmp(v18, v10, (int)v14))
					goto LABEL_37;
			} else if (i != *v10 || (v20 = (int)v14, P_wcsnicmp(v18, v10, (int)v14))){
LABEL_37:
				++v18;
				continue;
			}
			++v8;
			v18 += v20;
			if (a6 != -1 && a6 <= v8)
				break;
		}
	}
	v21 = v34;
	do
		++v13;
	while (v34[v13]);
	v22 = alloc_to_STR_tree((int)v13 + v8 * ((int)v15 - (int)v14), a7);
	v23 = (wchar_t*)v22;
	if (!v8){
		v24 = v34;
		v25 = (char*)v23 - (char*)v34;
		do{
			v26 = *v24++;
			*(wchar_t*)((char*)v24 + v25 - 2) = v26;
		} while (v26);
		goto LABEL_60;
	}
	v27 = v34;
	if (v39 > 1){
		wcsncpy((wchar_t*)v22, v34, v39);
		v28 = v39 - 1;
		v23 += v28;
		v27 = &v34[v28];
	}
	v29 = *v27;
	if (*v27){
		while (1){
			if (v8 > 0){
				if (v38){
					v30 = (int)v14;
					if (!P_wcsnicmp_1(v27, v10, (int)v14))
						goto LABEL_68;
				} else if (v29 == *v10){
					v30 = (int)v14;
					if (!P_wcsnicmp_1(v27, v10, (int)v14)){
LABEL_68:
						wcsncpy(v23, Source, (int)v15);
						v23 += (int)v15;
						v27 += v30;
						--v8;
						goto LABEL_57;
					}
				}
			}
			v31 = *v27;
			++v23;
			++v27;
			*(v23 - 1) = v31;
LABEL_57:
			v29 = *v27;
			if (!*v27){
				v21 = v34;
				break;
			}
		}
	}
	*v23 = 0;
LABEL_60:
	if (v35)
		free(v21);
	if (v36)
		free(v10);
	if (v37)
		free(Source);
}
void __fastcall my_wcsn_cmpcpy(wchar_t* a1, wchar_t* a2, wchar_t* a3, int a4){
	my_wcsn_cmpcpy2(a1, a2, a3, 0, 0, -1, a4);
}
_BYTE* __fastcall calc_size(char* a1, __int64 aSize){
	char v3; // [rsp+0h] [rbp-28h]
	__int64 v4; // [rsp+8h] [rbp-20h]
	char* v5; // [rsp+30h] [rbp+8h]

	v5 = a1;
	v4 = 0i64;
	while (*v5 && v4 < aSize){
		v3 = *v5;
		if ((*v5 & 0x80) != 0){
			if ((v3 & 0xE0) == 0xC0){
				if ((*++v5 & 0xC0) == 0x80){
					++v5;
					++v4;
				}
			} else if ((v3 & 0xF0) == 0xE0 && v5[1]){
				if ((v5[1] & 0xC0) == 0x80 && (v5[2] & 0xC0) == 0x80){
					v5 += 3;
					++v4;
				} else if ((v5[1] & 0xC0) == 0x80){
					v5 += 2;
				} else{
					++v5;
				}
			} else if ((v3 & 0xF8) == 0xF0 && v5[1] && v5[2]){
				if ((v5[1] & 0xC0) == 0x80 && (v5[2] & 0xC0) == 0x80 && (v5[3] & 0xC0) == 0x80){
					v5 += 4;
					++v4;
				} else if ((v5[1] & 0xC0) == 0x80 && (v5[2] & 0xC0) == 0x80){
					v5 += 3;
				} else if ((v5[1] & 0xC0) == 0x80){
					v5 += 2;
				} else{
					++v5;
				}
			} else{
				++v5;
			}
		} else{
			++v5;
			++v4;
		}
	}
	return (_BYTE*)(v5 - a1);
}
int __fastcall myMultiByteToWideCharEx(char* lpMultiByteStr, signed __int64 aSize, char a3, int aPos){
	signed __int64 size; // rbx
	int v5; // eax
	char* v8; // rax
	_WORD* v9; // rdi
	char* v10; // r14
	__int16 v11; // ax
	int result; // eax
	UINT v13; // ebp
	__int64 v14; // rbx
	signed __int64 v15; // rax
	int v16; // edi
	char* lpWideCharStr; // rsi

	size = aSize;
	v5 = a3 & 0x1F;
	if (aSize < -1)
		size = 0i64;
	if (v5 != 0x19){
		if (v5 == 2){
			v13 = _MB_CP_UTF8;
			if (size == -1)
				goto LABEL_18;
			if ((a3 & 0x40) == 0)
				size = (signed __int64)calc_size(lpMultiByteStr, size);
		} else{
			v13 = 0;
		}
		if (size != -1){
			v15 = 0i64;
			if (*lpMultiByteStr){
				do{
					if (v15 >= size)
						break;
					++v15;
				} while (lpMultiByteStr[v15]);
			}
			//LODWORD(v14) = v15;
			v14 = v15;
			goto LABEL_25;
		}
LABEL_18:
		v14 = -1i64;
		do
			++v14;
		while (lpMultiByteStr[v14]);
LABEL_25:
		v16 = MultiByteToWideChar(v13, 0, lpMultiByteStr, v14, 0i64, 0);
		lpWideCharStr = alloc_to_STR_tree(v16, aPos);
		result = MultiByteToWideChar(v13, 0, lpMultiByteStr, v14, (LPWSTR)lpWideCharStr, v16 + 1);
		*(_WORD*)&lpWideCharStr[2 * result] = 0;
		return result;
	}
	if (size == -1){
		do
			++size;
		while (*(_WORD*)&lpMultiByteStr[2 * size]);
	}
	v8 = alloc_to_STR_tree(size, aPos);
	v9 = v8;
	if (lpMultiByteStr){
		if (size){
			v10 = (char*)(lpMultiByteStr - v8);
			do{
				v11 = *(_WORD*)((char*)v9 + (_QWORD)v10);
				if (!v11)
					break;
				*v9++ = v11;
				--size;
			} while (size);
		}
	}
	result = TLS_cutr_str(size);
	*v9 = 0;
	return result;
}
char* str_tree_end(){
	strNode* Value; // rcx

	Value = (strNode*)TlsGetValue(g_dwTlsIndex);
	return &Value->str[Value->slen];
}

char* uncrypt_writefile(wchar_t* a1, __int64 a2, __int64 a5){
	int v3; // eax
	char* v4; // rax
	int v6; // [rsp-30h] [rbp-60h]
	wchar_t* v7; // [rsp-30h] [rbp-60h]
	char* v8; // [rsp-30h] [rbp-60h]
	WCHAR* v9; // [rsp+0h] [rbp-30h] BYREF
	HRSRC ResourceW; // [rsp+8h] [rbp-28h]
	char* Resource; // [rsp+10h] [rbp-20h]
	void* v12[3]; // [rsp+18h] [rbp-18h] BYREF

	v12[1] = 0i64;
	v12[0] = 0i64;
	Resource = 0i64;
	ResourceW = 0i64;
	v9 = 0i64;
	init_RSO();
	SET_TLS_2(a5);
	wstrdup_10((LPVOID*)&v9, a1);
	ResourceW = FindResourceW(g_DATA.g_module0handle, v9, (LPCWSTR)RT_RCDATA);
	if (!ResourceW)
		goto LABEL_5;
	Resource = Alloc_LoadResource(g_DATA.g_module0handle, ResourceW);
	g_DATA.g_sizeofres = HeapSize__0(Resource);
	xorfn(Resource, g_DATA.g_sizeofres, (wchar_t*)g_DATA.field_78);
	if (a2 != 1){
		v6 = GET_TLS_StrLen();
		v3 = GET_TLS_StrLen();
		myMultiByteToWideCharEx(Resource, g_DATA.g_sizeofres, 2, v3);
		dup_from_STR_tree(v12, v6);
		ZHeapFree(Resource);
LABEL_5:
		v7 = (wchar_t*)v12[0];
		GET_TLS_StrLen();
		add_to_STR_treeR(v7);
		v4 = (char*)v7 + STR_tree_root_0();
		goto LABEL_6;
	}
	MyWriteFile5(g_DATA.g_temp_fn100, Resource, g_DATA.g_sizeofres);
	ZHeapFree(Resource);
	v4 = str_tree_end();
	*(_WORD*)v4 = 0;
LABEL_6:
	v8 = v4;
	HeapFree__0(v9);
	HeapFree__0(v12[0]);
	return v8;
}
__int64 act_MyWriteFileText_path(){
	int v0      ; // eax
	int v1      ; // eax
	wchar_t* v2 ; // rcx
	int v4      ; // eax
	strNode* v5 ; // rax
	int v6      ; // eax
	strNode* v7 ; // rax
	int v8      ; // eax
	strNode* v9 ; // rax
	int v10     ; // eax
	strNode* v11; // rax
	int v12     ; // eax
	strNode* v13; // rax
	__int64 v14 ; // rax
	__int64 v15 ; // rax
	__int64 v16 ; // rax
	__int64 v17 ; // rax
	__int64 v18 ; // rax
	__int64 v19 ; // rax
	strNode* v20; // rax
	__int64 v21 ; // rax
	strNode* v22=0; // rax
	strNode* v23=0; // rax
	wchar_t* v25=0; // [rsp-10h] [rbp-C8h]
	wchar_t* v26=0; // [rsp-10h] [rbp-C8h]
	wchar_t* v27=0; // [rsp-8h] [rbp-C0h]
	wchar_t* v28=0; // [rsp-8h] [rbp-C0h]
	__int64 v29 ; // [rsp+0h] [rbp-B8h]
	__int64 v30 ; // [rsp+0h] [rbp-B8h]
	__int64 v31 ; // [rsp+0h] [rbp-B8h]
	__int64 v32 ; // [rsp+0h] [rbp-B8h]
	__int64 v33 ; // [rsp+0h] [rbp-B8h]
	__int64 v34 ; // [rsp+0h] [rbp-B8h]
	__int64 v35 ; // [rsp+0h] [rbp-B8h]
	wchar_t* v36=0; // [rsp+0h] [rbp-B8h]
	int v37     ; // [rsp+8h] [rbp-B0h]
	int v38     ; // [rsp+8h] [rbp-B0h]
	int v39     ; // [rsp+8h] [rbp-B0h]
	int v40     ; // [rsp+8h] [rbp-B0h]
	int v41     ; // [rsp+8h] [rbp-B0h]
	int v42     ; // [rsp+8h] [rbp-B0h]
	int v43     ; // [rsp+8h] [rbp-B0h]
	wchar_t* v44=0; // [rsp+8h] [rbp-B0h]
	__int64 v45 ; // [rsp+8h] [rbp-B0h]
	int v46     ; // [rsp+18h] [rbp-A0h]
	wchar_t* v47=0; // [rsp+18h] [rbp-A0h]
	int v48     ; // [rsp+18h] [rbp-A0h]
	int v49     ; // [rsp+18h] [rbp-A0h]
	int v50     ; // [rsp+18h] [rbp-A0h]
	int v51     ; // [rsp+18h] [rbp-A0h]
	int v52     ; // [rsp+18h] [rbp-A0h]
	QWORD v53   ; // [rsp+18h] [rbp-A0h]
	int v54     ; // [rsp+18h] [rbp-A0h]
	int v55     ; // [rsp+18h] [rbp-A0h]
	__int64 v56 ; // [rsp+18h] [rbp-A0h]
	__int64 v57 ; // [rsp+48h] [rbp-70h]
	__int16 v58 ; // [rsp+50h] [rbp-68h]
	wchar_t* v59=0; // [rsp+58h] [rbp-60h] BYREF
	wchar_t* v60=0; // [rsp+60h] [rbp-58h] BYREF
	WCHAR* v61  =0; // [rsp+68h] [rbp-50h] BYREF
	wchar_t* v62=0; // [rsp+70h] [rbp-48h] BYREF
	WCHAR* v63  =0; // [rsp+78h] [rbp-40h] BYREF
	WCHAR* v64  =0; // [rsp+80h] [rbp-38h] BYREF
	wchar_t* v65=0; // [rsp+88h] [rbp-30h] BYREF
	wchar_t* v66=0; // [rsp+90h] [rbp-28h] BYREF
	wchar_t* v67=0; // [rsp+98h] [rbp-20h] BYREF
	wchar_t* v68=0; // [rsp+A0h] [rbp-18h] BYREF

	init_RSO();

	// @shift / 0
	g_DATA.g_cursor = (_QWORD*)(g_salt + 0xD);
	v57 = 0i64;
	do{
		if (v57 > 8)
			break;
		v58 = *((char*)g_DATA.g_cursor)++;
		v46 = GET_TLS_StrLen();
		v0 = GET_TLS_StrLen();
		add_to_STR_tree_CHAR(-v58, v0);
		dup_from_STR_tree((LPVOID*)&v59, v46);
		v47 = v60;
		v1 = GET_TLS_StrLen();
		v2 = v47;
		LODWORD(v47) = v1;
		add_to_STR_treeR(v2);
		add_to_STR_treeR(v59);
		dup_from_STR_tree((LPVOID*)&v60, (int)v47);
	} while (!__OFADD__(1i64, v57++));

	v48 = GET_TLS_StrLen();
	GET_TLS_StrLen();
	GET_TLS_StrLen();
	v4 = GET_TLS_StrLen();
	MD_stuff((const WCHAR*)g_DATA.field_78, 1, v4);
	v5 = STR_tree_root();
	//MyCharUpperW((wchar_t*)((char*)v5 + v29), v37);
	MyCharUpperW((wchar_t*)((char*)v5 + v4), v4);
	dup_from_STR_tree((LPVOID*)&v61, v48);//9E427811E6D84EEDB2B2CA37BBB0A5CA

	v49 = GET_TLS_StrLen();
	GET_TLS_StrLen();
	GET_TLS_StrLen();
	v6 = GET_TLS_StrLen();
	MD_stuff((const WCHAR*)g_DATA.field_78, 3, v6);
	v7 = STR_tree_root();
	//MyCharUpperW((wchar_t*)((char*)v7 + v30), v38);
	MyCharUpperW((wchar_t*)((char*)v7 + v6), v6);
	dup_from_STR_tree((LPVOID*)&v62, v49); //6B2FE1154CE4BE0B9DC9A4294C2DE77C4CAED943

	v50 = GET_TLS_StrLen();
	GET_TLS_StrLen();
	GET_TLS_StrLen();
	v8 = GET_TLS_StrLen();
	MD_stuff(v61, 3, v8);
	v9 = STR_tree_root();
	//MyCharUpperW((wchar_t*)((char*)v9 + v31), v39);
	MyCharUpperW((wchar_t*)((char*)v9 + v8), v8);
	dup_from_STR_tree((LPVOID*)&v63, v50);//F21F10D7F0BC3CBB2D90CD79842A4D1B4F0DBAC4

	v51 = GET_TLS_StrLen();
	GET_TLS_StrLen();
	GET_TLS_StrLen();
	v10 = GET_TLS_StrLen();
	MD_stuff(v63, 3, v10);
	v11 = STR_tree_root();
	//MyCharUpperW((wchar_t*)((char*)v11 + v32), v40);
	MyCharUpperW((wchar_t*)((char*)v11 + v10), v10);
	dup_from_STR_tree((LPVOID*)&v64, v51);//4787DB144882FB4ECDE07B3FD82AC9A9288280FD

	v52 = GET_TLS_StrLen();
	GET_TLS_StrLen();
	GET_TLS_StrLen();
	v12 = GET_TLS_StrLen();
	MD_stuff(v64, 3, v12);
	v13 = STR_tree_root();
	//MyCharUpperW((wchar_t*)((char*)v13 + v33), v41);
	MyCharUpperW((wchar_t*)((char*)v13 + v12), v12);
	dup_from_STR_tree((LPVOID*)&v65, v52);//85BA1754AC5027C50052796D48026F48831A6C5E

	v53 = GET_TLS_StrLen();
	v14 = GET_TLS_StrLen();
	uncrypt_writefile(v65, 1i64, v14);
	SET_TLS_2(v53);
	//LODWORD(v53) = GET_TLS_StrLen();
	v53 = GET_TLS_StrLen();
	v15 = GET_TLS_StrLen();
	uncrypt_writefile(v62, 0i64, v15);
	dup_from_STR_tree((LPVOID*)&g_DATA.field_A0, v53);
	//LODWORD(v53) = GET_TLS_StrLen();
	v53 = GET_TLS_StrLen();
	v16 = GET_TLS_StrLen();
	uncrypt_writefile(v63, 0i64, v16);
	dup_from_STR_tree((LPVOID*)&v66, v53);
	//LODWORD(v53) = GET_TLS_StrLen();
	v53 = GET_TLS_StrLen();
	v17 = GET_TLS_StrLen();
	uncrypt_writefile(v64, 0i64, v17);
	dup_from_STR_tree((LPVOID*)&v67, v53);
	//LODWORD(v53) = GET_TLS_StrLen();
	v53 = GET_TLS_StrLen();
	v18 = GET_TLS_StrLen();
	uncrypt_writefile(v61, 0i64, v18);
	dup_from_STR_tree((LPVOID*)&v68, v53);
	GET_TLS_StrLen();
	GET_TLS_StrLen();
	GET_TLS_StrLen();
	v19 = GET_TLS_StrLen();
	str_get_lpszShortPath((wchar_t*)g_DATA.g_temp_fn04, v19);
	add2_to_StrTreeLen();
	v20 = STR_tree_root();
	// v25=v66, v27="**", v34=v19, v42 = v19
	//my_wcsn_cmpcpy(v25, v27, (wchar_t*)((char*)v20 + v34), v42);
	my_wcsn_cmpcpy(v66, L"**", (wchar_t*)((char*)v20 + v19), v19);
	// v54=v19
	dup_from_STR_tree((LPVOID*)&v66, v19);
	GET_TLS_StrLen();
	GET_TLS_StrLen();
	GET_TLS_StrLen();
	v21 = GET_TLS_StrLen();
	str_get_lpszShortPath(g_DATA.g_temp_fn100, v21);
	add2_to_StrTreeLen();
	v22 = STR_tree_root();
	// //v26=v66, v28="*"
	//my_wcsn_cmpcpy(v26, v28, (wchar_t*)((char*)v22 + v35), v43);
	my_wcsn_cmpcpy(v66, L"*", (wchar_t*)((char*)v22 + v21), v21);
	// v55=v21
	dup_from_STR_tree((LPVOID*)&v66, v21);
	GET_TLS_StrLen();
	v44 = v60;
	//GET_TLS_StrLen();
	v56 = GET_TLS_StrLen();
	add_to_STR_treeR(v44);
	add_to_STR_treeR(NL);
	add_to_STR_treeR(v66);
	add_to_STR_treeR(v68);
	add_to_STR_treeR(v67);
	add2_to_StrTreeLen();
	v23 = STR_tree_root();
	// v36=g_DATA.g_temp_fn03, v45=GET_TLS_StrLen()
	//MyWriteFileText(v36, (wchar_t*)((char*)v23 + v45));
	MyWriteFileText(g_DATA.g_temp_fn03, (wchar_t*)((char*)v23 + v56));
	// v56=GET_TLS_StrLen()
	SET_TLS_2(v56);
	HeapFree__0(v61);
	HeapFree__0(v60);
	HeapFree__0(v64);
	HeapFree__0(v65);
	HeapFree__0(v67);
	HeapFree__0(v63);
	HeapFree__0(v68);
	HeapFree__0(v62);
	HeapFree__0(v59);
	HeapFree__0(v66);
	return 0i64;
}
__int64 __fastcall setPTRS(__int16* a1){
	g_DATA.field_B8 = ptr(a1 + 3);
	g_DATA.field_48 = ptr(a1 + 4);
	g_DATA.field_80 = ptr(a1 + 5);
	g_DATA.field_F0 = ptr(a1 + 6);
	g_DATA.field_E0 = ptr(a1 + 7);
	return 0i64;
}
void sub_14000593C(){
	int v0;
	int v1;
	wchar_t* v2;
	bool v3;
	int v4;
	int v5;
	wchar_t* v6;
	int v7;
	int v8;
	wchar_t* v9;
	int v10;
	int v11;
	wchar_t* v12;
	int v13;
	int v14;
	wchar_t* v15;
	int v16;
	int v17;
	wchar_t* v18;
	int v19;
	int v20;
	wchar_t* v21;
	int v22;
	int v23;
	wchar_t* v24;
	int v25;
	int v26;
	wchar_t* v27;
	int v28;
	wchar_t* v29;
	__int64 v30;
	__int64 v31;
	__int64 v32;
	int v33;
	strNode* v34;
	int v35;
	strNode* v36;
	__int64 v37;
	__int64 v38;
	__int64 v39;
	__int64 v40;
	__int64 v41;
	__int64 v42;
	__int64 v43;
	__int64 v44;
	__int64 v45;
	__int64 v46;
	__int64 v47;
	strNode* v48;
	int v49;
	wchar_t* v50;
	__int64 v51;
	__int64 v52;
	__int64 v53;
	__int64 v54;
	int v55;
	wchar_t* v56;
	int v57;
	wchar_t* v58;
	int v59;
	strNode* v60;
	void* v61;
	__int64 v62;
	wchar_t* v63;
	wchar_t* v64;
	__int64 v65;
	__int64 v66;
	const WCHAR* v67;
	wchar_t* v68;
	int v69;
	int v70;
	wchar_t* v71;
	__int64 v72;
	wchar_t* v73;
	__int64 v74;
	__int64 v75;
	int v76;
	wchar_t* v77;
	int v78;
	wchar_t* v79;
	int v80;
	wchar_t* v81;
	int v82;
	wchar_t* v83;
	int v84;
	wchar_t* v85;
	int v86;
	__int64 v87;
	int v88;
	__int64 v89;
	int v90;
	__int64 v91;
	int v92;
	wchar_t* g_temp_fn100;
	wchar_t* v94;
	QWORD v95;
	__int64 v96;
	__int64 g_temp_fn02;
	__int64 g_temp_fn03;
	wchar_t* v99;
	__int64 v100;
	void* v101;
	__int64 v102;
	__int64 v103;
	__int64 v104;
	__int64 v105;
	__int64 v106;
	__int64 v107;
	__int64 v108;
	__int64 v109;
	__int64 v110;
	__int16 v111;
	__int16 v112;
	__int16 v113;
	__int16 v114;
	__int16 v115;
	__int16 v116;
	__int16 v117;
	__int16 v118;
	__int16 v119;
	wchar_t* v120 = 0;
	wchar_t* v121 = 0;
	wchar_t* v122 = 0;
	wchar_t* v123 = 0;
	wchar_t* v124 = 0;
	wchar_t* v125 = 0;
	wchar_t* v126 = 0;
	LPWSTR CommandLine_TLS_8;
	WCHAR* v128 = 0;
	__int16* v129;
	wchar_t* v130=0;
	LPVOID v131[3]={0,0,0};

	init_RSO();
	
	//Select the extraction path
	g_DATA.g_cursor = (_QWORD*)(g_salt + 0x16);
	v102 = 0i64;
	do{
		if (v102 > 25)
			break;
		v111 = *((char*)g_DATA.g_cursor)++;
		v76 = GET_TLS_StrLen();
		v0 = GET_TLS_StrLen();
		add_to_STR_tree_CHAR(-v111, v0);
		dup_from_STR_tree((LPVOID*)&v120, v76);
		v77 = v121;
		v1 = GET_TLS_StrLen();
		v2 = v77;
		LODWORD(v77) = v1;
		add_to_STR_treeR(v2);
		add_to_STR_treeR(v120);
		dup_from_STR_tree((LPVOID*)&v121, (int)v77);
		v3 = __OFADD__(1i64, v102++);
	} while (!v3);

	//cmd
	g_DATA.g_cursor = (_QWORD*)(g_salt + 0x7A);
	v103 = 0i64;
	do{
		if (v103 > 2)
			break;
		v112 = *((char*)g_DATA.g_cursor)++;
		v78 = GET_TLS_StrLen();
		v4 = GET_TLS_StrLen();
		add_to_STR_tree_CHAR(-v112, v4);
		dup_from_STR_tree((LPVOID*)&v120, v78);
		v79 = v122;
		v5 = GET_TLS_StrLen();
		v6 = v79;
		LODWORD(v79) = v5;
		add_to_STR_treeR(v6);
		add_to_STR_treeR(v120);
		dup_from_STR_tree((LPVOID*)&v122, (int)v79);
		v3 = __OFADD__(1i64, v103++);
	} while (!v3);

	//.exe
	g_DATA.g_cursor = (_QWORD*)(g_salt + 0x7F);
	v104 = 0i64;
	do{
		if (v104 > 3)
			break;
		v113 = *((char*)g_DATA.g_cursor)++;
		v80 = GET_TLS_StrLen();
		v7 = GET_TLS_StrLen();
		add_to_STR_tree_CHAR(-v113, v7);
		dup_from_STR_tree((LPVOID*)&v120, v80);
		v81 = v123;
		v8 = GET_TLS_StrLen();
		v9 = v81;
		LODWORD(v81) = v8;
		add_to_STR_treeR(v9);
		add_to_STR_treeR(v120);
		dup_from_STR_tree((LPVOID*)&v123, (int)v81);
		v3 = __OFADD__(1i64, v104++);
	} while (!v3);

	// /c
	g_DATA.g_cursor = (_QWORD*)(g_salt + 0x7D);
	v105 = 0i64;
	do{
		if (v105 > 1)
			break;
		v114 = *((char*)g_DATA.g_cursor)++;
		v82 = GET_TLS_StrLen();
		v10 = GET_TLS_StrLen();
		add_to_STR_tree_CHAR(-v114, v10);
		dup_from_STR_tree((LPVOID*)&v120, v82);
		v83 = v124;
		v11 = GET_TLS_StrLen();
		v12 = v83;
		LODWORD(v83) = v11;
		add_to_STR_treeR(v12);
		add_to_STR_treeR(v120);
		dup_from_STR_tree((LPVOID*)&v124, (int)v83);
		v3 = __OFADD__(1i64, v105++);
	} while (!v3);
	
	
	//b2eincfilepath
	g_DATA.g_cursor = (_QWORD*)(g_salt + 0x53);
	v106 = 0i64;
	do{
		if (v106 > 0xD)
			break;
		v115 = *((char*)g_DATA.g_cursor)++;
		v84 = GET_TLS_StrLen();
		v13 = GET_TLS_StrLen();
		add_to_STR_tree_CHAR(-v115, v13);
		dup_from_STR_tree((LPVOID*)&v120, v84);
		v85 = v125;
		v14 = GET_TLS_StrLen();
		v15 = v85;
		LODWORD(v85) = v14;
		add_to_STR_treeR(v15);
		add_to_STR_treeR(v120);
		dup_from_STR_tree((LPVOID*)&v125, (int)v85);
		v3 = __OFADD__(1i64, v106++);
	} while (!v3);
	
	
	//b2eincfilecount
	g_DATA.g_cursor = (_QWORD*)(g_salt + 0x61);
	v107 = 0i64;
	do{
		if (v107 > 0xE)
			break;
		v116 = *((char*)g_DATA.g_cursor)++;
		v86 = GET_TLS_StrLen();
		v16 = GET_TLS_StrLen();
		add_to_STR_tree_CHAR(-v116, v16);
		dup_from_STR_tree((LPVOID*)&v120, v86);
		v87 = g_DATA.field_58;
		v17 = GET_TLS_StrLen();
		v18 = (wchar_t*)v87;
		LODWORD(v87) = v17;
		add_to_STR_treeR(v18);
		add_to_STR_treeR(v120);
		dup_from_STR_tree((LPVOID*)&g_DATA.field_58, v87);
		v3 = __OFADD__(1i64, v107++);
	} while (!v3);
	
	
	//b2eincfile
	g_DATA.g_cursor = (_QWORD*)(g_salt + 0x70);
	v108 = 0i64;
	do{
		if (v108 > 9)
			break;
		v117 = *((char*)g_DATA.g_cursor)++;
		v88 = GET_TLS_StrLen();
		v19 = GET_TLS_StrLen();
		add_to_STR_tree_CHAR(-v117, v19);
		dup_from_STR_tree((LPVOID*)&v120, v88);
		v89 = g_DATA.field_F8;
		v20 = GET_TLS_StrLen();
		v21 = (wchar_t*)v89;
		LODWORD(v89) = v20;
		add_to_STR_treeR(v21);
		add_to_STR_treeR(v120);
		dup_from_STR_tree((LPVOID*)&g_DATA.field_F8, v89);
		v3 = __OFADD__(1i64, v108++);
	} while (!v3);


	//Error
	g_DATA.g_cursor = (_QWORD*)(g_salt + 8);
	v109 = 0i64;
	do{
		if (v109 > 4)
			break;
		v118 = *((char*)g_DATA.g_cursor)++;
		v90 = GET_TLS_StrLen();
		v22 = GET_TLS_StrLen();
		add_to_STR_tree_CHAR(-v118, v22);
		dup_from_STR_tree((LPVOID*)&v120, v90);
		v91 = g_DATA.field_B0;
		v23 = GET_TLS_StrLen();
		v24 = (wchar_t*)v91;
		LODWORD(v91) = v23;
		add_to_STR_treeR(v24);
		add_to_STR_treeR(v120);
		dup_from_STR_tree((LPVOID*)&g_DATA.field_B0, v91);
		v3 = __OFADD__(1i64, v109++);
	} while (!v3);
	
	
	//extd
	g_DATA.g_cursor = (_QWORD*)(g_salt + 0x87);
	v110 = 0i64;
	do{
		if (v110 > 3)
			break;
		v119 = *((char*)g_DATA.g_cursor)++;
		v92 = GET_TLS_StrLen();
		v25 = GET_TLS_StrLen();
		add_to_STR_tree_CHAR(-v119, v25);
		dup_from_STR_tree((LPVOID*)&v120, v92);
		g_temp_fn100 = g_DATA.g_temp_fn100;
		v26 = GET_TLS_StrLen();
		v27 = g_temp_fn100;
		LODWORD(g_temp_fn100) = v26;
		add_to_STR_treeR(v27);
		add_to_STR_treeR(v120);
		dup_from_STR_tree((LPVOID*)&g_DATA.g_temp_fn100, (int)g_temp_fn100);
		v3 = __OFADD__(1i64, v110++);
	} while (!v3);
	v94 = g_DATA.g_temp_fn100;
	v28 = GET_TLS_StrLen();
	v29 = v94;
	LODWORD(v94) = v28;
	add_to_STR_treeR(v29);
	add_to_STR_treeR(v123);
	dup_from_STR_tree((LPVOID*)&g_DATA.g_temp_fn100, (int)v94);//extd.exe
	LODWORD(v94) = GET_TLS_StrLen();
	v30 = GET_TLS_StrLen();
	//add_SystemDirectory_to_STR_tree(v122, v123, v31, v32, v30);
	add_SystemDirectory_to_STR_tree(v122, v123, 0,0, v30);
	dup_from_STR_tree((LPVOID*)&v126, (int)v94);
	CommandLine_TLS_8 = asm_MyGetCommandLine_TLS_8();
	g_DATA.g_module0handle = GetModuleHandleW(0i64);
	LODWORD(v94) = GET_TLS_StrLen();
	GET_TLS_StrLen();
	GET_TLS_StrLen();
	v33 = GET_TLS_StrLen();
	MD_stuff((const WCHAR*)g_DATA.field_78, 1, v33);
	v34 = STR_tree_root();
	//MyCharUpperW((wchar_t*)((char*)v34 + v65), v69);
	MyCharUpperW((wchar_t*)((char*)v34), v33);
	dup_from_STR_tree((LPVOID*)&v128, (int)v94);
	LODWORD(v94) = GET_TLS_StrLen();
	GET_TLS_StrLen();
	GET_TLS_StrLen();
	v35 = GET_TLS_StrLen();
	MD_stuff(v128, 1, v35);
	v36 = STR_tree_root();
	//MyCharUpperW((wchar_t*)((char*)v36 + v66), v70);
	MyCharUpperW((wchar_t*)((char*)v36), v35);
	dup_from_STR_tree((LPVOID*)&v128, (int)v94);
	v129 = (__int16*)decode(v128);
	v95 = GET_TLS_StrLen();
	v37 = GET_TLS_StrLen();

	//test xorfn
	//HRSRC ResourceW; // [rsp+60h] [rbp-28h]
	//wchar_t* Resource; // [rsp+68h] [rbp-20h]
	//Resource = 0i64;
	//ResourceW = 0i64;
	//v11 = 0i64;
	//init_RSO();
	//SET_TLS_2(0);
	//WCHAR outfn[512] = {0};
	//WCHAR fn[] = L"C64CA6164C688CB47E12DA892F4AB25C";
	//wstrdup_10((LPVOID*)&v11, fn);
	//ResourceW = FindResourceW(g_DATA.g_module0handle, fn, (LPCWSTR)RT_RCDATA);
	//Resource = Alloc_LoadResource(g_DATA.g_module0handle, ResourceW);
	//g_DATA.g_sizeofres = HeapSize__0(Resource);
	//char* b = xorfn((wchar_t*)Resource, g_DATA.g_sizeofres, (wchar_t*)g_DATA.field_78);
	//wstrcpy(outfn,fn,mywstrlen(fn));
	//StrCatW(outfn,L".unp");
	//wchar_t* ff = &outfn[0];
	//HANDLE hFile = CreateFileW(ff, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
	//DWORD nr = 0;
	////WriteFile(hFile, &b[22], g_DATA.g_sizeofres-22, &nr, NULL);
	//WriteFile(hFile, &b[0], g_DATA.g_sizeofres, &nr, NULL);
	//CloseHandle(hFile);
	printf("Do not Execute; or u system wil be destroed by shit in this installer!");
	exit(0);
	
	//sha1 test OK
	//int lll = GET_TLS_StrLen();
	//MD_stuff(L"SHA1-TEST", 3, 0); //410519AD41131491B475B4F891727B68DCF13D18
	//WCHAR *t = 0;	
	//dup_from_STR_tree((LPVOID*)&t, (int)lll);
	//wprintf(L"%s\n",t);

	//g_cursor++ bug
	//__int64* g_cursor=0;
	//printf("g_salt[%d] = %x\n", 0,&g_salt);
	//printf("g_saltE[%d] =%x\n", 0, &g_salt[144]);
	//g_cursor = (_QWORD*)(g_salt + 0);
	//WCHAR buf[20] = {0};
	//char* result = &buf[0];
	//do{
	//	//__int16 ch = *((char*)g_cursor)++;
	//	__int16 ch = *(char*)g_cursor++;
	//	*(_WORD*)result = -ch; 
	//	printf("%s", buf);
	//} while(*g_cursor > &g_salt[144]);
	////printf("g_cursor=%x, %s %2.2x \n", g_cursor, buf, buf[0] & 0xff);
	////printf("%s %2.2x ", buf, buf[0]);
	//exit(0);	

	//MyInputRequester((__int64)v129, v38, v39, v40, v37);
	MyInputRequester((__int64)v129, 0, 0, 0, v37);
	SET_TLS_2(v95);
	create_tmp_paths();
	salt_MyBrowseForFolder(v129);
	//LODWORD(v95) = GET_TLS_StrLen();
	v95 = GET_TLS_StrLen();
	v75 = GET_TLS_StrLen();
	v71 = v121;
	v41 = ptr(v129 + 2);
	//MyBrowseForFolder(v41, v71, v42, v43, v75);
	MyBrowseForFolder(v41, v71, 0, 0, v75);
	dup_from_STR_tree((LPVOID*)&g_DATA.g_path01, v95);
	PathRemoveBackslashW(g_DATA.g_path01);

	setPTRS(v129);

	GET_TLS_StrLen();
	GET_TLS_StrLen();
	v44 = GET_TLS_StrLen();
	//str_get_lpszShortPath(g_DATA.g_path01, v45, v46, v47, v44);
	str_get_lpszShortPath(g_DATA.g_path01, v44);
	add2_to_StrTreeLen();
	v48 = STR_tree_root();
	//MySetEnvironmentVariableW(v67, (const WCHAR*)((char*)v48 + v72));
	MySetEnvironmentVariableW(v125, (const WCHAR*)((char*)v48 + v44));
	//SET_TLS_2(v96);
	SET_TLS_2(v44);
	g_temp_fn02 = g_DATA.g_temp_fn02;
	v49 = GET_TLS_StrLen();
	v50 = (wchar_t*)g_temp_fn02;
	//LODWORD(g_temp_fn02) = v49;
	g_temp_fn02 = v49;
	add_to_STR_treeR(v50);
	add_to_STR_treeR(g_DATA.g_temp_fn100);
	dup_from_STR_tree((LPVOID*)&g_DATA.g_temp_fn100, g_temp_fn02);
	//C:\Users\adm\AppData\Local\Temp\ABDA.tmp\189A.tmp\extd.exe
	
	//LODWORD(g_temp_fn02) = GET_TLS_StrLen();
	g_temp_fn02 = GET_TLS_StrLen();
	v51 = GET_TLS_StrLen();
	//myset_env_vars((__int64)CommandLine_TLS_8, v52, v53, v54, v51);
	myset_env_vars((__int64)CommandLine_TLS_8, 0, 0, 0, v51);
	dup_from_STR_tree((LPVOID*)&v130, g_temp_fn02);
	act_MyWriteFileText_path();
	g_temp_fn03 = g_DATA.g_temp_fn03;
	v55 = GET_TLS_StrLen();
	v56 = (wchar_t*)g_temp_fn03;
	//LODWORD(g_temp_fn03) = v55;
	g_temp_fn03 = v55;
	add_to_STR_treeR(v56);
	dup_from_STR_tree(v131, g_temp_fn03);
	PathQuoteSpacesW((LPWSTR)v131[0]);
	v99 = (wchar_t*)v131[0];
	v57 = GET_TLS_StrLen();
	v58 = v99;
	LODWORD(v99) = v57;
	add_to_STR_treeR(v58);
	add_to_STR_treeR(L" ");
	add_to_STR_treeR(v130);
	dup_from_STR_tree((LPVOID*)&v130, (int)v99);
	PathQuoteSpacesW(v130);
	if (g_DATA.field_B8 == 1)
		g_DATA.field_18 = add_results_to_tree((LPTHREAD_START_ROUTINE)sub_140003DDC, v128);
	else
		sub_140003DDC(v128);
	GET_TLS_StrLen();
	v73 = v124;
	GET_TLS_StrLen();
	add_to_STR_treeR(v73);
	add_to_STR_treeR(L" ");
	add_to_STR_treeR(v130);
	add2_to_StrTreeLen();
	GET_TLS_StrLen();
	v59 = GET_TLS_StrLen();
	MyGetCurrentDirectoryW(v59);
	add2_to_StrTreeLen();
	v63 = v126;
	GET_TLS_StrLen();
	add_to_STR_treeR(v63);
	add_to_STR_treeR(v122);
	STR_tree_root();
	STR_tree_root();
	v60 = STR_tree_root();
	MyShellExecuteOpen(v64, v68, (wchar_t*)((char*)v60 + v74));
	v62 = v100;
	v101 = v61;
	SET_TLS_2(v62);
	v131[1] = v101;

	exit((__int64)v101);
	//asm_CLEAR_TEMP_AND_EXIT((__int64)v101);
}

void main() {
	//hashfunc();
	start();
	return 0;
}