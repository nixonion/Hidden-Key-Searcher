#include <windows.h>
#include <string.h>
#include <iostream>


typedef struct _UNICODE_STRING {
	USHORT Length;
	USHORT MaximumLength;
	PWSTR  Buffer;
} UNICODE_STRING;
typedef UNICODE_STRING* PUNICODE_STRING;

typedef
NTSTATUS(NTAPI* _NtDeleteValueKey)(
	IN HANDLE KeyHandle,
	IN PUNICODE_STRING ValueName
	);

_NtDeleteValueKey NtDeleteValueKey = NULL;

typedef struct _KEY_VALUE_BASIC_INFORMATION {
	ULONG   TitleIndex;
	ULONG   Type;
	ULONG   NameLength;
	WCHAR   Name[1];            // Variable size
} KEY_VALUE_BASIC_INFORMATION, * PKEY_VALUE_BASIC_INFORMATION;

typedef struct _KEY_VALUE_FULL_INFORMATION {
	ULONG   TitleIndex;
	ULONG   Type;
	ULONG   DataOffset;
	ULONG   DataLength;
	ULONG   NameLength;
	WCHAR   Name[1];            // Variable size
								//          Data[1];            // Variable size data not declared
} KEY_VALUE_FULL_INFORMATION, * PKEY_VALUE_FULL_INFORMATION;

typedef enum _KEY_VALUE_INFORMATION_CLASS {
	KeyValueBasicInformation,
	KeyValueFullInformation,
	KeyValuePartialInformation,
	KeyValueFullInformationAlign64,
	KeyValuePartialInformationAlign64,
	MaxKeyValueInfoClass  // MaxKeyValueInfoClass should always be the last enum
} KEY_VALUE_INFORMATION_CLASS;

typedef
NTSTATUS(NTAPI *_NtQueryValueKey)(
	IN HANDLE KeyHandle,
	IN PUNICODE_STRING ValueName,
	IN KEY_VALUE_INFORMATION_CLASS KeyValueInformationClass,
	IN PVOID KeyValueInformation,
	IN ULONG Length,
	IN PULONG ResultLength
	);

_NtQueryValueKey NtQueryValueKey = NULL;

//typedef NTSTATUS(*_NtQueryValueKey)(HANDLE, PUNICODE_STRING, KEY_VALUE_INFORMATION_CLASS, PVOID, ULONG, PULONG);

#define HIDDEN_KEY_LENGTH 11

void main() {

	HMODULE hNtdll1 = LoadLibraryA("ntdll.dll");
	NtQueryValueKey = (_NtQueryValueKey)GetProcAddress(hNtdll1, "NtQueryValueKey");

	UNICODE_STRING ValueName = { 0 };
	wchar_t runkeyPath[0x100] = L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run";
	wchar_t runkeyPath_trick[0x100] = L"\0\0SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run";

	if (!NtDeleteValueKey) {
		HMODULE hNtdll = LoadLibraryA("ntdll.dll");
		NtDeleteValueKey = (_NtDeleteValueKey)GetProcAddress(hNtdll, "NtDeleteValueKey");
	}

	ValueName.Buffer = runkeyPath_trick;
	printf("%ls\n", ValueName.Buffer+2);
	ValueName.Length = 2 * HIDDEN_KEY_LENGTH; //this value doesn't matter as long as it is non-zero
	ValueName.MaximumLength = 0;

	BYTE** buf=NULL; DWORD* buflen=NULL;
	
	ULONG ulKeyInfoSize = 0;
	ULONG size_needed = 0;
	PKEY_VALUE_FULL_INFORMATION  pKeyInfo = NULL;

	HKEY hkResult = NULL;
	ULONG Index = 0;
	NTSTATUS status;
	
	if (!RegOpenKeyExW(HKEY_CURRENT_USER, runkeyPath, NULL, KEY_ALL_ACCESS, &hkResult)) {
		printf("%p", hkResult);
		
		status = NtQueryValueKey(hkResult,&ValueName, KeyValueFullInformation,nullptr,0,&size_needed);
		
		//std::vector<BYTE> buffer(size_needed);
		ulKeyInfoSize = size_needed;
		pKeyInfo = (PKEY_VALUE_FULL_INFORMATION)alloca(size_needed);//ExAllocatePoolWithTag(NonPagedPool, ulKeyInfoSizeNeeded, g_ulTag);
		if (NULL == pKeyInfo)
		{
			return;
		}
		RtlZeroMemory(pKeyInfo, ulKeyInfoSize);
		printf("\n%d", ulKeyInfoSize);
		status = NtQueryValueKey(hkResult, &ValueName, KeyValueFullInformation, pKeyInfo, ulKeyInfoSize, &size_needed);

		printf("\n%ls", pKeyInfo->Name+13);

		ULONG_PTR   pSrc = NULL;
		pSrc = (ULONG_PTR)((PBYTE)pKeyInfo + pKeyInfo->DataOffset);
		printf("\n%ls", pSrc);
		
		



		
		//wcscmp(pKeyInfo->Name, L"ta");
		/*if (wcscmp(pKeyInfo->Name+2, L"MICRO")==0)
		{
			printf("lol");
		}
		//RegQueryValueExA(hkResult, NULL, NULL, NULL, NULL, buflen);
		//printf("%d", *buflen);
		//*buf = (BYTE*)malloc(*buflen);
		//RegQueryValueExA(hkResult, NULL, NULL, NULL, *buf, buflen);
		/* 
		if (!NtDeleteValueKey(hkResult, &ValueName)) {
			printf("SUCCESS deleting hidden run value in registry!\n");
		}
		*/
		//RegCloseKey(hkResult);
	}

	Index = 0;
	while (TRUE)
	{

	}
}