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

typedef
NTSTATUS(NTAPI *_NtEnumerateValueKey)(
	IN HANDLE KeyHandle,
	IN ULONG                       Index,
	IN KEY_VALUE_INFORMATION_CLASS KeyValueInformationClass,
	IN PVOID KeyValueInformation,
	IN ULONG Length,
	IN PULONG ResultLength
	);

_NtEnumerateValueKey NtEnumerateValueKey = NULL;


//typedef NTSTATUS(*_NtQueryValueKey)(HANDLE, PUNICODE_STRING, KEY_VALUE_INFORMATION_CLASS, PVOID, ULONG, PULONG);

#define HIDDEN_KEY_LENGTH 11

void main() {

	HMODULE hNtdll1 = LoadLibraryA("ntdll.dll");
	NtEnumerateValueKey = (_NtEnumerateValueKey)GetProcAddress(hNtdll1, "NtEnumerateValueKey");

	hNtdll1 = LoadLibraryA("ntdll.dll");
	NtQueryValueKey = (_NtQueryValueKey)GetProcAddress(hNtdll1, "NtQueryValueKey");

	UNICODE_STRING ValueName = { 0 };
	wchar_t runkeyPath[0x100] = L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run";
	wchar_t runkeyPath_trick[0x100] = L"\0\0SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run";

	if (!NtDeleteValueKey) {
		HMODULE hNtdll = LoadLibraryA("ntdll.dll");
		NtDeleteValueKey = (_NtDeleteValueKey)GetProcAddress(hNtdll, "NtDeleteValueKey");
	}

	ValueName.Buffer = runkeyPath_trick;
	printf("%.9ls\n", ValueName.Buffer+2);
	ValueName.Length = 2 * HIDDEN_KEY_LENGTH; //this value doesn't matter as long as it is non-zero
	printf("%d\n", ValueName.Length);
	ValueName.MaximumLength = 0;
	printf("%d\n\n", ValueName.MaximumLength);

	BYTE** buf=NULL; DWORD* buflen=NULL;
	
	ULONG ulKeyInfoSize = 0;
	ULONG size_needed = 0;
	PKEY_VALUE_FULL_INFORMATION  pKeyInfo = NULL;

	HKEY hkResult = NULL;
	ULONG Index = 0;
	NTSTATUS status;
	int i;
	
	if (!RegOpenKeyExW(HKEY_CURRENT_USER, runkeyPath, NULL, KEY_ALL_ACCESS, &hkResult)) {
		//printf("%p", hkResult);
		
		status = NtQueryValueKey(hkResult,&ValueName, KeyValueFullInformation,nullptr,0,&size_needed);
		
		//std::vector<BYTE> buffer(size_needed);
		ulKeyInfoSize = size_needed;
		pKeyInfo = (PKEY_VALUE_FULL_INFORMATION)alloca(size_needed);//ExAllocatePoolWithTag(NonPagedPool, ulKeyInfoSizeNeeded, g_ulTag);
		if (NULL == pKeyInfo)
		{
			return;
		}
		RtlZeroMemory(pKeyInfo, ulKeyInfoSize);
		//printf("\n%d", ulKeyInfoSize);
		status = NtQueryValueKey(hkResult, &ValueName, KeyValueFullInformation, pKeyInfo, ulKeyInfoSize, &size_needed);

		printf("\nname = %ls", pKeyInfo->Name+2);

		ULONG_PTR   pSrc = NULL;
		pSrc = (ULONG_PTR)((PBYTE)pKeyInfo + pKeyInfo->DataOffset);
		printf("\n%ls", pSrc);
		
		printf("\n\n\n");

		Index = 3;
		while (TRUE)
		{

			status = NtEnumerateValueKey(hkResult,
				Index,
				KeyValueFullInformation,
				nullptr,
				0,
				&size_needed);

			ulKeyInfoSize = size_needed;
			pKeyInfo = (PKEY_VALUE_FULL_INFORMATION)alloca(size_needed);//ExAllocatePoolWithTag(NonPagedPool, ulKeyInfoSizeNeeded, g_ulTag);
			if (NULL == pKeyInfo)
			{
				return;
			}
			RtlZeroMemory(pKeyInfo, ulKeyInfoSize);
			status = NtEnumerateValueKey(hkResult,
				Index,
				KeyValueFullInformation,
				pKeyInfo,
				ulKeyInfoSize,
				&size_needed);

			
			if (wcscmp(pKeyInfo->Name, L"\0") == 0 && wcscmp(pKeyInfo->Name +1, L"\0") == 0)
			{
				printf("\n%d-----------------\n\nname = ",Index);
				for (i = 0; i < pKeyInfo->NameLength/2; i++)
				{
					if (wcscmp(pKeyInfo->Name + i, L"\0") == 0)
					{
						printf("_");
					}
					printf("%s", pKeyInfo->Name + i);
				}
				//printf("\nname = %ls", pKeyInfo->Name +2 );
				printf("\nindex = %lu", pKeyInfo->TitleIndex);
				printf("\ntype = %d", pKeyInfo->Type); //0x00000001 REG_SZ
				printf("\ndatalength = %d", pKeyInfo->DataLength);
				printf("\nnamelength = %d", pKeyInfo->NameLength);
				ULONG_PTR   pSrc = NULL;
				pSrc = (ULONG_PTR)((PBYTE)pKeyInfo + pKeyInfo->DataOffset);
				printf("\nsource = %ls", pSrc);
				printf("\n-----------------\n");
			}
			if (status == 0x8000001A || status== 0xC000000D)
			{
				break;
			}

			printf("\nyolololo\n");

			ValueName = { 0 };
			ValueName.Buffer = pKeyInfo->Name;
			printf("%ls\n", ValueName.Buffer+2);
			ValueName.Length = pKeyInfo->NameLength; //this value doesn't matter as long as it is non-zero
			printf("%d\n", ValueName.Length);
			ValueName.MaximumLength = 0;
			printf("%d\n\n", ValueName.MaximumLength);
			break;
			Index++;

			
		}


		printf("new phase ---\n");
		status = NtQueryValueKey(hkResult, &ValueName, KeyValueFullInformation, nullptr, 0, &size_needed);

		//std::vector<BYTE> buffer(size_needed);
		ulKeyInfoSize = size_needed;
		pKeyInfo = (PKEY_VALUE_FULL_INFORMATION)alloca(size_needed);//ExAllocatePoolWithTag(NonPagedPool, ulKeyInfoSizeNeeded, g_ulTag);
		if (NULL == pKeyInfo)
		{
			return;
		}
		RtlZeroMemory(pKeyInfo, ulKeyInfoSize);
		//printf("\n%d", ulKeyInfoSize);
		status = NtQueryValueKey(hkResult, &ValueName, KeyValueFullInformation, pKeyInfo, ulKeyInfoSize, &size_needed);

		printf("\nname = %ls", pKeyInfo->Name + 2);

		ULONG_PTR   pSrc1 = NULL;
		pSrc1 = (ULONG_PTR)((PBYTE)pKeyInfo + pKeyInfo->DataOffset);
		printf("\n%ls", pSrc1);


		
		//wcscmp(pKeyInfo->Name, L"ta");
		/*if (wcscmp(pKeyInfo->Name+2, L"MICRO")==0)
		{
			printf("lol");
		}
		
		/* 
		if (!NtDeleteValueKey(hkResult, &ValueName)) {
			printf("SUCCESS deleting hidden run value in registry!\n");
		}
		*/
		RegCloseKey(hkResult);
	}

}