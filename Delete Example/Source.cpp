#include <windows.h>
#include <string.h>
#include <iostream>
#include <iostream>
using namespace std;


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



#define HIDDEN_KEY_LENGTH 11

void main() {

	HMODULE hNtdll1 = LoadLibraryA("ntdll.dll");
	NtEnumerateValueKey = (_NtEnumerateValueKey)GetProcAddress(hNtdll1, "NtEnumerateValueKey");

	hNtdll1 = LoadLibraryA("ntdll.dll");
	NtQueryValueKey = (_NtQueryValueKey)GetProcAddress(hNtdll1, "NtQueryValueKey");


	UNICODE_STRING ValueNameArray[100];
	int IndexOfNullKey = 0;
	HKEY IndexHkey[100];
	UNICODE_STRING ValueName = { 0 };
	wchar_t runkeyPath[0x100] = L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run";
	wchar_t runkeyPath_trick[0x100] = L"\0\0SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run";

	
	
	if (!NtDeleteValueKey) {
		HMODULE hNtdll = LoadLibraryA("ntdll.dll");
		NtDeleteValueKey = (_NtDeleteValueKey)GetProcAddress(hNtdll, "NtDeleteValueKey");
	}

	ValueName.Buffer = runkeyPath_trick;
	ValueName.Length = 2 * HIDDEN_KEY_LENGTH; //this value doesn't matter as long as it is non-zero
	ValueName.MaximumLength = 0;
	

	BYTE** buf=NULL; DWORD* buflen=NULL;
	
	ULONG ulKeyInfoSize = 0;
	ULONG size_needed = 0;
	PKEY_VALUE_FULL_INFORMATION  pKeyInfo ;

	HKEY hkResult = NULL;
	ULONG Index = 0;
	NTSTATUS status;
	int i=0;
	
	if (!RegOpenKeyExW(HKEY_CURRENT_USER, runkeyPath, NULL, KEY_ALL_ACCESS, &hkResult)) 
	{
		
		Index = 0;
		while (TRUE)
		{

			status = NtEnumerateValueKey(hkResult,
				Index,
				KeyValueFullInformation,
				nullptr,
				0,
				&size_needed);

			ulKeyInfoSize = size_needed;
			

			pKeyInfo = (PKEY_VALUE_FULL_INFORMATION)alloca(size_needed);
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

			if (status == 0x8000001A || status == 0xC000000D)
			{
				break;
			}

			
			if (wcscmp(pKeyInfo->Name, L"\0") == 0 && wcscmp(pKeyInfo->Name +1, L"\0") == 0)
			{
				printf("\n\n-----------------\n\n");
				printf("\nEntry Number : %d\n\n", IndexOfNullKey);
				printf("Registry Path\t= HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run\n");
				printf("Name\t= ");
				for (i = 0; i < pKeyInfo->NameLength/2; i++)
				{
					if (wcscmp(pKeyInfo->Name + i, L"\0") == 0)
					{
						printf("Null");
					}
					printf("%s", pKeyInfo->Name + i);
				}
				//printf("\nname = %ls", pKeyInfo->Name +2 );
				printf("\nIndex\t= %lu", pKeyInfo->TitleIndex);
				printf("\nType\t= %d", pKeyInfo->Type); //0x00000001 REG_SZ
				printf("\nDatalength\t= %d", pKeyInfo->DataLength);
				printf("\nNamelength\t= %d", pKeyInfo->NameLength);
				ULONG_PTR   pSrc = NULL;
				pSrc = (ULONG_PTR)((PBYTE)pKeyInfo + pKeyInfo->DataOffset);
				printf("\nSource\t= %ls", pSrc);
				printf("\nHandle\t= %p", hkResult);
				
				

				ValueNameArray[IndexOfNullKey] = { 0 };
				ValueNameArray[IndexOfNullKey].Buffer = pKeyInfo->Name;
				ValueNameArray[IndexOfNullKey].Length = pKeyInfo->NameLength;
				ValueNameArray[IndexOfNullKey].MaximumLength = 0;
				IndexHkey[IndexOfNullKey] = hkResult;
				IndexOfNullKey++;
			}
			
			
			Index++;

			
		}
		
		

		
		RegCloseKey(hkResult);
	}
/*
	
	
	if (!RegOpenKeyExW(HKEY_CURRENT_USER, L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce", NULL, KEY_ALL_ACCESS, &hkResult))
	{

		Index = 0;
		while (TRUE)
		{

			status = NtEnumerateValueKey(hkResult,
				Index,
				KeyValueFullInformation,
				nullptr,
				0,
				&size_needed);

			ulKeyInfoSize = size_needed;


			pKeyInfo = (PKEY_VALUE_FULL_INFORMATION)alloca(size_needed);
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

			if (status == 0x8000001A || status == 0xC000000D)
			{
				break;
			}


			if (wcscmp(pKeyInfo->Name, L"\0") == 0 && wcscmp(pKeyInfo->Name + 1, L"\0") == 0)
			{
				printf("\n\n-----------------\n\n");
				printf("\nEntry Number : %d\n\n", IndexOfNullKey);
				printf("Registry Path\t= HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce\n");
				printf("Name\t= ");
				for (i = 0; i < pKeyInfo->NameLength / 2; i++)
				{
					if (wcscmp(pKeyInfo->Name + i, L"\0") == 0)
					{
						printf("Null");
					}
					printf("%s", pKeyInfo->Name + i);
				}
				
				printf("\nIndex\t= %lu", pKeyInfo->TitleIndex);
				printf("\nType\t= %d", pKeyInfo->Type); //0x00000001 REG_SZ
				printf("\nDatalength\t= %d", pKeyInfo->DataLength);
				printf("\nNamelength\t= %d", pKeyInfo->NameLength);
				ULONG_PTR   pSrc = NULL;
				pSrc = (ULONG_PTR)((PBYTE)pKeyInfo + pKeyInfo->DataOffset);
				printf("\nSource\t= %ls", pSrc);


				ValueNameArray[IndexOfNullKey] = { 0 };
				ValueNameArray[IndexOfNullKey].Buffer = pKeyInfo->Name;
				ValueNameArray[IndexOfNullKey].Length = pKeyInfo->NameLength;
				ValueNameArray[IndexOfNullKey].MaximumLength = 0;
				IndexHkey[IndexOfNullKey] = hkResult;
				IndexOfNullKey++;
			}


			Index++;


		}



		RegCloseKey(hkResult);
	}

	if (!RegOpenKeyExW(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run", NULL, KEY_ALL_ACCESS, &hkResult))
	{

		Index = 0;
		while (TRUE)
		{

			status = NtEnumerateValueKey(hkResult,
				Index,
				KeyValueFullInformation,
				nullptr,
				0,
				&size_needed);

			ulKeyInfoSize = size_needed;


			pKeyInfo = (PKEY_VALUE_FULL_INFORMATION)alloca(size_needed);
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

			if (status == 0x8000001A || status == 0xC000000D)
			{
				break;
			}


			if (wcscmp(pKeyInfo->Name, L"\0") == 0 && wcscmp(pKeyInfo->Name + 1, L"\0") == 0)
			{
				printf("\n\n-----------------\n\n");
				printf("\nEntry Number : %d\n\n", IndexOfNullKey);
				printf("Registry Path\t= HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce\n");
				printf("Name\t= ");
				for (i = 0; i < pKeyInfo->NameLength / 2; i++)
				{
					if (wcscmp(pKeyInfo->Name + i, L"\0") == 0)
					{
						printf("Null");
					}
					printf("%s", pKeyInfo->Name + i);
				}

				printf("\nIndex\t= %lu", pKeyInfo->TitleIndex);
				printf("\nType\t= %d", pKeyInfo->Type); //0x00000001 REG_SZ
				printf("\nDatalength\t= %d", pKeyInfo->DataLength);
				printf("\nNamelength\t= %d", pKeyInfo->NameLength);
				ULONG_PTR   pSrc = NULL;
				pSrc = (ULONG_PTR)((PBYTE)pKeyInfo + pKeyInfo->DataOffset);
				printf("\nSource\t= %ls", pSrc);


				ValueNameArray[IndexOfNullKey] = { 0 };
				ValueNameArray[IndexOfNullKey].Buffer = pKeyInfo->Name;
				ValueNameArray[IndexOfNullKey].Length = pKeyInfo->NameLength;
				ValueNameArray[IndexOfNullKey].MaximumLength = 0;
				IndexHkey[IndexOfNullKey] = hkResult;
				IndexOfNullKey++;
			}


			Index++;


		}
		



		RegCloseKey(hkResult);
	}
	*/

	printf("\n---------------------------------------------------------------------------\n");
	
	printf("\n\n%d", IndexOfNullKey);
	printf("\n%ls", ValueNameArray[2].Buffer + 2);
	printf("\n%p", IndexHkey[2]);

	if (!RegOpenKeyExW(HKEY_CURRENT_USER, runkeyPath, NULL, KEY_ALL_ACCESS, &hkResult)) {
		//printf("%p", hkResult);

		status = NtQueryValueKey(IndexHkey[2], &ValueNameArray[2], KeyValueFullInformation, nullptr, 0, &size_needed);

		
		ulKeyInfoSize = size_needed;
		pKeyInfo = (PKEY_VALUE_FULL_INFORMATION)alloca(size_needed);//ExAllocatePoolWithTag(NonPagedPool, ulKeyInfoSizeNeeded, g_ulTag);
		if (NULL == pKeyInfo)
		{
			return;
		}
		RtlZeroMemory(pKeyInfo, ulKeyInfoSize);
		//printf("\n%d", ulKeyInfoSize);
		status = NtQueryValueKey(IndexHkey[2], &ValueNameArray[2], KeyValueFullInformation, pKeyInfo, ulKeyInfoSize, &size_needed);

		printf("\nname = %ls", pKeyInfo->Name + 2);

		ULONG_PTR   pSrc = NULL;
		pSrc = (ULONG_PTR)((PBYTE)pKeyInfo + pKeyInfo->DataOffset);
		printf("\n%ls", pSrc);

		printf("\n\n\n");
	}
	
	
		int inp;
		int consent;
		if (IndexOfNullKey != 0)
		{
			cout << "Enter 1 to delete entry, Enter 0 to exit : ";
			cin >> inp;
			if (inp == 1)
			{
				cout << "Entry Number of Key to delete  : ";
				cin >> inp;
				if (inp < 0 || inp >= IndexOfNullKey)
				{
					return;
				}
				printf("%d", inp);

				status = NtQueryValueKey(IndexHkey[inp], &ValueNameArray[inp], KeyValueFullInformation, nullptr, 0, &size_needed);

				printf("\nDeleting Entry.......\n");
				printf("\n%ls", ValueNameArray[inp].Buffer + 2);
				printf("\n%p", IndexHkey[inp]);
				ulKeyInfoSize = size_needed;
				pKeyInfo = (PKEY_VALUE_FULL_INFORMATION)alloca(size_needed);
				if (NULL == pKeyInfo)
				{
					return;
				}
				RtlZeroMemory(pKeyInfo, ulKeyInfoSize);

				status = NtQueryValueKey(IndexHkey[inp], &ValueNameArray[inp], KeyValueFullInformation, pKeyInfo, ulKeyInfoSize, &size_needed);

				printf("\nname = %ls", pKeyInfo->Name + 2);

				ULONG_PTR   pSrc = NULL;
				pSrc = (ULONG_PTR)((PBYTE)pKeyInfo + pKeyInfo->DataOffset);
				printf("\nSource = %ls", pSrc);
				printf("\n\n\n");
				cout << "Are you sure? Enter 1 for YES and 0 for No : ";
				cin >> consent;
				if (consent != 1)
				{
					return;

				}
				if (!NtDeleteValueKey(IndexHkey[inp], &ValueNameArray[inp])) {
					printf("\nSUCCESSFULLY deleted the hidden run value in registry!\n");
				}



			}
			//printf("%d", inp);

		}
		


		
	
	
	/* Uncomment this code to check the number of keys read by Non-Ntdll functions
	
	HKEY hkResult1;
	if (!RegOpenKeyExW(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run", NULL, KEY_ALL_ACCESS, &hkResult1))
	{

		DWORD cSubKeys = 0;
		DWORD cValues=0;
		DWORD retCode = RegQueryInfoKey(
			hkResult1,                    // key handle 
			NULL,                // buffer for class name 
			NULL,           // size of class string 
			NULL,                    // reserved 
			&cSubKeys,               // number of subkeys 
			NULL,            // longest subkey size 
			NULL,            // longest class string 
			&cValues,                // number of values for this key 
			NULL,            // longest value name 
			NULL,         // longest value data 
			NULL,   // security descriptor 
			NULL);       // last write time 

		printf("\n num keys = %d\n", cSubKeys);
		printf("\n num key values = %d\n", cValues);
		printf("\nhandle = %p\n", hkResult1);
		
		
		RegCloseKey(hkResult1);
		
	}
	*/

}