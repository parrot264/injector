#include <Windows.h>
#include <iostream>
#include <TlHelp32.h>
#include <string>
#include <tchar.h>

// Ensure we use ANSI versions
#ifdef UNICODE
#undef UNICODE
#endif
#ifdef _UNICODE
#undef _UNICODE
#endif

// Function to align section size to specified alignment
DWORD AlignSectionSize(DWORD size, DWORD alignment)
{
	if (alignment == 0)
		return size;
	return (size + alignment - 1) & ~(alignment - 1);
}

// Function to find process ID by name
DWORD GetProcessIdByName(const char *processName)
{
	HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (hSnapshot == INVALID_HANDLE_VALUE)
	{
		return 0;
	}

	PROCESSENTRY32 pe32;
	pe32.dwSize = sizeof(PROCESSENTRY32);

	if (Process32First(hSnapshot, &pe32))
	{
		do
		{
			// Convert to narrow string for comparison
			char currentProcessName[MAX_PATH] = {0};

			// Try both approaches to handle the confusion
			if (sizeof(pe32.szExeFile[0]) == sizeof(wchar_t))
			{
				// It's wide string
				WideCharToMultiByte(CP_ACP, 0, (LPCWSTR)pe32.szExeFile, -1, currentProcessName, MAX_PATH, NULL, NULL);
			}
			else
			{
				// It's narrow string
				strncpy_s(currentProcessName, MAX_PATH, (const char *)pe32.szExeFile, _TRUNCATE);
			}

			// Debug: print process name if it contains our target
			if (strstr(currentProcessName, "simple") != NULL || strstr(currentProcessName, "notepad") != NULL)
			{
				std::cout << "[DEBUG] Found: '" << currentProcessName << "' (PID: " << pe32.th32ProcessID << ")" << std::endl;
			}

			// Case-insensitive comparison
			if (_stricmp(currentProcessName, processName) == 0)
			{
				CloseHandle(hSnapshot);
				return pe32.th32ProcessID;
			}
		} while (Process32Next(hSnapshot, &pe32));
	}

	CloseHandle(hSnapshot);
	return 0;
}

// Function to inject DLL into target process
BOOL InjectDLL(DWORD processId, const char *dllPath)
{
	// Get handle to target process
	HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, processId);
	if (hProcess == NULL)
	{
		std::cout << "[-] Failed to open target process. Error: " << GetLastError() << std::endl;
		return FALSE;
	}

	// Calculate size needed for DLL path
	SIZE_T dllPathSize = strlen(dllPath) + 1;

	// Allocate memory in target process for DLL path
	LPVOID pRemoteDllPath = VirtualAllocEx(hProcess, NULL, dllPathSize,
										   MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	if (pRemoteDllPath == NULL)
	{
		std::cout << "[-] Failed to allocate memory in target process. Error: " << GetLastError() << std::endl;
		CloseHandle(hProcess);
		return FALSE;
	}

	// Write DLL path to allocated memory
	SIZE_T bytesWritten;
	if (!WriteProcessMemory(hProcess, pRemoteDllPath, dllPath, dllPathSize, &bytesWritten))
	{
		std::cout << "[-] Failed to write DLL path to target process. Error: " << GetLastError() << std::endl;
		VirtualFreeEx(hProcess, pRemoteDllPath, 0, MEM_RELEASE);
		CloseHandle(hProcess);
		return FALSE;
	}

	// Get address of LoadLibraryA function
	HMODULE hKernel32 = GetModuleHandleA("kernel32.dll");
	if (hKernel32 == NULL)
	{
		std::cout << "[-] Failed to get handle to kernel32.dll" << std::endl;
		VirtualFreeEx(hProcess, pRemoteDllPath, 0, MEM_RELEASE);
		CloseHandle(hProcess);
		return FALSE;
	}

	LPVOID pLoadLibraryA = GetProcAddress(hKernel32, "LoadLibraryA");
	if (pLoadLibraryA == NULL)
	{
		std::cout << "[-] Failed to get address of LoadLibraryA" << std::endl;
		VirtualFreeEx(hProcess, pRemoteDllPath, 0, MEM_RELEASE);
		CloseHandle(hProcess);
		return FALSE;
	}

	// Create remote thread to execute LoadLibraryA with our DLL path
	HANDLE hRemoteThread = CreateRemoteThread(hProcess, NULL, 0,
											  (LPTHREAD_START_ROUTINE)pLoadLibraryA,
											  pRemoteDllPath, 0, NULL);
	if (hRemoteThread == NULL)
	{
		std::cout << "[-] Failed to create remote thread. Error: " << GetLastError() << std::endl;
		VirtualFreeEx(hProcess, pRemoteDllPath, 0, MEM_RELEASE);
		CloseHandle(hProcess);
		return FALSE;
	}

	// Wait for remote thread to complete
	WaitForSingleObject(hRemoteThread, INFINITE);

	// Get exit code to check if LoadLibraryA succeeded
	DWORD exitCode;
	GetExitCodeThread(hRemoteThread, &exitCode);

	if (exitCode == 0)
	{
		std::cout << "[-] LoadLibraryA failed in target process" << std::endl;
	}
	else
	{
		std::cout << "[+] DLL successfully injected! Module base: 0x" << std::hex << exitCode << std::endl;
	}

	// Cleanup
	CloseHandle(hRemoteThread);
	VirtualFreeEx(hProcess, pRemoteDllPath, 0, MEM_RELEASE);
	CloseHandle(hProcess);

	return (exitCode != 0);
}

// Function to add a new section to PE file
BOOL AddSectionToPE(const char *targetFile, const char *sectionName, const char *dllPath)
{
	// Open target file
	HANDLE hFile = CreateFileA(targetFile, GENERIC_READ | GENERIC_WRITE, 0, NULL,
							   OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	if (hFile == INVALID_HANDLE_VALUE)
	{
		std::cout << "[-] Failed to open target file: " << targetFile << ". Error: " << GetLastError() << std::endl;
		return FALSE;
	}

	// Get file size
	DWORD fileSize = GetFileSize(hFile, NULL);
	if (fileSize == INVALID_FILE_SIZE)
	{
		std::cout << "[-] Failed to get file size. Error: " << GetLastError() << std::endl;
		CloseHandle(hFile);
		return FALSE;
	}

	// Allocate buffer for file
	PBYTE fileBuffer = (PBYTE)LocalAlloc(LPTR, fileSize);
	if (fileBuffer == NULL)
	{
		std::cout << "[-] Failed to allocate memory for file buffer" << std::endl;
		CloseHandle(hFile);
		return FALSE;
	}

	// Read file into buffer
	DWORD bytesRead;
	if (!ReadFile(hFile, fileBuffer, fileSize, &bytesRead, NULL))
	{
		std::cout << "[-] Failed to read file. Error: " << GetLastError() << std::endl;
		LocalFree(fileBuffer);
		CloseHandle(hFile);
		return FALSE;
	}
	// Validate PE file structure
	PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)fileBuffer;
	if (pDosHeader->e_magic != IMAGE_DOS_SIGNATURE)
	{
		std::cout << "[-] Invalid DOS signature" << std::endl;
		LocalFree(fileBuffer);
		CloseHandle(hFile);
		return FALSE;
	}

	PIMAGE_NT_HEADERS pNtHeaders = (PIMAGE_NT_HEADERS)(fileBuffer + pDosHeader->e_lfanew);
	if (pNtHeaders->Signature != IMAGE_NT_SIGNATURE)
	{
		std::cout << "[-] Invalid NT signature" << std::endl;
		LocalFree(fileBuffer);
		CloseHandle(hFile);
		return FALSE;
	}

	// Get section headers
	PIMAGE_SECTION_HEADER pSectionHeaders = IMAGE_FIRST_SECTION(pNtHeaders);
	WORD numberOfSections = pNtHeaders->FileHeader.NumberOfSections;

	// Find last section to determine where to add new section
	PIMAGE_SECTION_HEADER pLastSection = &pSectionHeaders[numberOfSections - 1];

	// Calculate new section's virtual address and file offset
	DWORD newSectionVA = AlignSectionSize(
		pLastSection->VirtualAddress + pLastSection->Misc.VirtualSize,
		pNtHeaders->OptionalHeader.SectionAlignment);

	DWORD newSectionOffset = AlignSectionSize(
		pLastSection->PointerToRawData + pLastSection->SizeOfRawData,
		pNtHeaders->OptionalHeader.FileAlignment);

	// Read DLL file to get its size
	HANDLE hDllFile = CreateFileA(dllPath, GENERIC_READ, 0, NULL,
								  OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	if (hDllFile == INVALID_HANDLE_VALUE)
	{
		std::cout << "[-] Failed to open DLL file: " << dllPath << ". Error: " << GetLastError() << std::endl;
		LocalFree(fileBuffer);
		CloseHandle(hFile);
		return FALSE;
	}

	DWORD dllSize = GetFileSize(hDllFile, NULL);
	CloseHandle(hDllFile);

	if (dllSize == INVALID_FILE_SIZE || dllSize == 0)
	{
		std::cout << "[-] Invalid DLL file size" << std::endl;
		LocalFree(fileBuffer);
		CloseHandle(hFile);
		return FALSE;
	}

	// Create new section header
	PIMAGE_SECTION_HEADER pNewSection = &pSectionHeaders[numberOfSections];
	ZeroMemory(pNewSection, sizeof(IMAGE_SECTION_HEADER));

	// Set section name (max 8 characters)
	strncpy_s((char *)pNewSection->Name, 8, sectionName, 8);

	// Set section properties
	pNewSection->VirtualAddress = newSectionVA;
	pNewSection->Misc.VirtualSize = dllSize;
	pNewSection->PointerToRawData = newSectionOffset;
	pNewSection->SizeOfRawData = AlignSectionSize(dllSize, pNtHeaders->OptionalHeader.FileAlignment);
	pNewSection->Characteristics = IMAGE_SCN_CNT_CODE | IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_READ;

	// Update PE headers
	pNtHeaders->FileHeader.NumberOfSections++;
	pNtHeaders->OptionalHeader.SizeOfImage = AlignSectionSize(
		newSectionVA + dllSize,
		pNtHeaders->OptionalHeader.SectionAlignment);

	// Write modified PE back to file
	SetFilePointer(hFile, 0, NULL, FILE_BEGIN);
	DWORD bytesWritten;
	if (!WriteFile(hFile, fileBuffer, fileSize, &bytesWritten, NULL))
	{
		std::cout << "[-] Failed to write modified PE file. Error: " << GetLastError() << std::endl;
		LocalFree(fileBuffer);
		CloseHandle(hFile);
		return FALSE;
	}

	// Cleanup
	LocalFree(fileBuffer);
	CloseHandle(hFile);

	std::cout << "[+] Successfully added section '" << sectionName << "' to PE file" << std::endl;
	return TRUE;
}

int main(int argc, char *argv[])
{
	// Validate command line arguments
	if (argc != 4)
	{
		std::cout << "Usage: " << argv[0] << " <process_name> <section_name> <dll_path>" << std::endl;
		std::cout << "Examples:" << std::endl;
		std::cout << "  " << argv[0] << " notepad.exe .inject test_dll.dll" << std::endl;
		std::cout << "  " << argv[0] << " CalculatorApp .inject test_dll.dll" << std::endl;
		std::cout << "  " << argv[0] << " simple_target.exe .inject test_dll.dll" << std::endl;
		return 1;
	}

	char *processName = argv[1]; // Changed from targetFile to processName
	char *sectionName = argv[2];
	char *dllPath = argv[3];

	// Convert relative DLL path to absolute path
	char absoluteDllPath[MAX_PATH];
	if (!GetFullPathNameA(dllPath, MAX_PATH, absoluteDllPath, NULL))
	{
		std::cout << "[-] Failed to get absolute path for DLL" << std::endl;
		return 1;
	}

	// Validate inputs
	if (strlen(sectionName) > 8)
	{
		std::cout << "[-] Section name must be 8 characters or less" << std::endl;
		return 1;
	}

	// Check if DLL file exists
	if (GetFileAttributesA(dllPath) == INVALID_FILE_ATTRIBUTES)
	{
		std::cout << "[-] DLL file does not exist: " << dllPath << std::endl;
		return 1;
	}

	// Note: We skip target file validation since we're injecting into running processes
	// This allows injection into UWP apps, system processes, etc.

	std::cout << "[+] PE File Injector - Educational Purpose Only" << std::endl;
	std::cout << "[+] Target Process: " << processName << std::endl;
	std::cout << "[+] Section: " << sectionName << std::endl;
	std::cout << "[+] DLL: " << absoluteDllPath << std::endl;
	std::cout << std::endl;

	// Step 1: Skip PE file modification (focusing on runtime injection)
	std::cout << "[*] Skipping PE file modification (focusing on runtime injection)" << std::endl;

	// Step 2: Find target process (assuming it's running)
	// Extract just the filename if a path was provided
	std::string targetProcessName = std::string(processName);
	size_t lastSlash = targetProcessName.find_last_of("\\/");
	if (lastSlash != std::string::npos)
	{
		targetProcessName = targetProcessName.substr(lastSlash + 1);
	}

	std::cout << "[*] Looking for process: " << targetProcessName << std::endl;
	DWORD processId = GetProcessIdByName(targetProcessName.c_str());

	if (processId == 0)
	{
		std::cout << "[-] Target process not found. Please ensure " << targetProcessName << " is running." << std::endl;
		std::cout << "[*] You can start the process and run this injector again." << std::endl;
		return 1;
	}

	std::cout << "[+] Found target process with PID: " << processId << std::endl;

	// Step 3: Inject DLL
	std::cout << "[*] Injecting DLL..." << std::endl;
	if (InjectDLL(processId, absoluteDllPath))
	{
		std::cout << "[+] Injection completed successfully!" << std::endl;
		return 0;
	}
	else
	{
		std::cout << "[-] Injection failed!" << std::endl;
		return 1;
	}
}