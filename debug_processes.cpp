#include <Windows.h>
#include <TlHelp32.h>
#include <iostream>

int main()
{
    std::cout << "[+] Process Enumeration Debug Tool" << std::endl;

    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE)
    {
        std::cout << "[-] Failed to create process snapshot" << std::endl;
        return 1;
    }

    PROCESSENTRY32 pe32;
    pe32.dwSize = sizeof(PROCESSENTRY32);

    std::cout << "[*] Enumerating processes..." << std::endl;

    if (Process32First(hSnapshot, &pe32))
    {
        int count = 0;
        do
        {
            // Convert to narrow string
            char processName[MAX_PATH];
            WideCharToMultiByte(CP_ACP, 0, (LPCWSTR)pe32.szExeFile, -1, processName, MAX_PATH, NULL, NULL);

            // Show first 20 processes to debug the conversion
            if (count < 20)
            {
                std::cout << "[" << count << "] " << processName << " (PID: " << pe32.th32ProcessID << ")" << std::endl;
            }

            // Also check for our target processes
            if (strstr(processName, "notepad") != NULL ||
                strstr(processName, "simple") != NULL ||
                strstr(processName, "target") != NULL ||
                strstr(processName, "calc") != NULL ||
                strstr(processName, "Calculator") != NULL)
            {
                std::cout << "[TARGET] Found: " << processName << " (PID: " << pe32.th32ProcessID << ")" << std::endl;
            }

            count++;
            if (count > 200)
                break; // Prevent infinite loop

        } while (Process32Next(hSnapshot, &pe32));

        std::cout << "[*] Total processes enumerated: " << count << std::endl;
    }
    else
    {
        std::cout << "[-] Failed to enumerate processes" << std::endl;
    }

    CloseHandle(hSnapshot);
    return 0;
}
