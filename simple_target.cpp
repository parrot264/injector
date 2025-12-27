#include <Windows.h>
#include <iostream>

// Simple target application for testing injection
int main() {
    std::cout << "[+] Simple Target Application Started" << std::endl;
    std::cout << "[*] Process ID: " << GetCurrentProcessId() << std::endl;
    std::cout << "[*] Press any key to exit..." << std::endl;
    
    // Keep the process running so we can inject into it
    while (true) {
        Sleep(1000);
        if (GetAsyncKeyState(VK_ESCAPE) & 0x8000) {
            break;
        }
    }
    
    std::cout << "[+] Target application exiting..." << std::endl;
    return 0;
}
