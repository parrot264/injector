#include <Windows.h>
#include <iostream>

// Simple test DLL for injection testing
BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved)
{
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
        // This will be called when the DLL is injected
        MessageBoxA(NULL, "DLL Successfully Injected!", "PE Injector Test", MB_OK | MB_ICONINFORMATION);
        break;
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}

// Export a simple function for testing
extern "C" __declspec(dllexport) void TestFunction()
{
    MessageBoxA(NULL, "Test function called!", "PE Injector Test", MB_OK);
}
