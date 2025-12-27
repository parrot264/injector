# Makefile for PE Injector
# Requires MinGW-w64 or Visual Studio Build Tools

CXX = g++
CXXFLAGS = -std=c++11 -Wall -O2
LDFLAGS = -static-libgcc -static-libstdc++

# Targets
INJECTOR = pe_injector.exe
TEST_DLL = test_dll.dll

all: $(INJECTOR) $(TEST_DLL)

# Build the PE injector
$(INJECTOR): fun.cpp
	$(CXX) $(CXXFLAGS) -o $(INJECTOR) fun.cpp $(LDFLAGS)

# Build the test DLL
$(TEST_DLL): test_dll.cpp
	$(CXX) $(CXXFLAGS) -shared -o $(TEST_DLL) test_dll.cpp -Wl,--out-implib,test_dll.lib

# Clean build artifacts
clean:
	del /f $(INJECTOR) $(TEST_DLL) test_dll.lib 2>nul || true

# Test target - builds everything and shows usage
test: all
	@echo.
	@echo [+] Build completed successfully!
	@echo [+] Usage: $(INJECTOR) ^<target_executable^> ^<section_name^> ^<dll_path^>
	@echo [+] Example: $(INJECTOR) notepad.exe .inject $(TEST_DLL)
	@echo.
	@echo [*] To test:
	@echo    1. Start notepad.exe
	@echo    2. Run: $(INJECTOR) notepad.exe .inject $(TEST_DLL)
	@echo.

.PHONY: all clean test
