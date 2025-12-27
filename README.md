# PE File Injector - Educational Tool

A Windows PE (Portable Executable) file injector for educational purposes that demonstrates DLL injection techniques.

## ⚠️ IMPORTANT DISCLAIMER

This tool is created for **EDUCATIONAL PURPOSES ONLY**. It demonstrates:
- PE file structure manipulation
- Process memory management
- DLL injection techniques
- Windows API usage

**DO NOT USE THIS TOOL FOR MALICIOUS PURPOSES**. Only use it on systems you own or have explicit permission to test.

## Features

- ✅ PE file parsing and validation
- ✅ Section addition to PE files
- ✅ Process enumeration and targeting
- ✅ DLL injection via CreateRemoteThread
- ✅ Comprehensive error handling
- ✅ Memory management and cleanup

## Building

### Prerequisites
- MinGW-w64 or Visual Studio Build Tools
- Windows SDK

### Compilation
```bash
# Build everything
make all

# Build just the injector
make pe_injector.exe

# Build just the test DLL
make test_dll.dll

# Clean build artifacts
make clean
```

### Manual Compilation
```bash
# Compile the injector
g++ -std=c++11 -Wall -O2 -o pe_injector.exe fun.cpp -static-libgcc -static-libstdc++

# Compile the test DLL
g++ -std=c++11 -Wall -O2 -shared -o test_dll.dll test_dll.cpp -Wl,--out-implib,test_dll.lib
```

## Usage

```bash
pe_injector.exe <target_executable> <section_name> <dll_path>
```

### Parameters
- `target_executable`: Path to the PE file to modify and inject into
- `section_name`: Name for the new section (max 8 characters)
- `dll_path`: Path to the DLL file to inject

### Example
```bash
# Start notepad first, then inject
pe_injector.exe notepad.exe .inject test_dll.dll
```

## How It Works

### 1. PE File Modification
- Parses the target PE file structure
- Validates DOS and NT headers
- Adds a new section with specified name
- Updates section count and image size
- Writes modified PE back to disk

### 2. Process Injection
- Enumerates running processes to find target
- Opens target process with required permissions
- Allocates memory in target process for DLL path
- Uses CreateRemoteThread + LoadLibraryA for injection
- Properly cleans up allocated resources

## Security Considerations

### Defensive Programming
- Input validation for all parameters
- File existence checks before processing
- PE structure validation
- Proper error handling and cleanup
- Memory allocation bounds checking

### Potential Issues
- **Antivirus Detection**: May be flagged as malicious
- **ASLR/DEP**: Modern protections may interfere
- **Process Permissions**: Requires appropriate privileges
- **Architecture Mismatch**: 32-bit vs 64-bit compatibility

## Educational Value

This implementation demonstrates:

1. **PE File Format Understanding**
   - DOS header structure
   - NT headers and optional header
   - Section header manipulation
   - File alignment concepts

2. **Windows API Usage**
   - File I/O operations
   - Process enumeration
   - Memory management
   - Thread creation

3. **Injection Techniques**
   - CreateRemoteThread method
   - LoadLibraryA-based injection
   - Process memory manipulation

## Limitations

- Only supports CreateRemoteThread injection method
- No support for manual DLL mapping
- Limited to LoadLibraryA-compatible DLLs
- No stealth or evasion techniques
- Basic error recovery

## Testing

1. Build the project:
   ```bash
   make test
   ```

2. Start a target process (e.g., notepad.exe)

3. Run the injector:
   ```bash
   pe_injector.exe notepad.exe .test test_dll.dll
   ```

4. You should see a message box confirming successful injection

## Troubleshooting

### Common Issues
- **"Target process not found"**: Ensure the process is running
- **"Failed to open target process"**: Run as Administrator
- **"Invalid PE file"**: Target file may be corrupted or protected
- **"LoadLibraryA failed"**: DLL may have dependencies or be incompatible

### Debug Tips
- Use Process Monitor to track file/registry access
- Check Windows Event Viewer for system errors
- Verify DLL dependencies with Dependency Walker
- Test with simple target processes first

## Legal Notice

This software is provided for educational purposes only. Users are responsible for ensuring compliance with all applicable laws and regulations. The authors assume no responsibility for misuse of this tool.
