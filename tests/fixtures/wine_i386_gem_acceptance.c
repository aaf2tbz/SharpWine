// SPDX-License-Identifier: Apache-2.0
#include <windows.h>

int main(void) {
    static const char marker[] = "METALSHARP_GEM_I386_OK\r\n";
    DWORD written = 0;
    HANDLE file = CreateFileA("C:\\metalsharp-gem-i386-ok.txt", GENERIC_WRITE, 0, NULL,
                              CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);

    if (file == INVALID_HANDLE_VALUE)
        return 10;
    if (!WriteFile(file, marker, sizeof(marker) - 1, &written, NULL) ||
        written != sizeof(marker) - 1) {
        CloseHandle(file);
        return 11;
    }
    if (!CloseHandle(file))
        return 12;
    return 0;
}
