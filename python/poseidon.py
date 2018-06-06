# Hashing function for dll name and function names for one of the later
# variants of PoSeidon.
#
# Reverse engineered from a sample binary.
#
# Author: Lloyd Macrohon <jl.macrohon@gmail.com>

import pefile
import os


__author__ = 'lmacrohon'

import pefile
import os


def uint64_t(n):
    """
    Because python uses arbitrary-precision integers, we need to bound it
    to uint64 to match the C implementation.
    """
    return n & 0xffffffffffffffff


def poseidon_hasher(data):
    """
    This is the PoSeidon hasher which is the same for both the dll and
    function name. The dll name version differs by normalizing the name
    first. It ensures it's in the printable range (at least ' ' or 0x20).

    Update: after reverse engineering the hash function and a a little bit 
    of research, it turns out that the hash function used is called the 
    Jenkins one_at a time hash function.

    https://en.wikipedia.org/wiki/Jenkins_hash_function  
    """
    n = 0
    for c in data:
        n += c
        n += n << 10
        n = (uint64_t(n) >> 6) ^ n
    n += n << 3
    n ^= uint64_t(n) >> 11
    n += n << 15
    return uint64_t(n)


def hash_dll_name(name):
    # it ensures character is in the printable range (at least a space)
    # but it doesn't bound it at the upper end though.
    name = [c | ord(' ') if c - ord('A') <= 25 else c for c in map(ord, name)]
    return poseidon_hasher(name)


def hash_function_name(name):
    return poseidon_hasher(map(ord, name))


if __name__ == '__main__':
    dlls = ["kernel32.dll", "ntdll.dll", "advapi32.dll", "wininet.dll", "crypt32.dll",
            "iphlpapi.dll", "psapi.dll", "userenv.dll", ]
    with open('fn-hash.csv', 'w+t') as f:
        for dll in dlls:
            pe = pefile.PE(os.path.join(r'c:\windows\system32', dll))
            f.write("dll,export,dll-hash,export-hash\n")
            for exp in [e for e in pe.DIRECTORY_ENTRY_EXPORT.symbols if e.name]:
                f.write(("%s,%s,0x%x,0x%x\n" % (dll, exp.name.decode('ascii'), hash_dll_name(dll),
                                                hash_function_name(exp.name.decode('ascii')))))
