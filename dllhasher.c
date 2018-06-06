/*
 * dll name and function hasher used by PoSeidon.
 *
 * reverse engineered from the binary. disassembly shows quite a few
 * multiplication and 32-bit manipulation, but really, this is a simple
 * bit-shifts, add and xor
 *
 * Lloyd Macrohon <jl.macrohon@gmail.com>
 *
 * gcc -o dllhasher dllhasher.c
 */

#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <inttypes.h>


uint64_t HashFunctionName(const char* name)
{
    uint64_t hash = 0;
    for (const char* p = name; *p; p++) {
        hash += *p;
        hash += (hash << 10);
        hash ^= (hash >> 6);
    }

    hash += (hash << 3);
    hash ^= (hash >> 11);
    hash += (hash << 15);
    return hash;
}

uint64_t HashDllName(const char* name)
{
    /* this is the same as HashFunctionName, except this one ensures
     * each character is at least 0x20 ' '. it does not check upper
     * bound though.
     *
     * Update: after reverse engineering this function and a little
     * bit of research, I've discovered that this function is the
     * Jenkins' one_at_a_time hash function.
     *
     * https://en.wikipedia.org/wiki/Jenkins_hash_function
     */
    uint64_t hash = 0;
    for (const char* p = name; *p; p++) {
        hash += *p - 'A' <= 25 ? (*p | ' ') : *p;
        hash += (hash << 10);
        hash ^= (hash >> 6);
    }

    hash += (hash << 3);
    hash ^= (hash >> 11);
    hash += (hash << 15);
    return hash;
}

int main(int argc, const char* argv[])
{
    if (argc > 1) 
        printf("%30s - 0x%" PRIx64 "i64\n", argv[1], HashDllName(argv[1]));

    if (argc > 2)
        printf("%30s - 0x%" PRIx64 "i64\n", argv[2], HashFunctionName(argv[2]));

    if (argc == 1) {
        printf("Usage: dllhasher <dllname> [<function-name>]\n\n"
               "e.g. dllhasher kernel32.dll AcquireSRWLockExclusive\n\n"
               "%30s - 0xd78acaf904a2cf36i64\n"
               "%30s - 0x5c6095cd9e0bc46fi64\n\n", "kernel32.dll", "AcquireSRWLockExclusive");
        return EXIT_FAILURE;
    }

    return EXIT_SUCCESS;
}

