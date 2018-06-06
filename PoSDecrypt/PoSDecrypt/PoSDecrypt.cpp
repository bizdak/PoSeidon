/*
Overview:

The PoSeidon malware contains embedded configuration (mostly C&C servers/urls).
This configuration is encrypted but the key is stored along with it. In sample seen,
immediately, before the encrypted data.

Note, the sample in the .idb, the encrypted data is stored in: .data:00406020
the key is stored immediately before that at: .data:00406018

Author: Lloyd Macrohon <jl.macrohon@gmail.com>
*/
#include "stdafx.h"
#include <Windows.h>
#include <stdint.h>
#include <vector>
#include <memory>
#include <stdarg.h>


inline void Throw(const char* fmt, ...)
{
	char buf[1024];
	va_list args;
	va_start(args, fmt);
	_vsnprintf_s(buf, sizeof(buf), _TRUNCATE, fmt, args);
	va_end(args);
	throw std::runtime_error(buf);
}

inline off_t FileSize(const char* filename)
{
	struct stat st;
	if (stat(filename, &st) == -1) 
		throw std::runtime_error("error getting filesize");
	return st.st_size;	
}

std::unique_ptr<FILE, decltype(&fclose)> Fopen(const char* name, const char* mode)
{
	FILE* fp = nullptr;
	errno_t err = 0;
	if ((err = fopen_s(&fp, name, mode)) != 0)
		Throw("unable to open file %s - %d", name, err);
	return std::unique_ptr<FILE, decltype(&fclose)>(fp, fclose);
}

void Pos_DecryptData(uint8_t* data, DWORD dataLen, uint8_t* key, DWORD keyLen)
{
	HCRYPTPROV hProv = 0;
	HCRYPTKEY hKey = 0;
	HCRYPTHASH hHash = 0;

	try {
		if (!CryptAcquireContext(&hProv, 0, 0, 1, CRYPT_VERIFYCONTEXT)) 
			Throw("CryptAcquireContext error: 0x%08x\n", GetLastError());

		// key derivation
		if (!CryptCreateHash(hProv, CALG_MD5, 0, 0, &hHash)) 
			Throw("CryptCreateHash error: 0x%08x\n", GetLastError());

		if (!CryptHashData(hHash, key, keyLen, 0)) 
			Throw("CryptHashData error: 0x%08x\n", GetLastError());

		int keySize = (0x28 << 16);
		if (!CryptDeriveKey(hProv, CALG_RC4, hHash, keySize | CRYPT_EXPORTABLE | CRYPT_NO_SALT, &hKey)) 
			Throw("CryptDeriveKey error: 0x%08x\n", GetLastError());

		// decrypt the data
		if (!CryptDecrypt(hKey, 0, 1, 0, data, &dataLen)) 
			Throw("CryptDecrypt error: 0x%08x\n", GetLastError());
	}
	catch (std::exception& e) {
		printf("Error: %s\n", e.what());
	}

	if (hHash)
		CryptDestroyHash(hHash), hHash = 0;
	if (hKey)
		CryptDestroyKey(hKey), hKey = 0;
	if (hProv)
		CryptReleaseContext(hProv, 0), hProv = 0;
}

uint8_t* LoadKey(const char* filename, std::vector<uint8_t>& buf)
{
	buf.resize(FileSize(filename));
	if (buf.size() == 0)
		Throw("key file is zero bytes");
	auto fp(Fopen(filename, "rb"));
	if (fread(&buf[0], buf.size(), 1, fp.get()) != 1)
		Throw("io error. unexpected number of bytes");
	return &buf[0];
}

int main(int argc, const char* argv[])
{
	// this key is embedded in the binary
	uint8_t embeddedKey[] = { 0xca, 0xdc, 0x47, 0xe3, 0x85, 0x94, 0xc0, 0xd9 };
	uint8_t* key = embeddedKey;
	int keyLen = sizeof(embeddedKey);
	std::vector<uint8_t> keyBuf;

	if (argc < 3) {
		printf("Usage:\n\tPosDecrypt <encryptedfile> <outputfile> [<encryptedkey>]\n");
		return EXIT_FAILURE;
	}

	const char* filename = argv[1];
	const char* outname = argv[2];
	if (argc > 3)
		key = LoadKey(argv[3], keyBuf);

	try {
		// load encrypted file
		std::vector<uint8_t> data(FileSize(filename));
		if (data.size() == 0) 
			Throw("input file is zero bytes");
		auto fp(Fopen(filename, "rb"));

		if (fread(&data[0], data.size(), 1, fp.get()) != 1)
			Throw("io error. unexpected number of bytes");

		// decrypt the data
		Pos_DecryptData(&data[0], data.size(), key, keyLen);

		// save decrypted data
		auto outfp(Fopen(outname, "wb"));
		if (fwrite(&data[0], data.size(), 1, outfp.get()) != 1)
			Throw("write failed");
		return EXIT_SUCCESS;
	}
	catch (std::exception& e) {
		printf("Error: %s\n", e.what());
	}

	return EXIT_FAILURE;
}


