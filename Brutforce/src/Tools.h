#pragma once
#include <string>
#include <vector>

#include <openssl/evp.h>
#include <openssl/aes.h>
#include <openssl/sha.h>

namespace tools
{
    bool PasswordToKey(std::string& password, _Out_ unsigned char* key, _Out_ unsigned char* iv);
    void CalculateHash(const std::vector<unsigned char>& data, _Out_ std::vector<unsigned char>& hash);
}
