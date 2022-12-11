#pragma once

#include <windows.h>
#include <string>
#include <vector>
#include <exception>
#include <iostream>
#include <algorithm>

#include <openssl/evp.h>
#include <openssl/aes.h>
#include <openssl/sha.h>

#include "Tools.h"
#include "File.h"
#include "DecryptorAes.h"

class DecryptorAes;

namespace encrypt
{
    void EncryptAes     (const std::vector<unsigned char> plainText, std::string password, _Out_ std::vector<unsigned char>& chipherText);
    bool Encrypt        (std::string_view path, std::string_view pathToSave, std::string password);
    
}
