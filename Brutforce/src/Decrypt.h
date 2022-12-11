#pragma once
#include <vector>
#include <optional>
#include <string>

#include <openssl/evp.h>
#include <openssl/aes.h>
#include <openssl/sha.h>

#include "Tools.h"
#include "File.h"

namespace decrypt
{
    bool DecryptAes(const std::vector<unsigned char>& encryptedText, std::string password, _Out_ std::vector<unsigned char>& decryptedText);
    std::optional<std::vector<unsigned char>> Decrypt(std::string_view path, std::string password);
}
