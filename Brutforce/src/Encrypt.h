#pragma once

#include <windows.h>
#include <string>
#include <vector>
#include <fstream>
#include <exception>
#include <iostream>
#include <optional>
#include <algorithm>
#include <thread>

#include <openssl/evp.h>
#include <openssl/aes.h>
#include <openssl/sha.h>

#include "Timer.h"
#include "DecryptorAes.h"

class DecryptorAes;

namespace crypt
{
    //File tools
    bool ReadFile       (const std::string& filePath, std::vector<unsigned char>& buf);
    bool WriteFile      (const std::string& filePath, const std::vector<unsigned char>& buf);
    bool AppendToFile   (const std::string& filePath, const std::vector<unsigned char>& buf);
    bool AppendToFile   (const std::string& filePath, std::string_view data);

    //Hash and Key
    void PasswordToKey  (std::string& password);
    void CalculateHash  (const std::vector<unsigned char>& data, std::vector<unsigned char>& hash);

    //Encryption
    void EncryptAes     (const std::vector<unsigned char> plainText, std::vector<unsigned char>& chipherText);
    bool Encrypt        (std::string_view path, std::string_view pathToSave);

    //Decription
    bool DecryptAes(const std::vector<unsigned char>& encryptedText, std::vector<unsigned char>& decryptedText);
    std::optional<std::vector<unsigned char>> Decrypt(std::string_view path);
    
    //Brutforce decrtption
    std::optional<std::vector<unsigned char>> BrutforceDecrypt(std::string_view pathToFile, int lenghtOfPassword = 0, std::string_view setOfCharacters = "", std::string_view pathToLog = "");
    bool Brutforce(DecryptorAes& decryptor, int size_password, std::string_view setOfCharacters, std::string_view pathToLog);
}
