#pragma once
#include <filesystem>
#include "Encrypt.h"

namespace fs = std::filesystem;

class DecryptorAes
{
public:
    using symbols_data      = std::vector<unsigned char>;
    using opt_symbols_data  = std::optional<symbols_data>;

    DecryptorAes (std::string_view pathToFile, unsigned int hashSize = 32);

    void passwordToKey(std::string password);
    opt_symbols_data decrypt();

    bool isInitialized() const;

    std::string_view getPassword();
    symbols_data const& getDecryptedData() const;

private:
    bool decryptAes();

private:
    bool m_isIntialized;

    symbols_data m_encryptedData;
    symbols_data m_decryptedData;
    symbols_data m_hash;

    std::string m_key;
    std::string m_iv;
    std::string m_password;

    unsigned int const m_hashSize;
};

