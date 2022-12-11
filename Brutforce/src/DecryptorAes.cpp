#include "DecryptorAes.h"

DecryptorAes::DecryptorAes(std::string_view pathToFile, unsigned int hashSize)
    : m_hashSize        (hashSize)
    , m_isIntialized    (false)
{
    if (fs::exists(pathToFile))
    {
        if (!tools::ReadFile(pathToFile.data(), m_encryptedData))
            m_encryptedData.clear();
        else
        {
            m_hash.reserve(m_hashSize);
            std::copy(m_encryptedData.cend() - m_hashSize, m_encryptedData.cend(), std::back_inserter(m_hash));
            m_isIntialized = true;
        }
    }
}

void DecryptorAes::passwordToKey(std::string password)
{
    const EVP_MD* dgst = EVP_get_digestbyname("md5");
    if (!dgst)
    {
        throw std::runtime_error("no such digest");
    }
    const unsigned char* salt = NULL;
    if (!EVP_BytesToKey(EVP_aes_128_cbc(), EVP_md5(), salt,
        reinterpret_cast<unsigned char*>(&password[0]),
        password.size(), 1, reinterpret_cast<unsigned char*>(&m_key[0]), reinterpret_cast<unsigned char*>(&m_iv[0])))
    {
        throw std::runtime_error("EVP_BytesToKey failed");
    }
    m_password = password;
}


DecryptorAes::opt_symbols_data DecryptorAes::decrypt()
{
    opt_symbols_data ret = std::nullopt;
    try
    {
        if (decryptAes())
        {
            symbols_data originalHash;
            tools::CalculateHash(m_decryptedData, originalHash);
            if (originalHash == m_hash)
                ret = m_decryptedData;
        }
    }
    catch (const std::exception&)
    {

    }
    return ret;
}

bool DecryptorAes::isInitialized() const
{
    return m_isIntialized;
}

std::string_view DecryptorAes::getPassword()
{
    return m_password;
}

DecryptorAes::symbols_data const& DecryptorAes::getDecryptedData() const
{
    return m_decryptedData;
}

bool DecryptorAes::decryptAes()
{
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!EVP_DecryptInit_ex(ctx, EVP_aes_128_cbc(), NULL, reinterpret_cast<unsigned char*>(&m_key[0]), reinterpret_cast<unsigned char*>(&m_iv[0])))
    {
        return false;
    }
    std::vector<unsigned char> chipherTextBuf(m_encryptedData.size() + AES_BLOCK_SIZE);
    int chipherTextSize = 0;
    if (!EVP_DecryptUpdate(ctx, &chipherTextBuf[0], &chipherTextSize, &m_encryptedData[0], m_encryptedData.size())) {
        EVP_CIPHER_CTX_free(ctx);
        return false;
    }

    int lastPartLen = 0;
    if (!EVP_DecryptFinal_ex(ctx, &chipherTextBuf[0] + chipherTextSize, &lastPartLen)) {
        EVP_CIPHER_CTX_free(ctx);
        return false;
    }
    chipherTextSize += lastPartLen;
    chipherTextBuf.erase(chipherTextBuf.begin() + chipherTextSize, chipherTextBuf.end());

    m_decryptedData.swap(chipherTextBuf);

    EVP_CIPHER_CTX_free(ctx);

    return true;
}
