#include "Tools.h"
namespace tools
{
    bool PasswordToKey(std::string& password, _Out_ unsigned char* key, _Out_ unsigned char* iv)
    {
        const EVP_MD* dgst = EVP_get_digestbyname("md5");
        if (!dgst)
            return false;

        const unsigned char* salt = NULL;
        if (!EVP_BytesToKey(EVP_aes_128_cbc(), EVP_md5(), salt,
            reinterpret_cast<unsigned char*>(&password[0]),
            password.size(), 1, key, iv))
        {
            return false;
        }

        return true;
    }

    void CalculateHash(const std::vector<unsigned char>& data, _Out_ std::vector<unsigned char>& hash)
    {
        std::vector<unsigned char> hashTmp(SHA256_DIGEST_LENGTH);

        SHA256_CTX sha256;
        SHA256_Init(&sha256);
        SHA256_Update(&sha256, &data[0], data.size());
        SHA256_Final(&hashTmp[0], &sha256);

        hash.swap(hashTmp);
    }
}