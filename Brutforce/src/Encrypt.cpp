#include "Encrypt.h"

namespace encrypt
{
    void EncryptAes(const std::vector<unsigned char> plainText, std::string password, _Out_ std::vector<unsigned char>& chipherText)
    {
        EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();

        unsigned char key[EVP_MAX_KEY_LENGTH];
        unsigned char iv[EVP_MAX_IV_LENGTH];

        tools::PasswordToKey(password, key, iv);
        if (!EVP_EncryptInit_ex(ctx, EVP_aes_128_cbc(), NULL, key, iv))
        {
            throw std::runtime_error("EncryptInit error");
        }
        std::vector<unsigned char> chipherTextBuf(plainText.size() + AES_BLOCK_SIZE);
        int chipherTextSize = 0;
        if (!EVP_EncryptUpdate(ctx, &chipherTextBuf[0], &chipherTextSize, &plainText[0], plainText.size())) {
            EVP_CIPHER_CTX_free(ctx);
            throw std::runtime_error("Encrypt error");
        }

        int lastPartLen = 0;
        if (!EVP_EncryptFinal_ex(ctx, &chipherTextBuf[0] + chipherTextSize, &lastPartLen)) {
            EVP_CIPHER_CTX_free(ctx);
            throw std::runtime_error("EncryptFinal error");
        }
        chipherTextSize += lastPartLen;
        chipherTextBuf.erase(chipherTextBuf.begin() + chipherTextSize, chipherTextBuf.end());

        chipherText.swap(chipherTextBuf);

        EVP_CIPHER_CTX_free(ctx);
    }

    bool Encrypt(std::string_view path, std::string_view pathToSave, std::string password)
    {
        if (pathToSave.empty())
            return false;

        std::vector<unsigned char> plainText;

        if (!tools::ReadFile(path.data(), plainText))
            return false;

        std::vector<unsigned char> hash;
        tools::CalculateHash(plainText, hash);

        std::vector<unsigned char> chipherText;
        EncryptAes(plainText, password, chipherText);

        if(!tools::WriteFile(pathToSave.data(), chipherText))
            return false;

        if(!tools::AppendToFile(pathToSave.data(), hash))
            return false;

        return true;
    }

}