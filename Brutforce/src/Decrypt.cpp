#include "Decrypt.h"

namespace decrypt
{
    bool DecryptAes(const std::vector<unsigned char>& encryptedText, std::string password, _Out_ std::vector<unsigned char>& decryptedText)
    {
        EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();

        unsigned char key[EVP_MAX_KEY_LENGTH];
        unsigned char iv[EVP_MAX_IV_LENGTH];

        tools::PasswordToKey(password, key, iv);

        if (!EVP_DecryptInit_ex(ctx, EVP_aes_128_cbc(), NULL, key, iv))
        {
            return false;
        }
        std::vector<unsigned char> chipherTextBuf(encryptedText.size() + AES_BLOCK_SIZE);
        int chipherTextSize = 0;
        if (!EVP_DecryptUpdate(ctx, &chipherTextBuf[0], &chipherTextSize, &encryptedText[0], encryptedText.size())) {
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

        decryptedText.swap(chipherTextBuf);

        EVP_CIPHER_CTX_free(ctx);

        return true;
    }

    std::optional<std::vector<unsigned char>> Decrypt(std::string_view path, std::string password)
    {
        if (path.empty())
            return std::nullopt;

        try
        {
            std::vector<unsigned char> encryptedText;
            if (!tools::ReadFile(path.data(), encryptedText))
                return std::nullopt;

            std::vector<unsigned char> decryptedText;

            //Cut hash 
            std::vector<unsigned char> hash;
            int defautHashSize{ 32 };
            hash.reserve(defautHashSize);
            std::copy(encryptedText.cend() - defautHashSize, encryptedText.cend(), std::back_inserter(hash));

            if (hash.size() != defautHashSize)
                return std::nullopt;

            encryptedText.erase(encryptedText.end() - defautHashSize, encryptedText.end());

            //Decrypt Aes
            if (DecryptAes(encryptedText, password, decryptedText))
            {
                std::vector<unsigned char> originalHash;
                tools::CalculateHash(decryptedText, originalHash);

                //Check hash
                if (originalHash == hash)
                    return decryptedText;
            }
        }
        catch (std::exception const&)
        {

        }
        return std::nullopt;
    }

}
