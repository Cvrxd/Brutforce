#include "Encrypt.h"

unsigned char key[EVP_MAX_KEY_LENGTH];
unsigned char iv[EVP_MAX_IV_LENGTH];

namespace crypt
{
    bool ReadFile(const std::string& filePath, std::vector<unsigned char>& buf)
    {
        bool ret = false;
        std::basic_fstream<unsigned char> fileStream(filePath, std::ios::binary | std::fstream::in);
        if (fileStream.is_open())
        {
            buf.clear();
            buf.insert(buf.begin(), std::istreambuf_iterator<unsigned char>(fileStream), std::istreambuf_iterator<unsigned char>());

            fileStream.close();
            ret = true;
        }
        return ret;
    }

    bool WriteFile(const std::string& filePath, const std::vector<unsigned char>& buf)
    {
        bool ret = false;
        std::basic_ofstream<unsigned char> fileStream(filePath, std::ios::binary);
        if (fileStream.is_open())
        {
            fileStream.write(&buf[0], buf.size());
            fileStream.close();
            bool ret = true;
        }
        return ret;
    }

    bool AppendToFile(const std::string& filePath, const std::vector<unsigned char>& buf)
    {
        bool ret = false;
        std::basic_ofstream<unsigned char> fileStream(filePath, std::ios::binary | std::ios::app);
        if (fileStream.is_open())
        {
            fileStream.write(&buf[0], buf.size());
            fileStream.close();
            ret = true;
        }
        return ret;
    }

    bool AppendToFile(const std::string& filePath, std::string_view data)
    {
        bool ret = false;
        std::basic_ofstream<unsigned char> fileStream(filePath, std::ios::app);
        if (fileStream.is_open())
        {
            fileStream << data.data() << '\n';
            fileStream.close();
            ret = true;
        }
        return ret;
    }

    void PasswordToKey(std::string& password)
    {
        const EVP_MD* dgst = EVP_get_digestbyname("md5");
        if (!dgst)
        {
            throw std::runtime_error("no such digest");
        }

        const unsigned char* salt = NULL;
        if (!EVP_BytesToKey(EVP_aes_128_cbc(), EVP_md5(), salt,
            reinterpret_cast<unsigned char*>(&password[0]),
            password.size(), 1, key, iv))
        {
            throw std::runtime_error("EVP_BytesToKey failed");
        }
    }

    void EncryptAes(const std::vector<unsigned char> plainText, std::vector<unsigned char>& chipherText)
    {
        EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
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

    void CalculateHash(const std::vector<unsigned char>& data, std::vector<unsigned char>& hash)
    {
        std::vector<unsigned char> hashTmp(SHA256_DIGEST_LENGTH);

        SHA256_CTX sha256;
        SHA256_Init(&sha256);
        SHA256_Update(&sha256, &data[0], data.size());
        SHA256_Final(&hashTmp[0], &sha256);

        hash.swap(hashTmp);
    }

    bool Encrypt(std::string_view path, std::string_view pathToSave)
    {
        if (pathToSave.empty())
            return false;

        std::vector<unsigned char> plainText;

        if (!ReadFile(path.data(), plainText))
            return false;

        std::vector<unsigned char> hash;
        CalculateHash(plainText, hash);

        std::vector<unsigned char> chipherText;
        EncryptAes(plainText, chipherText);

        if(!WriteFile(pathToSave.data(), chipherText))
            return false;

        if(!AppendToFile(pathToSave.data(), hash))
            return false;

        return true;
    }


    bool DecryptAes(const std::vector<unsigned char>& encryptedText, std::vector<unsigned char>& decryptedText)
    {
        EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
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

    std::optional<std::vector<unsigned char>> Decrypt(std::string_view path)
    {
        if(path.empty())
            return std::nullopt;

        try
        {
            std::vector<unsigned char> encryptedText;
            if (!ReadFile(path.data(), encryptedText))
                return std::nullopt;

            std::vector<unsigned char> decryptedText;

            //Cut hash 
            std::vector<unsigned char> hash;
            int defautHashSize{32};
            hash.reserve(defautHashSize);
            std::copy(encryptedText.cend() - defautHashSize, encryptedText.cend(), std::back_inserter(hash));

            if (hash.size() != defautHashSize)
                return std::nullopt;

            encryptedText.erase(encryptedText.end() - defautHashSize, encryptedText.end());

            //Decrypt Aes
            if (DecryptAes(encryptedText, decryptedText))
            {
                std::vector<unsigned char> originalHash;
                CalculateHash(decryptedText, originalHash);

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


    std::optional<std::vector<unsigned char>> BrutforceDecrypt(std::string_view pathToFile, int lenghtOfPassword, std::string_view setOfCharacters, std::string_view pathToLog)
    {
        Timer timer;
        std::optional<std::vector<unsigned char>> ret = std::nullopt;
        std::string password;

        try
        {
            if (pathToFile.empty())
            {
                std::cout << "Path to file is empty\n";
                return ret;
            }

            std::cout << "Please wait..." << std::endl;

            if (setOfCharacters.empty())
            {
                setOfCharacters = "qwertyuiopasdfghjklzxcvbnm0123456789";
                std::cout << "Given an empty set of characters. Using default: " << setOfCharacters << '\n';
            }

            if (!lenghtOfPassword)
            {
                size_t lenght{ 0 };
                while (true)
                {
                    if (auto opt = Brutforce(++lenght, pathToFile, setOfCharacters, pathToLog); opt != std::nullopt)
                    {
                        password = opt.value().second;
                        ret = opt.value().first;
                    }    
                }
            }
            else
            {
                if (auto opt = Brutforce(lenghtOfPassword, pathToFile, setOfCharacters, pathToLog); opt != std::nullopt)
                {
                    password = opt.value().second;
                    ret = opt.value().first;
                }
            }
          
        }
        catch (std::exception const&)
        {
        }

        if (ret == std::nullopt)
        {
            std::string lenght = lenghtOfPassword == 0 ? "not given lenght" : std::to_string(lenghtOfPassword) + " lenght";
            std::cout << "Unable to BrutforceDecrypt with " << lenght << " and characters set: " << setOfCharacters << '\n';
            std::cout << "Time elapsed: " << timer.elapsed();
        }
        else
        {
            std::cout << "Successfully decrypted file. Password to file: " << password << '\n';
            std::cout << "Time elapsed: " << timer.elapsed() << '\n';
        }

        return ret;
    }



    std::optional<std::pair<std::vector<unsigned char>, std::string>> Brutforce(int size_password, std::string_view pathToFile, std::string_view setOfCharacters, std::string_view pathToLog)
    {
        bool cycle      = true;
        bool founded    = false;
        int size_chars  = setOfCharacters.size();
        int* indexer    = new int[size_password] (0);

        std::string str_bruteforce;
        str_bruteforce.resize(size_password);

        std::fill_n(indexer, size_password, 0);

        while (true)
        {
            for (int i = size_password - 1; i >= 0; --i)
            {
                if (i != 0)
                {
                    if (indexer[i] == size_chars)
                    {
                        indexer[i] = 0;
                        indexer[i - 1]++;
                    }
                }
            }

            for (int i = 0; i < size_password; ++i) 
                str_bruteforce[i] = setOfCharacters[indexer[i]];

            cycle = true;

            PasswordToKey(str_bruteforce);

            if (!pathToLog.empty())
                AppendToFile(pathToLog.data(), str_bruteforce);

            if (auto opt = Decrypt(pathToFile); opt != std::nullopt)
            {
                delete[] indexer;
                return std::make_pair(opt.value(), str_bruteforce);
            } 

            if (!cycle) break;

            cycle = false;
            for (int i = 0; i < size_password; ++i) 
            {
                if (indexer[i] != size_chars - 1) 
                {
                    cycle = true;
                    break;
                }
            } 
            if (!cycle) break;

            indexer[size_password - 1]++;
        }
        if (!founded)
            std::cout << "Unable to find password with lenght "<< size_password << std::endl;

        delete[] indexer;
        return std::nullopt;
    }
}