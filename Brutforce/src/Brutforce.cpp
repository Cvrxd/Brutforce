#include "Brutforce.h"

namespace brutforce
{
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

            DecryptorAes decryptor(pathToFile);
            if (!decryptor.isInitialized())
                return std::nullopt;

            if (!lenghtOfPassword)
            {
                size_t lenght{ 0 };
                while (true)
                {
                    if (Brutforce(decryptor, ++lenght, setOfCharacters, pathToLog))
                    {
                        ret = decryptor.getDecryptedData();
                        password = decryptor.getPassword();
                    }
                }
            }
            else
            {
                if (Brutforce(decryptor, lenghtOfPassword, setOfCharacters, pathToLog))
                {
                    ret = decryptor.getDecryptedData();
                    password = decryptor.getPassword();
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

    bool Brutforce(DecryptorAes& decryptor, int size_password, std::string_view setOfCharacters, std::string_view pathToLog)
    {
        bool cycle = true;
        bool founded = false;
        int size_chars = setOfCharacters.size();
        int* indexer = new int[size_password](0);

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

            decryptor.passwordToKey(str_bruteforce);

            if (!pathToLog.empty())
                tools::AppendToFile(pathToLog.data(), str_bruteforce);

            if (auto opt = decryptor.decrypt(); opt != std::nullopt)
            {
                delete[] indexer;
                return true;
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
            std::cout << "Unable to find password with lenght " << size_password << std::endl;

        delete[] indexer;
        return false;
    }
}