#include "Brutforce.h"

int main(int argc, char* argv[])
{
    try
    {
        if (argc != 5)
        {
            std::cout << "Not enough arguments\n";
            return 1;
        }
        std::string pathToFile              = argv[0];
        std::string charactersSet           = argv[1];
        std::string pathToSaveDecryptedData = argv[2];
        std::string pathToSavePasswords     = argv[3];
        int lenghtOfPassword                = std::atoi(argv[4]);

        if (auto decriptionData = brutforce::BrutforceDecrypt(pathToFile, lenghtOfPassword, charactersSet, pathToSavePasswords); decriptionData != std::nullopt)
        {
            if (!tools::WriteFile(pathToSaveDecryptedData, decriptionData.value()))
                std::cout << "Unable to save decrypted data to file: " << pathToSaveDecryptedData << '\n';
        }
    }
    catch (std::exception const& ex)
    {
        std::cerr << "Unhandled exception: " << ex.what() << '\n';
    }
    system("pause");

    return 0;
}