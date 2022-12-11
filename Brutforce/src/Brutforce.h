#pragma once

#include <optional>

#include "Timer.h"
#include "DecryptorAes.h"
#include "Tools.h"

namespace brutforce
{
    std::optional<std::vector<unsigned char>> BrutforceDecrypt(std::string_view pathToFile, int lenghtOfPassword = 0, std::string_view setOfCharacters = "", std::string_view pathToLog = "");
    bool Brutforce(DecryptorAes& decryptor, int size_password, std::string_view setOfCharacters, std::string_view pathToLog);
}
