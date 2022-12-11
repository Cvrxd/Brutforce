#pragma once
#include <vector>
#include <string>
#include <fstream>

namespace tools
{
    bool ReadFile       (const std::string& filePath, std::vector<unsigned char>& buf);
    bool WriteFile      (const std::string& filePath, const std::vector<unsigned char>& buf);
    bool AppendToFile   (const std::string& filePath, const std::vector<unsigned char>& buf);
    bool AppendToFile   (const std::string& filePath, std::string_view data);
}
