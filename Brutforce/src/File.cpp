#include "File.h"

namespace tools
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
}