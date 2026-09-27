#include "vm/native_undefined.hpp"
#include <iostream>
#include <string>

int main()
{
    unsigned mode = 0;
    unsigned operands = 0;
    std::string encoded;
    while (std::cin >> mode >> operands >> encoded)
    {
        if (encoded.empty() || encoded.size() % 2 != 0)
            return 2;
        std::vector<uint8_t> bytes;
        for (size_t offset = 0; offset < encoded.size(); offset += 2)
            bytes.push_back(uint8_t(std::stoul(encoded.substr(offset, 2), nullptr, 16)));
        std::cout << chernobog::vm::native_undefined_encoding_supported(bytes, mode, operands)
                  << '\n';
    }
    return std::cin.eof() ? 0 : 3;
}
