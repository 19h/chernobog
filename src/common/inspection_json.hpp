#pragma once
#include <map>
#include <ostream>
#include <string>
#include <vector>

namespace chernobog
{
// Inspection producers supply ASCII labels and numeric/byte encodings. This
// does not silently claim arbitrary Unicode or raw diagnostic serialization.
inline std::string inspection_json_quote(const std::string &text)
{
    std::string out = "\"";
    for (unsigned char ch : text)
    {
        if (ch == '"' || ch == '\\')
            out += '\\';
        if (ch < 32)
        {
            static const char digits[] = "0123456789abcdef";
            out += "\\u00";
            out += digits[ch >> 4];
            out += digits[ch & 15];
            continue;
        }
        if (ch >= 127)
        {
            out += '?';
            continue;
        }
        out += char(ch);
    }
    return out + '"';
}

inline void inspection_json_rows(std::ostream &out, const char *name,
                                 const std::vector<std::map<std::string, std::string>> &items)
{
    out << ',' << inspection_json_quote(name) << ":[";
    bool first = true;
    for (const auto &item : items)
    {
        if (!first)
            out << ',';
        first = false;
        out << '{';
        bool field = true;
        for (const auto &pair : item)
        {
            if (!field)
                out << ',';
            field = false;
            out << inspection_json_quote(pair.first) << ':' << inspection_json_quote(pair.second);
        }
        out << '}';
    }
    out << ']';
}
} // namespace chernobog
