#pragma once
#include <cstdint>
#include <string>
namespace chernobog::warbird
{
void install(int64_t database);
void uninstall(int64_t database);
std::string start(uint64_t function, unsigned profile, const std::string &key);
std::string poll();
std::string cancel();
std::string profile_json();
}
