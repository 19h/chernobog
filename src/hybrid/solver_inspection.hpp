#pragma once
#include "../common/solver_evidence.hpp"
#include <string>

namespace chernobog::hybrid {
void solver_inspection_install(int64_t database);
void solver_inspection_remove(int64_t database);
void solver_inspection_begin(uint64_t function);
std::string solver_inspection_json(uint64_t function, bool state_only = false);
} // namespace chernobog::hybrid
