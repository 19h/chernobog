#include "mba_cobra.hpp"
namespace chernobog::mba_smt::cobra_backend
{
bool available() noexcept { return false; }
Outcome generate(const Term &, const Request &)
{
    Outcome result;
    result.status = Status::Unsupported;
    return result;
}
} // namespace chernobog::mba_smt::cobra_backend
