#include "solver_inspection.hpp"
#include "../common/inspection_json.hpp"
#include "../common/warn_off.h"
#include <pro.h>
#include <ida.hpp>
#include <bytes.hpp>
#include <funcs.hpp>
#include "../common/warn_on.h"
#include <array>
#include <deque>
#include <map>
#include <sstream>

namespace chernobog::hybrid
{
namespace
{
constexpr size_t function_limit = 16, record_limit = 128, byte_limit = 4u << 20;
struct FunctionLog
{
    uint64_t generation = 0;
    size_t omitted = 0, bytes = 0;
    std::vector<solver_evidence::Row> records;
};
struct DatabaseLog
{
    size_t bytes = 0, evicted_functions = 0;
    std::map<uint64_t, FunctionLog> functions;
    std::deque<uint64_t> order;
};
std::map<int64_t, DatabaseLog> databases;
uint64_t next_identity = 0;
uint64_t identity() { return next_identity == UINT64_MAX ? 0 : ++next_identity; }
std::string hex(uint64_t value)
{
    std::ostringstream out;
    out << "0x" << std::hex << value;
    return out.str();
}

FunctionLog &ensure(DatabaseLog &database, uint64_t function)
{
    auto found = database.functions.find(function);
    if (found != database.functions.end())
        return found->second;
    if (database.functions.size() == function_limit)
    {
        const auto oldest = database.order.front();
        database.order.pop_front();
        database.bytes -= database.functions.at(oldest).bytes;
        database.functions.erase(oldest);
        ++database.evicted_functions;
    }
    database.order.push_back(function);
    auto &log = database.functions[function];
    log.generation = identity();
    return log;
}

// This is a navigation guard for a historical query's originating instruction,
// not a proof that the current IR still has the recorded formula/assumptions.
std::string site_bytes(uint64_t site, uint64_t function)
{
    if (site == UINT64_MAX)
        return {};
    const auto *owner = get_func(ea_t(site));
    if (!owner || owner->start_ea != function || !is_code(get_flags(ea_t(site))))
        return {};
    const auto count = get_item_size(ea_t(site));
    if (count == 0 || count > 16)
        return {};
    std::string result;
    static const char digits[] = "0123456789abcdef";
    for (asize_t i = 0; i < count; ++i)
    {
        if (!is_loaded(ea_t(site + i)))
            return {};
        const auto value = get_byte(ea_t(site + i));
        result += digits[value >> 4];
        result += digits[value & 15];
    }
    return result;
}

class InspectionCollector final : public solver_evidence::Collector
{
  public:
    bool accepts(const solver_evidence::Origin &origin) override
    {
        auto found = databases.find(origin.database);
        if (origin.database != int64_t(get_dbctx_id()) || found == databases.end() ||
            origin.function == UINT64_MAX)
            return false;
        auto &log = ensure(found->second, origin.function);
        if (log.records.size() >= record_limit || found->second.bytes >= byte_limit)
        {
            ++log.omitted;
            return false;
        }
        return true;
    }
    void publish(const solver_evidence::Origin &origin, solver_evidence::Row row) override
    {
        auto &database = databases.at(origin.database);
        auto &log = ensure(database, origin.function);
        row["query_id"] = hex(identity());
        row["generation"] = hex(log.generation);
        row["function"] = hex(origin.function);
        row["site"] = hex(origin.site);
        row["phase"] = origin.phase;
        row["maturity"] = std::to_string(origin.maturity);
        if (origin.capture_revision && origin.transition_check)
        {
            row["capture_revision"] = hex(origin.capture_revision);
            row["run"] = hex(origin.run);
            row["seed"] = hex(origin.seed);
            row["sequence"] = hex(origin.sequence);
            row["transition_check"] = hex(origin.transition_check);
        }
        row["site_bytes"] = site_bytes(origin.site, origin.function);
        row["source_contract"] =
            "matching instruction bytes/owner permit navigation only; whole query applicability remains historical";
        size_t bytes = 0;
        for (const auto &field : row)
            bytes += field.first.size() + field.second.size();
        if (bytes > byte_limit - database.bytes)
        {
            ++log.omitted;
            return;
        }
        log.bytes += bytes;
        database.bytes += bytes;
        log.records.push_back(std::move(row));
    }
} collector;
} // namespace

void solver_inspection_install(int64_t database)
{
    databases.try_emplace(database);
    solver_evidence::collector = &collector;
}
void solver_inspection_remove(int64_t database)
{
    databases.erase(database);
    if (databases.empty())
        solver_evidence::collector = nullptr;
}
void solver_inspection_begin(uint64_t function)
{
    auto found = databases.find(int64_t(get_dbctx_id()));
    if (found == databases.end() || function == UINT64_MAX)
        return;
    auto &log = ensure(found->second, function);
    found->second.bytes -= log.bytes;
    log = FunctionLog{};
    log.generation = identity();
}

std::string solver_inspection_json(uint64_t function, bool state_only)
{
    const int64_t database = int64_t(get_dbctx_id());
    auto found = databases.find(database);
    const FunctionLog *log = nullptr;
    if (found != databases.end())
    {
        auto entry = found->second.functions.find(function);
        if (entry != found->second.functions.end())
            log = &entry->second;
    }
    std::ostringstream out;
    out << "{\"schema\":1,\"available\":" << (log ? "true" : "false")
        << ",\"database\":" << inspection_json_quote(std::to_string(database))
        << ",\"function\":" << inspection_json_quote(hex(function))
        << ",\"generation\":" << inspection_json_quote(hex(log ? log->generation : 0))
        << ",\"omitted\":" << (log ? log->omitted : 0) << ",\"evicted_functions\":"
        << (found != databases.end() ? found->second.evicted_functions : 0);
    std::vector<solver_evidence::Row> rows;
    if (log)
        for (const auto &record : log->records)
        {
            const auto bytes = site_bytes(std::stoull(record.at("site"), nullptr, 16), function);
            auto row =
                state_only ? solver_evidence::Row{{"query_id", record.at("query_id")}} : record;
            row["source_bytes_current"] =
                record.at("query_id") != "0x0" && !bytes.empty() && bytes == record.at("site_bytes")
                    ? "true"
                    : "false";
            rows.push_back(std::move(row));
        }
    inspection_json_rows(out, "records", rows);
    out << '}';
    return out.str();
}
} // namespace chernobog::hybrid
