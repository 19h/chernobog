#include "ida.hpp"
#include "model.hpp"
#include "../../hybrid/rax_loader.hpp"
#include "../../common/inspection_json.hpp"
#include "../../common/warn_off.h"
#include <pro.h>
#include <bytes.hpp>
#include <funcs.hpp>
#include <idp.hpp>
#include <kernwin.hpp>
#include <loader.hpp>
#include <nalt.hpp>
#include "../../common/warn_on.h"
#include <charconv>
#include <future>
#include <map>
#include <memory>
#include <sstream>
#include <stdexcept>

namespace chernobog::warbird
{
namespace
{
struct Session
{
    int64_t database = -1;
    uint64_t revision = 0;
    uint64_t ticket = 0;
    uint64_t function = 0;
    std::shared_ptr<std::atomic_bool> stop;
    std::future<Report> future;
    std::string result;
};
std::map<int64_t, std::unique_ptr<Session>> sessions;
ssize_t idaapi changed(void *data, int, va_list)
{
    auto &s = *static_cast<Session *>(data);
    if (get_dbctx_id() == s.database)
    {
        ++s.revision;
        if (s.stop)
            s.stop->store(true);
        s.result.clear();
    }
    return 0;
}
Session *current()
{
    auto found = sessions.find(get_dbctx_id());
    return found == sessions.end() ? nullptr : found->second.get();
}
std::string error(const std::string &why)
{
    return "{\"ok\":false,\"reason\":" + inspection_json_quote(why) + "}";
}
bool active()
{
    for (const auto &[id, s] : sessions)
        if (s->future.valid() &&
            s->future.wait_for(std::chrono::seconds(0)) != std::future_status::ready)
            return true;
    return false;
}
struct ImportCapture
{
    std::vector<ImportBinding> bindings;
    std::string module;
    bool failed = false;
};
int idaapi capture_import(ea_t ea, const char *name, uval_t ordinal, void *opaque)
{
    auto &capture = *static_cast<ImportCapture *>(opaque);
    try
    {
        if (capture.bindings.size() >= 4096)
            throw std::runtime_error("import count quota");
        size_t length = 0;
        if (name)
            while (length <= 512 && name[length])
                ++length;
        capture.bindings.push_back(
            {ea, capture.module, name ? std::string(name, length) : "", ordinal});
        return 1;
    }
    catch (...)
    {
        capture.failed = true;
        return 0;
    }
}
std::vector<ImportBinding> capture_imports(const hybrid::ProgramImage &image)
{
    if (!is_main_thread())
        throw std::runtime_error("import capture requires main thread");
    const auto count = get_import_module_qty();
    if (count > 256)
        throw std::runtime_error("import module quota");
    ImportCapture capture;
    for (unsigned n = 0; n < count; ++n)
    {
        qstring module;
        if (!get_import_module_name(&module, int(n)) || module.empty() || module.length() > 512)
            throw std::runtime_error("invalid import module name");
        capture.module = module.c_str();
        if (enum_import_names(int(n), capture_import, &capture) != 1 || capture.failed)
            throw std::runtime_error("import enumeration incomplete");
    }
    validate_imports(image, capture.bindings);
    return std::move(capture.bindings);
}
}
void install(int64_t database)
{
    if (sessions.count(database))
        return;
    auto s = std::make_unique<Session>();
    s->database = database;
    hook_to_notification_point(HT_IDB, changed, s.get());
    sessions.emplace(database, std::move(s));
}
void uninstall(int64_t database)
{
    auto it = sessions.find(database);
    if (it == sessions.end())
        return;
    unhook_from_notification_point(HT_IDB, changed, it->second.get());
    if (it->second->stop)
        it->second->stop->store(true);
    // std::future joins before immutable snapshots are destroyed. The worker
    // owns no IDA object and performs no main-thread callbacks while joining.
    sessions.erase(it);
}
std::string start(uint64_t function, unsigned profile, const std::string &key_text)
try
{
    auto *s = current();
    if (!is_main_thread())
        return error("main thread required");
    if (!s)
        return error("no database session");
    if (active())
        return error("another WARBIRD job is active");
    if (!hybrid::rax_load())
        return error("RAX disabled or unavailable");
    if (profile >= profiles().size())
        return error("invalid profile");
    auto *fn = get_func(function);
    if (!fn)
        return error("select an existing function");
    uint64_t key = 0;
    std::string text = key_text;
    if (text.size() > 2 && text[0] == '0' && (text[1] == 'x' || text[1] == 'X'))
        text.erase(0, 2);
    const auto parsed = std::from_chars(text.data(), text.data() + text.size(), key, 16);
    if (parsed.ec != std::errc{} || parsed.ptr != text.data() + text.size() || text.empty())
        return error("key must be an unsigned 64-bit hexadecimal value");
    auto image = std::make_shared<hybrid::ProgramImage>();
    hybrid::HybridConfig config;
    config.max_image_bytes = 64ULL * 1024 * 1024;
    const auto snapshot = hybrid::hybrid_snapshot_image(*image, config);
    if (!snapshot.complete)
        return error(snapshot.diagnostic);
    auto admission = admit(*image, get_imagebase(), profiles()[profile]);
    if (!admission.valid())
        return error(admission.rejection);
    bind_imports(*image, admission, capture_imports(*image));
    Lease lease;
    lease.database = s->database;
    lease.generation = image->generation;
    lease.image_hash = image->content_hash;
    lease.base = get_imagebase();
    lease.key = key;
    lease.revision = s->revision;
    s->function = fn->start_ea;
    s->stop = std::make_shared<std::atomic_bool>(false);
    s->result.clear();
    ++s->ticket;
    s->future = std::async(std::launch::async, [image, admission, lease, stop = s->stop]
                           { return explore(*image, admission, lease, Limits{}, *stop); });
    return "{\"ok\":true,\"state\":\"running\",\"ticket\":" + std::to_string(s->ticket) + "}";
}
catch (const std::exception &e)
{
    return error(e.what());
}

std::string poll()
try
{
    auto *s = current();
    if (!is_main_thread())
        return error("main thread required");
    if (!s)
        return error("no database session");
    if (!s->future.valid())
        return s->result.empty() ? error("no result") : s->result;
    if (s->future.wait_for(std::chrono::seconds(0)) != std::future_status::ready)
        return "{\"ok\":true,\"state\":\"running\"}";
    Report report = s->future.get();
    hybrid::ProgramImage now;
    hybrid::HybridConfig config;
    config.max_image_bytes = 64ULL * 1024 * 1024;
    const auto snapshot = hybrid::hybrid_snapshot_image(now, config);
    if (!snapshot.complete)
        return s->result = error("freshness snapshot incomplete");
    if (report.lease.database != s->database || report.lease.revision != s->revision ||
        report.lease.base != get_imagebase() || report.lease.image_hash != now.content_hash ||
        !dependencies_match(now, report.dependencies) || report.imports != capture_imports(now))
        return s->result = error("stale result discarded");
    return s->result = report.json();
}
catch (const std::exception &e)
{
    return error(e.what());
}

std::string cancel()
{
    auto *s = current();
    if (!is_main_thread())
        return error("main thread required");
    if (!s)
        return error("no database session");
    if (s->stop)
        s->stop->store(true);
    ++s->revision;
    s->result.clear();
    return "{\"ok\":true,\"state\":\"cancellation requested\"}";
}
std::string profile_json()
{
    std::ostringstream out;
    out << "[";
    for (size_t n = 0; n < profiles().size(); ++n)
    {
        if (n)
            out << ',';
        const auto &p = profiles()[n];
        out << "{\"index\":" << n << ",\"name\":" << inspection_json_quote(p.name)
            << ",\"key_count\":" << p.entry_keys.size() << ",\"keys\":[";
        for (size_t k = 0; k < p.entry_keys.size(); ++k)
        {
            if (k)
                out << ',';
            std::ostringstream key;
            key << "0x" << std::hex << p.entry_keys[k];
            out << inspection_json_quote(key.str());
        }
        out << "]}";
    }
    return out.str() + "]";
}
} // namespace chernobog::warbird
