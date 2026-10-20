#include <cobra/core/Budget.h>
#include <cobra/core/Expr.h>
#include <cstdio>
#include <optional>
#include <stdexcept>

namespace
{
int failures = 0;
void check(bool value, const char *message)
{
    if (!value)
    {
        std::fprintf(stderr, "FAIL: %s\n", message);
        ++failures;
    }
}
template <class Function> void exhausted(Function function, cobra::budget::Reason reason)
{
    bool rejected = false;
    try
    {
        function();
    }
    catch (const cobra::budget::Exhausted &error)
    {
        rejected = error.reason == reason;
    }
    check(rejected, "expected exhaustion reason");
}
}
int main()
{
    using namespace cobra;
    using namespace cobra::budget;
    auto time = Clock::time_point{};
    auto ledger = std::make_shared<Ledger>(4096);
    std::optional<BudgetVector<uint64_t>> retained;
    {
        Scope scope({time + std::chrono::milliseconds(100), {}, [&] { return time; }, ledger});
        BudgetVector<uint64_t> values(128, 3);
        check(ledger->live == 1024, "vector payload accounted exactly");
        exhausted([&] { values.resize(4096); }, Reason::Allocation);
        check(ledger->live == 1024 && values.size() == 128,
              "failed growth preserves ledger and container");
        {
            auto expression = Expr::Add(Expr::Variable(0), Expr::Constant(1));
            check(ledger->live > 1024, "AST payload and children accounted");
        }
        check(ledger->live == 1024, "AST destruction releases accounting");
        auto *parent = current;
        {
            Scope child({time + std::chrono::seconds(1), {}, {}, std::make_shared<Ledger>(1)});
            check(current->deadline == parent->deadline && current->ledger == ledger,
                  "nested scope inherits earlier deadline and shared ledger");
            time += std::chrono::milliseconds(100);
            exhausted([] { Checkpoint(true); }, Reason::Deadline);
        }
        check(current == parent, "nested exhaustion restores parent context");
        time = Clock::time_point{};
        retained.emplace(std::move(values));
    }
    check(current == nullptr && ledger->live == 1024,
          "returned container retains allocation owner");
    retained.reset();
    check(ledger->live == 0 && ledger->peak <= ledger->limit,
          "cleanup outside scope balances ledger");
    {
        Scope scope({Clock::time_point::max(), [] { return true; }, {}, ledger});
        exhausted([] { Checkpoint(true); }, Reason::Cancellation);
    }
    {
        Scope scope({Clock::time_point::max(),
                     []() -> bool { throw std::runtime_error("callback"); },
                     {},
                     ledger});
        exhausted([] { Checkpoint(true); }, Reason::Callback);
    }
    exhausted([] { CheckedProduct(SIZE_MAX, 2); }, Reason::Allocation);
    check(current == nullptr && ledger->live == 0, "all exits restore scope and ledger");
    std::printf("CoBRA budget failures: %d\n", failures);
    return failures != 0;
}
