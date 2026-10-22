#include "common/arm64e.h"
#include "common/arm64_branch.h"

#include <cstdlib>
#include <iostream>

using namespace chernobog::arm64e;
static void require(bool value, const char *message)
{
    if (!value)
    {
        std::cerr << message << '\n';
        std::exit(1);
    }
}
int main()
{
    // Golden instruction words assembled independently by LLVM's AArch64
    // assembler. Vary every encoded register and both key/address domains.
    for (unsigned op = 0; op < 16; ++op)
        for (unsigned rd = 0; rd < 32; ++rd)
            for (unsigned rn = 0; rn < 32; ++rn)
            {
                const uint32_t word = 0xDAC10000U | op << 10 | rn << 5 | rd;
                const auto p = decode(word);
                if (op >= 8 && rn != 31)
                    require(!p, "reserved zero-modifier encoding");
                else
                    require(p && p->key == Key(op & 3U) && p->destination == rd &&
                                p->source == rd && p->modifier == rn &&
                                p->zero_modifier == (op >= 8) &&
                                p->kind == ((op & 4U) ? Kind::authenticate : Kind::sign),
                            "PAC/AUT fields");
            }
    for (unsigned key = 0; key < 2; ++key)
        for (unsigned rd = 0; rd < 32; ++rd)
            for (unsigned rn = 0; rn < 32; ++rn)
            {
                const auto p = decode(0xDAC14000U | key << 10 | rn << 5 | rd);
                require(bool(p) == (rn == 31), "XPAC reserved field");
                if (p)
                    require(p->kind == Kind::strip && p->destination == rd &&
                                p->key == (key ? Key::da : Key::ia),
                            "XPAC domain");
            }
    for (bool key_b : {false, true})
        for (bool writeback : {false, true})
            for (int scaled : {-512, -1, 0, 1, 511})
            {
                const uint32_t immediate = unsigned(scaled) & 1023U;
                const uint32_t word = 0xF8200400U | (key_b ? 0x800000U : 0) |
                                      ((immediate >> 9) << 22) | ((immediate & 511U) << 12) |
                                      (writeback ? 0x800U : 0) | (9U << 5) | 8U;
                const auto p = decode(word);
                require(p && p->kind == Kind::load && p->offset == int64_t(scaled) * 8 &&
                            p->key == (key_b ? Key::db : Key::da) && p->writeback == writeback &&
                            p->source == 9 && p->destination == 8,
                        "authenticated load fields");
            }
    require(!decode(0xF8200D08U), "writeback register overlap rejected");
    for (uint32_t word : {0xD71F0911U, 0xD71F0D11U, 0xD61F091FU, 0xD61F0D1FU, 0xD73F0911U,
                          0xD73F0D11U, 0xD63F091FU, 0xD63F0D1FU})
    {
        const auto p = decode(word);
        const auto transfer = chernobog::arm64_branch::decode_indirect(word);
        require(p && transfer && transfer->authenticated && p->source == 8 &&
                    p->key == ((word & 0x400U) ? Key::ib : Key::ia) &&
                    p->kind == (transfer->call ? Kind::call : Kind::branch),
                "all authenticated transfers");
    }
    for (uint32_t word :
         {0xD503211FU, 0xD503215FU, 0xD503219FU, 0xD50321DFU, 0xD503231FU, 0xD503233FU, 0xD503235FU,
          0xD503237FU, 0xD503239FU, 0xD50323BFU, 0xD50323DFU, 0xD50323FFU, 0xD50320FFU})
        require(decode(word) && decode(word)->implicit, "PAuth hints");
    for (unsigned kind = 0; kind < 4; ++kind)
    {
        const auto p = decode(0xD503241FU | kind << 6);
        require(p && p->kind == Kind::landing_pad && p->modifier == kind, "BTI class");
    }
    require(decode(0x9AC23020U)->kind == Kind::generic && decode(0x9AC23020U)->source == 1 &&
                decode(0x9AC23020U)->modifier == 2,
            "PACGA operands");
    require(decode(0xD65F0BFFU)->key == Key::ia && decode(0xD65F0FFFU)->key == Key::ib,
            "authenticated returns");
    for (uint32_t word : {0xD503201FU, 0xD61F0920U, 0xDAC14800U, 0x5AC10020U, 0xF9400420U})
        require(!decode(word), "non-PAuth or reserved encoding");
    require(same_strip_domain(Key::ia, Key::ib) && !same_strip_domain(Key::ia, Key::da),
            "strip domains");
    std::cout << "ARM64e decoder tests passed\n";
}
