#pragma once

#include <cstdint>
#include <initializer_list>
#include <optional>
#include <string_view>

namespace chernobog::arm64e
{

// Encodings follow Arm FEAT_PAuth and FEAT_BTI. Register 31 means SP for
// modifiers/bases and XZR for values; zero_modifier denotes architectural zero.
enum class Kind
{
    sign,
    authenticate,
    strip,
    generic,
    load,
    branch,
    call,
    ret,
    landing_pad
};
enum class Key : unsigned
{
    ia,
    ib,
    da,
    db,
    ga
};
struct Instruction
{
    Kind kind;
    Key key = Key::ia;
    unsigned destination = 0;
    unsigned source = 0;
    unsigned modifier = 0;
    bool zero_modifier = false;
    bool writeback = false;
    int64_t offset = 0;
    bool implicit = false;
};

inline std::optional<Instruction> decode(uint32_t word)
{
    if ((word & 0xFFFF0000U) == 0xDAC10000U)
    {
        const unsigned opcode = (word >> 10) & 63U;
        const unsigned rn = (word >> 5) & 31U;
        const unsigned rd = word & 31U;
        if (opcode < 16)
        {
            if (opcode >= 8 && rn != 31)
                return std::nullopt;
            return Instruction{(opcode & 4U) ? Kind::authenticate : Kind::sign,
                               Key(opcode & 3U),
                               rd,
                               rd,
                               rn,
                               opcode >= 8};
        }
        if ((opcode == 16 || opcode == 17) && rn == 31)
            return Instruction{Kind::strip, opcode == 16 ? Key::ia : Key::da, rd, rd};
        return std::nullopt;
    }
    if ((word & 0xFFE0FC00U) == 0x9AC03000U)
        return Instruction{Kind::generic, Key::ga, word & 31U, (word >> 5) & 31U,
                           (word >> 16) & 31U};
    if ((word & 0xFF200400U) == 0xF8200400U)
    {
        const unsigned imm10 = ((word >> 12) & 511U) | (((word >> 22) & 1U) << 9);
        const int64_t offset = (imm10 & 512U ? int64_t(imm10) - 1024 : int64_t(imm10)) * 8;
        const unsigned rt = word & 31U, rn = (word >> 5) & 31U;
        const bool writeback = (word & 0x800U) != 0;
        // Writeback overlap is architecturally constrained UNPREDICTABLE.
        if (writeback && rt == rn && rn != 31)
            return std::nullopt;
        return Instruction{
            Kind::load, (word & 0x800000U) ? Key::db : Key::da, rt, rn, 0, true, writeback, offset};
    }
    if ((word & 0xFEDFF800U) == 0xD61F0800U)
    {
        const bool zero = (word & 0x01000000U) == 0;
        if (zero && (word & 31U) != 31)
            return std::nullopt;
        return Instruction{(word & 0x200000U) ? Kind::call : Kind::branch,
                           (word & 0x400U) ? Key::ib : Key::ia,
                           0,
                           (word >> 5) & 31U,
                           word & 31U,
                           zero};
    }
    if (word == 0xD65F0BFFU || word == 0xD65F0FFFU)
        return Instruction{Kind::ret, word == 0xD65F0BFFU ? Key::ia : Key::ib, 30, 30, 31};
    if ((word & 0xFFFFFF3FU) == 0xD503241FU)
        return Instruction{Kind::landing_pad, Key::ia, 0, 0, (word >> 6) & 3U};
    if (word == 0xD50320FFU)
        return Instruction{Kind::strip, Key::ia, 30, 30, 0, false, false, 0, true};
    for (unsigned bank = 0; bank < 2; ++bank)
    {
        if (word == 0xD503211FU + bank * 0x40U || word == 0xD503219FU + bank * 0x40U)
            return Instruction{word & 0x80U ? Kind::authenticate : Kind::sign,
                               Key(bank),
                               17,
                               17,
                               16,
                               false,
                               false,
                               0,
                               true};
        for (unsigned authenticate = 0; authenticate < 2; ++authenticate)
            for (unsigned stack = 0; stack < 2; ++stack)
                if (word == 0xD503231FU + bank * 0x40U + authenticate * 0x80U + stack * 0x20U)
                    return Instruction{authenticate ? Kind::authenticate : Kind::sign,
                                       Key(bank),
                                       30,
                                       30,
                                       31,
                                       stack == 0,
                                       false,
                                       0,
                                       true};
    }
    return std::nullopt;
}

inline bool instruction_key(Key key) { return key == Key::ia || key == Key::ib; }
inline bool same_strip_domain(Key left, Key right)
{
    return instruction_key(left) == instruction_key(right) && left != Key::ga && right != Key::ga;
}
inline const char *helper(Kind kind, Key key)
{
    if (kind == Kind::generic)
        return "__arm64e_pacga";
    if (kind == Kind::branch)
        return key == Key::ia   ? "__arm64e_auth_branch_ia"
               : key == Key::ib ? "__arm64e_auth_branch_ib"
                                : nullptr;
    if (kind == Kind::strip)
        return instruction_key(key) ? "__arm64e_xpaci" : "__arm64e_xpacd";
    if (kind != Kind::sign && kind != Kind::authenticate)
        return nullptr;
    constexpr const char *names[2][4] = {
        {"__arm64e_pacia", "__arm64e_pacib", "__arm64e_pacda", "__arm64e_pacdb"},
        {"__arm64e_autia", "__arm64e_autib", "__arm64e_autda", "__arm64e_autdb"}};
    return unsigned(key) >= 4 ? nullptr : names[kind == Kind::authenticate][unsigned(key)];
}

inline std::optional<Instruction> helper_instruction(std::string_view name)
{
    for (unsigned key = 0; key < 4; ++key)
        for (Kind kind : {Kind::sign, Kind::authenticate})
            if (name == helper(kind, Key(key)))
                return Instruction{kind, Key(key)};
    for (Key key : {Key::ia, Key::da})
        if (name == helper(Kind::strip, key))
            return Instruction{Kind::strip, key};
    for (Key key : {Key::ia, Key::ib})
        if (name == helper(Kind::branch, key))
            return Instruction{Kind::branch, key};
    if (name == helper(Kind::generic, Key::ga))
        return Instruction{Kind::generic, Key::ga};
    return std::nullopt;
}

} // namespace chernobog::arm64e
