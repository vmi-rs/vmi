#include "enum_flags.h"

#include <cstdint>

namespace {

enum class flags : uint8_t {
    none                    = 0x00,
    first                   = 0x01,
    second                  = 0x02,
    high                    = 0x80,
};

SCFW_DEFINE_ENUM_FLAG_OPERATORS(flags);

constexpr bool
enum_flag_operators_work()
{
    flags value = flags::first | flags::second;
    value |= flags::high;
    value &= ~flags::second;

    if (!has_any(value, flags::first | flags::high)
        || has_any(value, flags::none)
        || !has_all(value, flags::first | flags::high)
        || has_all(value, flags::first | flags::second)
        || !has_all(value, flags::none)
        || (value & flags::high) != flags::high)
    {
        return false;
    }

    value ^= flags::first;

    return (value ^ flags::high) == flags::none
        && static_cast<uint8_t>(~flags::first) == 0xfe;
}

static_assert(enum_flag_operators_work());

} // namespace
