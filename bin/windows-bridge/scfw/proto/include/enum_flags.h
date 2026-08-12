#pragma once

#include <type_traits>

//
// Adds BitmaskType operators and membership predicates to a scoped enum with
// an unsigned underlying type. Invoke this macro in the enum's namespace so
// argument-dependent lookup finds the generated functions.
//

#define SCFW_DEFINE_ENUM_FLAG_OPERATORS(Enum)                                 \
    static_assert(                                                            \
        std::is_scoped_enum_v<Enum>                                           \
        && std::is_unsigned_v<std::underlying_type_t<Enum>>,                  \
        "enum flag types must be scoped and use an unsigned underlying type"  \
        );                                                                    \
                                                                              \
    [[nodiscard]]                                                             \
    constexpr Enum                                                            \
    operator|(Enum lhs, Enum rhs) noexcept                                    \
    {                                                                         \
        using underlying_type = std::underlying_type_t<Enum>;                 \
        return static_cast<Enum>(                                             \
            static_cast<underlying_type>(lhs)                                 \
            | static_cast<underlying_type>(rhs)                               \
            );                                                                \
    }                                                                         \
                                                                              \
    constexpr Enum&                                                           \
    operator|=(Enum& lhs, Enum rhs) noexcept                                  \
    {                                                                         \
        return lhs = lhs | rhs;                                               \
    }                                                                         \
                                                                              \
    [[nodiscard]]                                                             \
    constexpr Enum                                                            \
    operator&(Enum lhs, Enum rhs) noexcept                                    \
    {                                                                         \
        using underlying_type = std::underlying_type_t<Enum>;                 \
        return static_cast<Enum>(                                             \
            static_cast<underlying_type>(lhs)                                 \
            & static_cast<underlying_type>(rhs)                               \
            );                                                                \
    }                                                                         \
                                                                              \
    constexpr Enum&                                                           \
    operator&=(Enum& lhs, Enum rhs) noexcept                                  \
    {                                                                         \
        return lhs = lhs & rhs;                                               \
    }                                                                         \
                                                                              \
    [[nodiscard]]                                                             \
    constexpr Enum                                                            \
    operator^(Enum lhs, Enum rhs) noexcept                                    \
    {                                                                         \
        using underlying_type = std::underlying_type_t<Enum>;                 \
        return static_cast<Enum>(                                             \
            static_cast<underlying_type>(lhs)                                 \
            ^ static_cast<underlying_type>(rhs)                               \
            );                                                                \
    }                                                                         \
                                                                              \
    constexpr Enum&                                                           \
    operator^=(Enum& lhs, Enum rhs) noexcept                                  \
    {                                                                         \
        return lhs = lhs ^ rhs;                                               \
    }                                                                         \
                                                                              \
    [[nodiscard]]                                                             \
    constexpr Enum                                                            \
    operator~(Enum value) noexcept                                            \
    {                                                                         \
        using underlying_type = std::underlying_type_t<Enum>;                 \
        return static_cast<Enum>(static_cast<underlying_type>(                \
            ~static_cast<underlying_type>(value)                              \
            ));                                                               \
    }                                                                         \
                                                                              \
    [[nodiscard]]                                                             \
    constexpr bool                                                            \
    has_any(Enum value, Enum mask) noexcept                                   \
    {                                                                         \
        return (value & mask) != static_cast<Enum>(0);                        \
    }                                                                         \
                                                                              \
    [[nodiscard]]                                                             \
    constexpr bool                                                            \
    has_all(Enum value, Enum mask) noexcept                                   \
    {                                                                         \
        return (value & mask) == mask;                                        \
    }
