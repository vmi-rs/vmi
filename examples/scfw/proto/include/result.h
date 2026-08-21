#pragma once

#include <cstdint>
#include <concepts>
#include <type_traits>

namespace sc {
namespace proto {

//
// Marks types that may be used as protocol error codes.
//

template <typename T>
struct is_error_code : std::false_type {};

template <>
struct is_error_code<uint8_t> : std::true_type {};

//
// Accepts explicitly enabled error-code types represented by uint8_t.
//

template <typename T>
concept error_code =
    is_error_code<std::remove_cvref_t<T>>::value
    && (
        std::same_as<std::remove_cvref_t<T>, uint8_t>
        || (
            std::is_enum_v<std::remove_cvref_t<T>>
            && std::same_as<
                std::underlying_type_t<std::remove_cvref_t<T>>,
                uint8_t
            >
        )
    );

//
// Accepts non-boolean native error-code types that fit in a bridge value.
//

template <typename T>
concept native_error_code =
    std::integral<std::remove_cvref_t<T>>
    && !std::same_as<std::remove_cvref_t<T>, bool>
    && sizeof(std::remove_cvref_t<T>) <= sizeof(uintptr_t);

namespace detail {

    //
    // Zero-extends native error codes without changing their original bit pattern.
    //

    template <native_error_code Code>
    [[nodiscard]]
    constexpr uintptr_t
    normalize_native_code(Code code) noexcept
    {
        using unsigned_type =
            std::make_unsigned_t<std::remove_cvref_t<Code>>;

        return static_cast<uintptr_t>(static_cast<unsigned_type>(code));
    }

} // namespace detail

//
// Couples a protocol error code with optional native error information.
//

template <error_code Code>
struct failure {
    template <native_error_code NativeCode = uintptr_t>
    explicit
    constexpr
    failure(
        Code code,
        NativeCode native_code = {}
        ) noexcept
        : code{ code }
        , native_code{ detail::normalize_native_code(native_code) }
    {
    }

    Code code;
    uintptr_t native_code;
};

enum class status : uint8_t {
    success                 = 0x00,
    waiting                 = 0x01,
    invalid_parameters      = 0xfd,
    operation_failed        = 0xfe,
    aborted                 = 0xff,
};

//
// Represents the terminal result reported to the bridge host.
//

template <typename Stage>
struct result {
    [[nodiscard]]
    static
    constexpr result
    success(
        Stage stage
        ) noexcept
    {
        return result(stage, status::success, 0, 0);
    }

    template <error_code Code>
    [[nodiscard]]
    static
    constexpr result
    invalid_parameters(
        Stage stage,
        failure<Code> error
        ) noexcept
    {
        return result(
            stage,
            status::invalid_parameters,
            static_cast<uint8_t>(error.code),
            error.native_code
            );
    }

    template <error_code Code>
    [[nodiscard]]
    static
    constexpr result
    operation_failed(
        Stage stage,
        failure<Code> error
        ) noexcept
    {
        return result(
            stage,
            status::operation_failed,
            static_cast<uint8_t>(error.code),
            error.native_code
            );
    }

    [[nodiscard]]
    static
    constexpr result
    aborted(
        Stage stage
        ) noexcept
    {
        return result(stage, status::aborted, 0, 0);
    }

    [[nodiscard]]
    constexpr uintptr_t
    packed_status() const noexcept
    {
        return static_cast<uintptr_t>(stage_)
            | static_cast<uintptr_t>(status_) << 8
            | static_cast<uintptr_t>(code_) << 16;
    }

    [[nodiscard]]
    constexpr uintptr_t
    native_code() const noexcept
    {
        return native_code_;
    }

private:
    constexpr
    result(
        Stage stage,
        status status,
        uint8_t code,
        uintptr_t native_code
        ) noexcept
        : stage_{ stage }
        , status_{ status }
        , code_{ code }
        , native_code_{ native_code }
    {
    }

    Stage stage_;
    status status_;
    uint8_t code_;
    uintptr_t native_code_;
};

} // namespace proto
} // namespace sc
