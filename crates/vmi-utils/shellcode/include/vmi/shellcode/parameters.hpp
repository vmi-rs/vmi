#pragma once

#include <cstdint>

namespace sc {
namespace vmi {

//
// Guest-side reader for the host's `ParameterWriter`.
//

class parameter_reader {
public:
    explicit
    parameter_reader(
        void* data
        )
        : position_{ static_cast<uint8_t*>(data) }
    {
    }

    int8_t read_int8() { return read<int8_t>(); }
    uint8_t read_uint8() { return read<uint8_t>(); }
    int16_t read_int16() { return read<int16_t>(); }
    uint16_t read_uint16() { return read<uint16_t>(); }
    int32_t read_int32() { return read<int32_t>(); }
    uint32_t read_uint32() { return read<uint32_t>(); }
    int64_t read_int64() { return read<int64_t>(); }
    uint64_t read_uint64() { return read<uint64_t>(); }

    char*
    read_string()
    {
        auto* value = reinterpret_cast<char*>(position_);
        auto* end = value;

        while (*end != '\0')
        {
            ++end;
        }

        position_ = reinterpret_cast<uint8_t*>(end + 1);
        return value;
    }

    wchar_t*
    read_wstring()
    {
        auto* value = reinterpret_cast<wchar_t*>(position_);
        auto* end = value;

        while (*end != L'\0')
        {
            ++end;
        }

        position_ = reinterpret_cast<uint8_t*>(end + 1);
        return value;
    }

private:
    template <typename T>
    T
    read()
    {
        const auto value = *reinterpret_cast<T*>(position_);
        position_ += sizeof(T);
        return value;
    }

    uint8_t* position_;
};

} // namespace vmi
} // namespace sc
