#pragma once

#include <cstdint>

namespace sc {
namespace proto {

class reader {
public:
    explicit
    reader(
        void* cursor
        )
        : cursor_(static_cast<uint8_t*>(cursor))
    {
    }

    int8_t next_int8() { return next<int8_t>(); }
    uint8_t next_uint8() { return next<uint8_t>(); }
    int16_t next_int16() { return next<int16_t>(); }
    uint16_t next_uint16() { return next<uint16_t>(); }
    int32_t next_int32() { return next<int32_t>(); }
    uint32_t next_uint32() { return next<uint32_t>(); }
    int64_t next_int64() { return next<int64_t>(); }
    uint64_t next_uint64() { return next<uint64_t>(); }

    char*
    next_string()
    {
        auto* value = reinterpret_cast<char*>(cursor_);
        auto* end = value;

        while (*end != '\0')
        {
            ++end;
        }

        cursor_ = reinterpret_cast<uint8_t*>(end + 1);
        return value;
    }

    wchar_t*
    next_wstring()
    {
        auto* value = reinterpret_cast<wchar_t*>(cursor_);
        auto* end = value;

        while (*end != L'\0')
        {
            ++end;
        }

        cursor_ = reinterpret_cast<uint8_t*>(end + 1);
        return value;
    }

private:
    template <typename T>
    T
    next()
    {
        const auto value = *reinterpret_cast<T*>(cursor_);
        cursor_ += sizeof(T);
        return value;
    }

    uint8_t* cursor_;
};

} // namespace proto
} // namespace sc
