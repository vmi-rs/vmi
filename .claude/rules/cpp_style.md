# C++ Style Guide

Project-independent C++ conventions. These rules describe how code should be
written, not what any particular project does.

## Class member declaration order

Use a consistent declaration order within each access section. The order is:

1. Nested types and type aliases.
2. Static constants.
3. Factory functions.
4. Constructors, ordered as default, parameterized or converting, copy, then
   move.
5. Assignment operators, ordered as copy then move.
6. Destructor.
7. Remaining member functions, grouped by behavior.
8. Data members.

Order access sections as `public`, `protected`, then `private`, and omit empty
sections.

Only copy and move assignment operators belong in the special-member block.
Place all other operators with the behavior they represent. For example, put
conversion and dereference operators with observers and accessors rather than
in a general operator section.

Within the remaining member functions, use semantic groups rather than
alphabetical order. Put observers and accessors before modifiers. Put private
helper functions before private data members. Separate conceptual groups with
a blank line.

Do not reorder virtual member functions in an ABI-sensitive class merely for
style, because their order can affect implementation vtable layout.

```cpp
class resource {
public:
    using handle_type = void*;

    resource() = default;
    explicit resource(handle_type value);
    resource(const resource&) = delete;
    resource(resource&& other) noexcept;
    resource& operator=(const resource&) = delete;
    resource& operator=(resource&& other) noexcept;
    ~resource();

    handle_type get() const;
    explicit operator bool() const;
    handle_type operator*() const;

    void reset();

private:
    void release();

    handle_type value_ = nullptr;
};
```
