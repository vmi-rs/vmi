# Rust Style Guide

Project-independent Rust conventions. These rules describe *how* code should be
written, not what any particular project does. They are meant to be shared
across repositories. Nothing here depends on a specific crate, binary, or
domain.

The illustrative before/after snippets use invented type and variable names.
They exist to make a rule concrete, not to reference any real code. When adding
or editing a rule, keep its snippets that way: invent neutral, domain-free names
rather than pulling in types, functions, or terms from whatever project you
happen to be working in. A snippet that names a real crate or concept tempts the
next reader to treat this guide as project-specific, which it is not.

## General

These rules are not Rust-specific and apply to every language, prose file, and
commit message.

### ASCII only

No non-ASCII characters in code or comments. No emdashes, Unicode arrows, or
fancy quotes. Use `->` / `<-` for arrows, `-` or `,` instead of dashes for
parenthetical remarks, and ASCII quotes only.

### US English

Use US English spelling in code, comments, commit messages, and docs (specs,
plans, READMEs). Prefer `-ize` over `-ise`, `-ization` over `-isation`, `-or`
over `-our`, `-er` over `-re`, `-ense` over `-ence` (for nouns like defense,
license). Common examples: serialize, initialization, behavior, color, center,
defense, analyze.

This applies to prose. Identifiers that come from third-party APIs keep
whatever spelling the API uses. If a dependency spells a type `Colour` or a
method `normalise`, keep that name, do not Americanize it.

### Separator comments

Do not use visual section separators like:

```rust
// -- Helpers ----------------------------------------------------
```

If a file is large enough that it needs visual dividers, it wants to be split
into smaller modules. A module's structure should be apparent from its items,
not from ASCII-art horizon lines.

## Toolchain defaults

The conventions below assume this setup. Individual projects may differ (for
example an older edition), but these are the defaults.

- Rust 2024 edition, resolver v3.
- Format with `cargo +nightly fmt` (nightly is required for unstable options in
  `rustfmt.toml`). Never format with stable `fmt`. Check with
  `cargo +nightly fmt -- --check`.
- Lint with `cargo clippy` (stable, run periodically).
- Import grouping: `StdExternalCrate` (std first, then external crates, then
  local).
- `skip_macro_invocations` in `rustfmt.toml` for macros whose hand-aligned
  layout `fmt` would otherwise mangle.
- `missing_docs = "warn"` as a workspace-wide lint.

## Error handling

### Result

Always write the full `Result<T, E>`. Do not introduce crate-local `Result<T>`
aliases and do not rely on module-level ones from other crates.

### anyhow

`anyhow` lives only in `main`. Everything else returns a concrete error type.

Prefer `anyhow::Context::context` over `.expect` for user-facing failures at
that boundary. `.expect` is for invariants that cannot fail, not for missing
inputs or bad configuration. If an input is missing an expected field, the user
should see a labelled error, not a panic.

## Pattern matching and control flow

### Matching Option / Result

Arm order is fixed. When matching `Option`, `Some` comes first and `None`
second. When matching `Result`, `Ok` comes first and `Err` second. The happy
path leads. This applies to every match, including guards and nested patterns.

```rust
// no
match rest.first() {
    None => Target::Default,
    Some(arg) if arg == "-1" => Target::Current,
    Some(arg) => parse(arg),
}

// yes
match rest.first() {
    Some(arg) if arg == "-1" => Target::Current,
    Some(arg) => parse(arg),
    None => Target::Default,
}
```

### No let ... else for Option / Result

Do not use `let ... else` for `Option` / `Result`. Always use `match`:

```rust
// no
let Some(x) = maybe_x else { return Err(...) };

// yes
let x = match maybe_x {
    Some(maybe_x) => maybe_x,
    None => return Err(...),
};
```

### Binding names in match arms

In the match arm, bind the inner value to the *same name as the scrutinee*, not
a short alias:

```rust
// no
let user = match current_user {
    Some(u) => u,
    None => return,
};

// yes
let user = match current_user {
    Some(current_user) => current_user,
    None => return,
};
```

Exception: the capture in `Err(...)` is always named `err`, regardless of what
the scrutinee or the error type is called. The scrutinee rule applies to `Ok`,
`Some`, and enum variants. `Err` is the one place where a short uniform name
wins.

```rust
// no
match record.id() {
    Ok(id) => id,
    Err(id) => return Err(id.into()),
}

// yes
match record.id() {
    Ok(id) => id,
    Err(err) => return Err(err.into()),
}
```

### Closure parameters

Name a closure parameter after what it holds, not a single letter. `|o|` or
`|x|` forces the reader into the body to recover the meaning a real name would
have carried at the binding site. This is the same principle as binding a match
arm to the scrutinee's name.

```rust
// no
entry.owner().ok().and_then(|o| o.id().ok())
items.iter().filter(|x| x.enabled)

// yes
entry.owner().ok().and_then(|owner| owner.id().ok())
items.iter().filter(|item| item.enabled)
```

The exception is a parameter the body ignores, which stays `_` or a
`_`-prefixed name: `.map_err(|_| Error::Timeout)`, `.inspect(|_entry| count += 1)`.

When a closure binds an error and the body uses it, name it `err`, the same
`Err(...)` convention from above, not a single letter: `.map_err(|err|
Error::Io(err))`.

### Binding modes

Prefer the reference at the scrutinee over `ref` in the pattern. Match
ergonomics gives you `&T` bindings automatically when the scrutinee is
`&Option<T>` or `&Result<T, E>`, so `ref` is legacy for this case. This applies
to `if let`, `while let`, and `match`.

```rust
// no
if let Some(ref directory) = self.extraction_directory {
    use_directory(directory);
}

match self.extraction_directory {
    Some(ref directory) => use_directory(directory),
    None => (),
}

// yes
if let Some(directory) = &self.extraction_directory {
    use_directory(directory);
}

match &self.extraction_directory {
    Some(directory) => use_directory(directory),
    None => (),
}
```

`ref` remains correct for the rare patterns that bind part of a compound
scrutinee by reference while moving another part. For simple `Option` /
`Result` extraction, use `&` on the scrutinee.

### Scope blocks

Do not wrap code in `{ ... }` to shorten a borrow. NLL ends non-`Drop` borrows
at their last use, so a bare `let store = registry.store();` followed later by
`registry.reload()`, which borrows `&mut self`, works without an explicit scope.
Trust NLL.

```rust
// no
let owner_id;
{
    let store = registry.store();
    let entry = store.lookup(key)?;
    owner_id = entry.owner().ok().and_then(|owner| owner.id().ok());
}
registry.reload()?;

// yes
let store = registry.store();
let entry = store.lookup(key)?;
let owner_id = entry.owner().ok().and_then(|owner| owner.id().ok());
registry.reload()?;
```

The same applies to `let x = { ... };` used to build a value: prefer a flat
sequence of `let` bindings. Reserve scope blocks for the cases where they are
actually load-bearing: forcing a `Drop` type (`MutexGuard`, file handle) to
release early, or when the block's final expression is genuinely the cleanest
way to compute a value.

## Bindings and types

### Type annotations

Do not annotate a binding's type before `=` unless the compiler genuinely
cannot infer it. Use a turbofish on the producing expression instead.

```rust
// no
let entries: Vec<Entry> = iter.filter_map(...).collect();

// yes
let entries = iter.filter_map(...).collect::<Vec<_>>();
```

This reads top-down, matches the direction the reader follows the expression,
and avoids repeating the inner type when an underscore suffices.

## Imports

Types used inside a file must be brought in at the top with `use` and referenced
by their short name. Do not spell them with a partial path inline. The `use`
block is the single source of truth about where each item comes from. Partial
paths on type references scatter that across signatures and let-bindings where
it rots as code moves.

```rust
// no
fn render(node: &graph::Node, ...) { ... }

// yes
use graph::Node;

fn render(node: &Node, ...) { ... }
```

The rule is about types. Free-standing function calls through a partial path are
fine. `graph::walk(...)` or `super::exec::run(...)` read cleanly at the call
site and do not need their own `use` line. Importing them would often collide
with a local `run` or `walk` and require renaming, which buys nothing.

Exceptions:

- The standard `impl std::fmt::Display for T { fn fmt(&self, f: &mut
  std::fmt::Formatter) -> std::fmt::Result }` idiom stays as-is. The three `fmt`
  items travel together, `std::fmt::Result` disambiguates from the ambient
  `Result`, and spelling the full path keeps the block self-describing. Same for
  `Debug`, `LowerHex`, and siblings.
- Error enum variants that declare their payload with a partial path stay as-is:
  `Io(#[from] std::io::Error)`,
  `Uri(#[from] http::uri::InvalidUri)`. The variant's payload type is visible at
  the declaration, which helps readers of the error enum more than an extra
  `use` line would.
- `std::marker::PhantomData` stays fully qualified. It is a marker, not a
  working type, and the full path is idiomatic.
- One-off configuration calls on a module-qualified type in `main` or equivalent
  setup code stay as-is: `tracing_subscriber::EnvFilter::from_default_env()`,
  `tracing_subscriber::fmt()`. Importing for a single call adds noise without
  reuse.
- Disambiguating two types that share a name (`std::fmt::Result` next to a
  crate-local `Result`).

## Formatting macros

Use inline format arguments when the argument is a bare identifier. This applies
to every formatting macro: `format!`, `write!`, `writeln!`, `print!`,
`println!`, `eprint!`, `eprintln!`, and the tracing macros.

```rust
// no
format!("[{}]", frame)
writeln!(f, "{}: {}", name, value)

// yes
format!("[{frame}]")
writeln!(f, "{name}: {value}")
```

This rule only covers bare identifiers. When an argument is a field access,
method call, index, or any other expression, the whole call stays positional. Do
not mix inline captures with positional arguments in the same macro call.

```rust
// no
format!("{abc} {}", abc.def)

// yes
format!("{} {}", abc, abc.def)
```

## Documentation (rustdoc)

Document every item, including private ones. Be terse. Explain only when the
meaning is non-obvious. A one-line doc is usually right.

Do not state what is already obvious from the signature or name. A doc that just
repeats "the X field" or "returns the Y" for an accessor that is clearly
`fn y(&self) -> &Y` adds nothing. Write something if the constraint, unit,
lifetime, or invariant is non-obvious, otherwise leave the one-liner short.

Type docs on a struct or enum should describe what the item represents, not
enumerate its fields or variants. Anyone reading the file sees the fields right
below the doc. Restating them in the type doc is the same redundancy the rule
above forbids for accessors. The per-field rustdocs already carry the per-field
meaning, so the type doc adds the meaning of the whole.

```rust
// no
/// One parsed annotation: name plus positional argument texts.
pub struct Annotation<'a> {
    pub name: &'a str,
    pub args: Vec<&'a str>,
}

// yes
/// One `#[name(...)]` attribute group decoded from the token stream.
pub struct Annotation<'a> {
    pub name: &'a str,
    pub args: Vec<&'a str>,
}
```

Do not reference unreleased versions or future promises in docs. No "in v1",
"for now", "will be extended later". Code evolves. Doc what it does today.

Function rustdocs begin with an active verb describing the effect or return.
"Returns the active worker." "Clears the pending flag." "Sets the retry
deadline." Not "The active worker." or "Pending-flag helper." This keeps the doc
grammatically parallel to the function's behavior.

Write complete sentences with an explicit, unambiguous subject. Telegraphic
shorthand where a bare plural noun doubles as both subject and verb forces the
reader to backtrack and re-parse. The fix is to rewrite with a real subject
phrase, not to add commas or rearrange clauses.

```rust
// no
/// Reads bump the entry's access time so the eviction pass skips it,
/// then fall through to the backing store when the key is missing so
/// the value loads.

// yes
/// On a read, bumps the entry's access time so the eviction pass
/// skips it, and falls through to the backing store when the key is
/// missing so the value loads.
```

The bad version reads "Reads" as either "read accesses" (noun) or "this function
reads" (verb), and then "fall through" floats without a clear subject. The good
version anchors each clause to a named subject.

In structs and enums, separate each documented field or variant with a blank
line between the rustdoc and the previous field. The doc visually attaches to
the item it describes, not the one above.

```rust
// no
/// Currently selected tab.
current_tab: Tab,
/// Currently focused pane.
current_pane: PaneId,

// yes
/// Currently selected tab.
current_tab: Tab,

/// Currently focused pane.
current_pane: PaneId,
```

Avoid leaning on parentheses, `e.g.`, and `i.e.` as crutches. When the main
sentence would not be clear on its own, the common reflex is to tuck the real
claim into parentheses and then add an example with `e.g.` to prop it up. Both
happen in the same comment when the writer does not trust the main sentence. The
fix is to rewrite the main sentence so it stands on its own, not to patch it
with asides. Parentheses and `e.g.` are fine in moderation and become a problem
when they appear in most doc comments.

Do not use semicolons in rustdocs. Two short sentences are almost always better.
Reserve the semicolon for the rare case where the two clauses are so tightly
coupled that splitting them would distort the meaning.
