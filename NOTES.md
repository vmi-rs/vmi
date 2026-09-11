- revisit sc::vmi namespace name. suggest other names?
- class cursor: suggest better name?
- enum class status, struct result... pick better names (also for rust counterparts) and make them unified
  o result/TerminalResult -> status/Status
  o status/TerminalStatus -> status_kind/StatusKind ? reason/Reason ?
  o put enum class status inside struct result? status::kind?
  - reorder fields? make kind first and stage second?
  - pub fn encode(self) -> BridgeStatusCode ... make the fn inside the trait BridgeStage? some other trait?
  - pub fn decode(value: BridgeStatusCode) -> Self ... make it take BridgePacket?
    - extend TerminalResult with native_code?
o move examples/windows-bridge/bridge into crates/vmi-utils/src/shellcode
o cmake should put shellcodes into examples/shellcodes/bin (and .rs files should include those... and it should be included in git too)

in docs: (where? injector? recipe? shellcode? bridge?)
opinionated shellcode [library? sdk? module?]
recipes are intended for short sequences of api calls...
sometimes, recipes are not enough... --> shellcode