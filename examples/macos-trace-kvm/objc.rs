//! Passive Objective-C metadata decoding for macOS arm64e.
//!
//! Every runtime address comes from a libobjc symbol name (exports and local
//! symbols), the shared-cache range and relative selector base come from the
//! versioned dyld cache header, and structure offsets are the compiler-emitted
//! ObjC ABI cited from objc4-951.7. Exported `objc_debug_*` values are checked
//! against the values the decoder supports before any of them is used. PAC
//! stripping identifies pointers and does not authenticate them. No guest
//! code is called.

use std::{collections::HashMap, sync::Arc};

use vmi::{Va, VmiContext, VmiError, os::macos::MacOs};

use crate::{
    Driver,
    encoding::{AbiKind, AbiType, MethodSignature, parse_method_encoding},
};

/// Canonical user pointer bits checked against the runtime debug masks.
const POINTER_MASK: u64 = 0x0000_7fff_ffff_ffff;
/// Class bits of a packed or signed isa.
///
/// objc4-951.7 `runtime/isa.h:100-102` defines `ISA_MASK_NOSIG` on macOS as
/// `0x00007ffffffffff8`, without the pointer-authentication signature that
/// arm64e `ISA_MASK` keeps. `objc_debug_isa_class_mask` is only compared
/// against it.
const ISA_CLASS_MASK: u64 = 0x0000_7fff_ffff_fff8;
/// Maximum classes retained before dropping the metadata snapshot.
const CLASS_LIMIT: usize = 16_384;
/// Maximum cached method declarations.
const METHOD_LIMIT: usize = 65_536;
/// Maximum superclass depth, bounding corrupt or cyclic hierarchies.
const CLASS_DEPTH: usize = 128;
/// Maximum lists inspected in one method lookup.
const LIST_LIMIT: u32 = 4096;
/// Maximum method or ivar entries accepted in a single list.
const ENTRY_LIMIT: u32 = 65_536;
/// Maximum metadata string length.
const NAME_LIMIT: usize = 1024;
/// Maximum method encoding length.
const ENCODING_LIMIT: usize = 4096;

/// `objc_class::superclass`, after the isa word.
///
/// objc4-951.7 `runtime/objc-runtime-new.h:2635-2644`
/// (`objc_class : objc_object` with `superclass`, the 16-byte `cache_t` and
/// `class_data_bits_t bits`).
const CLASS_SUPERCLASS: u64 = 0x8;
/// `objc_class::bits`, the class data word.
const CLASS_BITS: u64 = 0x20;
/// `FAST_IS_RW_POINTER`, set once `bits` points at a `class_rw_t`.
///
/// objc4-951.7 `runtime/objc-runtime-new.h:148`.
const FAST_IS_RW_POINTER: u64 = 1 << 63;
/// `class_rw_t::ro_or_rw_ext`, after the 32-bit flags and 16-bit witness.
///
/// objc4-951.7 `runtime/objc-runtime-new.h:2212-2220`. Tag bit zero selects
/// `class_rw_ext_t` (`ro_or_rw_ext_t` at line 2226, `PointerUnion.h:84-96`).
const RW_RO_OR_EXT: u64 = 0x8;
/// `class_rw_ext_t::methods`, after the `ro` pointer at offset zero.
///
/// objc4-951.7 `runtime/objc-runtime-new.h:2202-2205`.
const RWE_METHODS: u64 = 0x8;
/// `class_ro_t::name`.
///
/// objc4-951.7 `runtime/objc-runtime-new.h:1598-1617`: `flags`,
/// `instanceStart`, `instanceSize`, `reserved`, `ivarLayout`, `name`,
/// `baseMethods`, `baseProtocols`, `ivars`.
const RO_NAME: u64 = 0x18;
/// `class_ro_t::baseMethods`, tag bit zero selecting a relative list of lists.
const RO_BASE_METHODS: u64 = 0x20;
/// `class_ro_t::ivars`.
const RO_IVARS: u64 = 0x30;
/// `RO_META` in `class_ro_t::flags`.
///
/// objc4-951.7 `runtime/objc-runtime-new.h:43`.
const RO_META: u32 = 1;
/// `method_list_t` entry size mask, the complement of the `0xffff0003` flag
/// mask.
///
/// objc4-951.7 `runtime/objc-runtime-new.h:1241` and `entsize_list_tt` at
/// 696-705.
const METHOD_SIZE_MASK: u32 = 0xfffc;
/// `methodListIsUniqued | methodListIsSorted`, enabling binary search.
///
/// dyld-1378 `common/ObjCVisitor.h:208-209`.
const METHOD_LIST_SORTED: u32 = 3;
/// `method_list_t::smallMethodListFlag`, three 32-bit relative fields per
/// entry.
///
/// objc4-951.7 `runtime/objc-runtime-new.h:1251` and `method_t::small` at
/// 975-980.
const SMALL_METHOD_LIST: u32 = 0x8000_0000;
/// `methodListUsesTypeOffsets`, set by the cache builder when small method
/// types were rewritten as offsets from the relative selector base.
///
/// dyld-1378 `common/ObjCVisitor.h:211` and
/// `cache_builder/CacheDylib.cpp:1789-1806`.
const METHOD_LIST_TYPE_OFFSETS: u32 = 0x2000_0000;
/// `bigSignedMethodListFlag`, carried in bit 63 of a method list pointer.
///
/// objc4-951.7 `runtime/objc-runtime-new.h:1242-1249`.
const BIG_SIGNED_METHOD_LIST: u64 = 1 << 63;
/// Size of `method_t::small`.
const SMALL_METHOD_SIZE: u64 = 12;
/// Size of `method_t::big` (`name`, `types`, `imp`).
///
/// objc4-951.7 `runtime/objc-runtime-new.h:920-924`.
const BIG_METHOD_SIZE: u64 = 24;
/// Size of `ivar_t` (`offset`, `name`, `type`, `alignment_raw`, `size`).
///
/// objc4-951.7 `runtime/objc-runtime-new.h:1205-1219`, listed by
/// `ivar_list_t : entsize_list_tt<ivar_t, ivar_list_t, 0>` at line 1496.
const IVAR_SIZE: u32 = 0x20;
/// `ivar_t::name`.
const IVAR_NAME: u64 = 0x8;
/// `ivar_t::type`.
const IVAR_TYPE: u64 = 0x10;
/// `ivar_t::size`.
const IVAR_BYTES: u64 = 0x1c;
/// Size of one `header_info_rw` in `objc_headeropt_rw_t::headers`, whose
/// bit zero is `isLoaded`.
///
/// objc4-951.7 `runtime/objc-opt.h:34-68`.
const HEADER_INFO_RW_SIZE: u64 = 8;

/// dyld cache header magic prefix accepted by dyld itself.
///
/// dyld-1378 `common/DyldSharedCache.cpp:175`.
const CACHE_MAGIC: &[u8] = b"dyld_v1";
/// Bytes of `dyld_cache_header` read, through `objcOptsSize`.
const CACHE_HEADER_SIZE: usize = 0x1e0;
/// `dyld_cache_header::mappingOffset`, which is also the size of the header
/// the cache was built with, so a field exists only below it.
///
/// dyld-1378 `include/mach-o/dyld_cache_format.h:32-115`.
const CACHE_MAPPING_OFFSET: usize = 0x10;
/// `dyld_cache_header::mappingCount`.
const CACHE_MAPPING_COUNT: usize = 0x14;
/// `dyld_cache_header::sharedRegionSize`, format line 71.
const CACHE_SHARED_REGION_SIZE: usize = 0xe8;
/// `dyld_cache_header::subCacheArrayCount`, format line 95. Its presence
/// selects `sharedRegionSize` as the mapped size.
///
/// dyld-1378 `common/DyldSharedCache.cpp:399-417`.
const CACHE_SUB_CACHE_COUNT: usize = 0x18c;
/// `dyld_cache_header::objcOptsOffset`, format line 104, relative to the
/// header.
const CACHE_OBJC_OPTS_OFFSET: usize = 0x1d0;
/// `dyld_cache_header::objcOptsSize`, format line 105.
const CACHE_OBJC_OPTS_SIZE: usize = 0x1d8;
/// Size of one `dyld_cache_mapping_info`, format lines 122-128.
const CACHE_MAPPING_SIZE: u64 = 0x20;
/// Largest mapping table offset dyld walks.
///
/// dyld-1378 `common/DyldSharedCache.cpp:177-180`.
const CACHE_MAPPING_OFFSET_LIMIT: u32 = 1024;
/// Largest mapping count dyld walks.
const CACHE_MAPPING_COUNT_LIMIT: u32 = 20;
/// `ObjCOptimizationHeader::relativeMethodSelectorBaseAddressOffset`, relative
/// to the cache header.
///
/// dyld-1378 `common/DyldSharedCache.h:80-94` and
/// `DyldSharedCache.cpp:1942-1948`.
const OBJC_OPTS_SELECTOR_BASE: u64 = 0x30;
/// `objc_opt_t::version` the fallback layout applies to.
///
/// dyld-1378 `include/objc-shared-cache.h:82`.
const OBJC_OPT_VERSION: u32 = 16;
/// `objc_opt_t::relativeMethodSelectorBaseAddressOffset`, relative to the
/// `objc_opt_t` in libobjc.
///
/// dyld-1378 `include/objc-shared-cache.h:93-104, 145-148`.
const OBJC_OPT_SELECTOR_BASE: u64 = 0x28;

/// Private libobjc functions that attach images, categories or methods.
///
/// Matched by base name because objc4 appends parameters between releases,
/// which changes the C++ mangling.
const MUTATION_HOOKS: [&str; 3] = ["map_images_nolock", "attachCategories", "addMethods_finish"];

/// Runtime identity and display metadata of a class or metaclass.
#[derive(Debug)]
pub struct ClassInfo {
    /// Raw runtime class name, without invoking Swift demangling.
    pub name: String,
    /// Whether this descriptor is a metaclass.
    pub is_metaclass: bool,
    /// Canonical superclass address, zero at the root.
    pub superclass: u64,
}

/// Instance variable metadata from compiler-emitted `ivar_t` records.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Ivar {
    /// Live byte offset read through `ivar_t::offset`.
    pub offset: u64,
    /// Declared byte size.
    pub size: u32,
    /// ObjC type encoding, empty when the compiler emitted none.
    pub type_encoding: String,
}

/// Cached selector and declared fixed ABI.
#[derive(Debug)]
pub struct Method {
    /// Selector text copied only when this descriptor is first cached.
    pub selector: String,
    /// Declared fixed arguments and result, including hidden self and SEL.
    pub signature: MethodSignature,
}

/// What a passive entry observation establishes about dispatch.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DispatchStatus {
    /// Live method metadata or a checked semantic hook supplies the ABI.
    Resolved,
    /// Nil has no receiver class and no selector-derived method ABI.
    Nil,
    /// No declaration was found, possibly pending resolution or forwarding.
    Unresolved,
    /// An absolute method entry explicitly names the configured forwarder.
    Forwarded,
    /// Runtime symbols, the cache header or debug values were missing or
    /// unsupported.
    UnsupportedLayout,
}

/// One message or optimized semantic operation at its entry instruction.
#[derive(Debug)]
pub struct Invocation {
    /// Actual receiver, including for objc_super records.
    pub receiver: u64,
    /// Actual receiver lookup class, not the superclass dispatch origin.
    pub class: u64,
    /// Whether the actual receiver is a class object.
    pub is_class: bool,
    /// Shared immutable selector and ABI declaration.
    pub method: Arc<Method>,
    /// Register index of the first explicit argument, two or one.
    pub argument_base: usize,
    /// Explicit nil, missing-layout, unresolved or forwarded state.
    pub status: DispatchStatus,
}

/// Cold class metadata needed for live method collection traversal.
struct ClassMetadata {
    /// Cached display metadata.
    info: ClassInfo,
    /// Read-only class metadata address.
    ro: u64,
    /// Realized writable metadata, zero for unrealized classes.
    rw: u64,
}

/// How a found method entry stores its types and implementation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum EntryKind {
    /// Pointer-sized `name`, `types` and `imp` fields.
    Absolute,
    /// 32-bit relative fields, types optionally relative to the selector base.
    Relative {
        /// Whether `types` is an offset from the shared selector base.
        shared_types: bool,
    },
}

/// Shared-cache facts read from the versioned dyld cache header.
struct SharedCache {
    /// Slid cache header, the start of `_dyld_get_shared_cache_range`.
    start: u64,
    /// Exclusive end of the mapped cache.
    end: u64,
    /// Whether the header carries an `ObjCOptimizationHeader`.
    objc_opts: bool,
    /// Relative method selector base from that header.
    string_base: Option<u64>,
}

/// Addresses of the libobjc globals the decoder reads, all named symbols.
#[derive(Default)]
struct Globals {
    /// `objc_debug_isa_class_mask`.
    isa_class_mask: u64,
    /// `objc_debug_class_rw_data_mask`.
    class_rw_data_mask: u64,
    /// `objc_debug_taggedpointer_mask`.
    tagged_mask: u64,
    /// `objc_debug_taggedpointer_slot_mask`.
    slot_mask: u64,
    /// `objc_debug_taggedpointer_ext_mask`.
    ext_mask: u64,
    /// `objc_debug_taggedpointer_ext_slot_shift`.
    ext_slot_shift: u64,
    /// `objc_debug_taggedpointer_ext_slot_mask`.
    ext_slot_mask: u64,
    /// `objc_debug_taggedpointer_classes`.
    tagged_classes: u64,
    /// `objc_debug_taggedpointer_ext_classes`.
    ext_classes: u64,
    /// `objc_debug_taggedpointer_obfuscator`.
    obfuscator: u64,
    /// `objc_debug_tag60_permutations`.
    permutations: u64,
    /// `objc_debug_taggedpointer_payload_lshift`.
    payload_lshift: u64,
    /// `objc_debug_taggedpointer_payload_rshift`.
    payload_rshift: u64,
    /// `objc_debug_taggedpointer_ext_payload_lshift`.
    ext_payload_lshift: u64,
    /// `objc_debug_taggedpointer_ext_payload_rshift`.
    ext_payload_rshift: u64,
    /// `objc_debug_headerInfoRWs`.
    header_info_rws: u64,
}

impl Globals {
    /// Returns the address slot of an exported debugger global by symbol name.
    fn slot(&mut self, name: &str) -> Option<&mut u64> {
        match name {
            "objc_debug_isa_class_mask" => Some(&mut self.isa_class_mask),
            "objc_debug_class_rw_data_mask" => Some(&mut self.class_rw_data_mask),
            "objc_debug_taggedpointer_mask" => Some(&mut self.tagged_mask),
            "objc_debug_taggedpointer_slot_mask" => Some(&mut self.slot_mask),
            "objc_debug_taggedpointer_ext_mask" => Some(&mut self.ext_mask),
            "objc_debug_taggedpointer_ext_slot_shift" => Some(&mut self.ext_slot_shift),
            "objc_debug_taggedpointer_ext_slot_mask" => Some(&mut self.ext_slot_mask),
            "objc_debug_taggedpointer_classes" => Some(&mut self.tagged_classes),
            "objc_debug_taggedpointer_ext_classes" => Some(&mut self.ext_classes),
            "objc_debug_taggedpointer_obfuscator" => Some(&mut self.obfuscator),
            "objc_debug_tag60_permutations" => Some(&mut self.permutations),
            "objc_debug_taggedpointer_payload_lshift" => Some(&mut self.payload_lshift),
            "objc_debug_taggedpointer_payload_rshift" => Some(&mut self.payload_rshift),
            "objc_debug_taggedpointer_ext_payload_lshift" => Some(&mut self.ext_payload_lshift),
            "objc_debug_taggedpointer_ext_payload_rshift" => Some(&mut self.ext_payload_rshift),
            "objc_debug_headerInfoRWs" => Some(&mut self.header_info_rws),
            _ => None,
        }
    }

    /// Whether every global the decoder reads has been named by the symbol
    /// table. `objc_debug_isa_class_mask` is only a cross-check.
    fn complete(&self) -> bool {
        [
            self.class_rw_data_mask,
            self.tagged_mask,
            self.slot_mask,
            self.ext_mask,
            self.ext_slot_shift,
            self.ext_slot_mask,
            self.tagged_classes,
            self.ext_classes,
            self.obfuscator,
            self.permutations,
            self.payload_lshift,
            self.payload_rshift,
            self.ext_payload_lshift,
            self.ext_payload_rshift,
            self.header_info_rws,
        ]
        .iter()
        .all(|address| *address != 0)
    }
}

/// Verified runtime globals and process-specific tagged-pointer snapshot.
struct Layout {
    /// Mask for authenticated and packed isa class identification.
    isa_mask: u64,
    /// Mask for class data bits after stripping authentication.
    data_mask: u64,
    /// Shared-cache lower address boundary.
    cache_start: u64,
    /// Shared-cache exclusive upper boundary.
    cache_end: u64,
    /// Optimized shared-cache selector and type string base, if published.
    string_base: Option<u64>,
    /// Runtime loaded-header table pointer global.
    headers: u64,
    /// Runtime flag disabling preattached category lookup, if named.
    disable_preattached: Option<u64>,
    /// Tagged-pointer recognition mask.
    tagged_mask: u64,
    /// Encoded ordinary class slots.
    tagged_classes: [u64; 8],
    /// Encoded extended class slots.
    extended_classes: [u64; 256],
    /// Logical basic tag to encoded slot permutation.
    permutations: [u8; 8],
    /// Runtime payload obfuscator.
    obfuscator: u64,
    /// Basic unsigned payload left and right shifts.
    payload_shifts: (u32, u32),
    /// Extended unsigned payload left and right shifts.
    extended_shifts: (u32, u32),
}

impl Layout {
    /// Tests membership in the runtime shared-cache range.
    fn in_cache(&self, address: u64) -> bool {
        address >= self.cache_start && address < self.cache_end
    }
}

/// Per-translation-root runtime snapshot with lazy live class fallback.
#[derive(Default)]
pub struct ObjcRuntime {
    /// Exported debugger globals named by the symbol table.
    globals: Globals,
    /// Local `DisablePreattachedCategories` option, zero when unnamed.
    disable_preattached: u64,
    /// Local `_objc_opt_data`, the pre-`objcOpts` optimization header.
    opt_data: u64,
    /// Configured forwarder entry addresses.
    forwarders: [u64; 2],
    /// Entry addresses of each private mutation hook, by `MUTATION_HOOKS`
    /// index.
    mutation_hooks: [Vec<u64>; 3],
    /// Shared-cache range and selector base of this process.
    cache: Option<SharedCache>,
    /// Lazily verified process-specific runtime snapshot.
    layout: Option<Layout>,
    /// Class and metaclass descriptors loaded from live memory.
    classes: HashMap<u64, ClassMetadata>,
    /// Interned selector text read once from the guest.
    selectors: HashMap<u64, Arc<str>>,
    /// Successfully resolved class and selector declarations.
    methods: HashMap<(u64, u64), Arc<Method>>,
    /// Unknown ABI descriptors, never used as a negative lookup cache.
    unknown: HashMap<u64, Arc<Method>>,
    /// Checked semantic ABI descriptors, independent of mutable method lists.
    semantic: HashMap<&'static str, Arc<Method>>,
}

impl ObjcRuntime {
    /// Records a recognized libobjc symbol and reports whether it was consumed.
    ///
    /// Names arrive with exactly one leading underscore stripped, so the C
    /// symbol `_objc_msgForward` arrives as `_objc_msgForward`.
    pub fn configure_symbol(&mut self, name: &str, address: u64) -> bool {
        if let Some(index) = mutation_hook(name) {
            let hooks = &mut self.mutation_hooks[index];
            if !hooks.contains(&address) {
                hooks.push(address);
            }
            return true;
        }
        match name {
            "_objc_msgForward" => self.forwarders[0] = pointer(address),
            "_objc_msgForward_impcache" => self.forwarders[1] = pointer(address),
            "DisablePreattachedCategories" => self.disable_preattached = address,
            "_objc_opt_data" => self.opt_data = address,
            _ => match self.globals.slot(name) {
                Some(slot) => *slot = address,
                None => return false,
            },
        }
        self.invalidate();
        true
    }

    /// Reads the shared-cache range and relative selector base of this process.
    ///
    /// `header` is the slid address of the process's dyld cache header. The
    /// range equals what libobjc stores from `_dyld_get_shared_cache_range`
    /// (objc4-951.7 `runtime/objc-opt.mm:434-437`), which returns the header
    /// and `DyldSharedCache::mappedSize` (dyld-1378
    /// `dyld/DyldAPIs.cpp:1988-2001`). An unrecognized header leaves the layout
    /// unsupported.
    pub fn configure_shared_cache(
        &mut self,
        vmi: &VmiContext<MacOs<Driver>>,
        header: u64,
    ) -> Result<(), VmiError> {
        self.cache = None;
        self.invalidate();
        let mut bytes = [0_u8; CACHE_HEADER_SIZE];
        vmi.read(Va(header), &mut bytes)?;
        if !bytes.starts_with(CACHE_MAGIC) {
            return Ok(());
        }
        let size = match shared_region_size(&bytes) {
            Some(size) => size,
            None => match mapping_span(vmi, header, &bytes)? {
                Some(size) => size,
                None => return Ok(()),
            },
        };
        let end = match header.checked_add(size) {
            Some(end) if size != 0 => end,
            _ => return Ok(()),
        };
        let (objc_opts, string_base) = match objc_opts(&bytes) {
            Some((offset, size)) => {
                let base = if size >= OBJC_OPTS_SELECTOR_BASE + 8 {
                    let field = header
                        .wrapping_add(offset)
                        .wrapping_add(OBJC_OPTS_SELECTOR_BASE);
                    let offset = vmi.read_u64(Va(field))?;
                    header
                        .checked_add(offset)
                        .filter(|base| offset != 0 && *base < end)
                }
                else {
                    None
                };
                (true, base)
            }
            None => (false, None),
        };
        self.cache = Some(SharedCache {
            start: header,
            end,
            objc_opts,
            string_base,
        });
        Ok(())
    }

    /// Drops class, method, selector and tagged snapshots after runtime
    /// mutation.
    ///
    /// Existing invocation descriptors remain valid through their Arc handles.
    pub fn invalidate(&mut self) {
        self.layout = None;
        self.classes.clear();
        self.methods.clear();
        self.selectors.clear();
        self.unknown.clear();
    }

    /// Lists public mutation entry points the tracer must observe.
    ///
    /// Invalidate on entry and on return, avoiding a stale snapshot populated
    /// while a mutator is in flight. Image-load completion also invalidates.
    pub fn mutation_symbols() -> &'static [&'static str] {
        &[
            "class_addMethod",
            "class_replaceMethod",
            "class_addMethodsBulk",
            "class_replaceMethodsBulk",
            "method_setImplementation",
            "method_exchangeImplementations",
            "objc_registerClassPair",
            "objc_readClassPair",
            "objc_disposeClassPair",
            "object_setClass",
            "class_setSuperclass",
            "objc_setForwardHandler",
            "_objc_registerTaggedPointerClass",
            "dlopen",
            "dlclose",
        ]
    }

    /// Returns named private image, category and method attachment hooks.
    ///
    /// Observe both entry and return. The lines name every hook without a
    /// symbol, after which method metadata may stay stale until another
    /// invalidation.
    pub fn mutation_addresses(&self) -> (Vec<u64>, Vec<String>) {
        let mut addresses = Vec::new();
        let mut lines = Vec::new();
        for (hook, found) in MUTATION_HOOKS.iter().zip(&self.mutation_hooks) {
            if found.is_empty() {
                lines.push(format!(
                    "objc incomplete: no libobjc symbol for mutation hook {hook}, method metadata may be stale after it runs"
                ));
            }
            addresses.extend_from_slice(found);
        }
        (addresses, lines)
    }

    /// Returns cached metadata for a canonical class or metaclass address.
    pub fn info(&self, class: u64) -> Option<&ClassInfo> {
        self.classes.get(&class).map(|metadata| &metadata.info)
    }

    /// Identifies a receiver's actual lookup class and loads cold live
    /// metadata.
    pub fn class_info(
        &mut self,
        vmi: &VmiContext<MacOs<Driver>>,
        receiver: u64,
    ) -> Result<Option<&ClassInfo>, VmiError> {
        if receiver == 0 || !self.ensure_layout(vmi)? {
            return Ok(None);
        }
        let class = self.receiver_class(vmi, receiver)?;
        if class == 0 || !self.load_class(vmi, class)? {
            return Ok(None);
        }
        Ok(self.info(class))
    }

    /// Returns an object's lookup class address, zero when it is unknown.
    pub fn object_class(
        &mut self,
        vmi: &VmiContext<MacOs<Driver>>,
        receiver: u64,
    ) -> Result<u64, VmiError> {
        if receiver == 0 || !self.ensure_layout(vmi)? {
            return Ok(0);
        }
        self.receiver_class(vmi, receiver)
    }

    /// Finds an instance variable by name in a class or its superclasses.
    ///
    /// The offset is the live value behind `ivar_t::offset`, which the runtime
    /// may slide when a superclass grows. Subclass ivars shadow superclass
    /// ivars.
    pub fn ivar(
        &mut self,
        vmi: &VmiContext<MacOs<Driver>>,
        class: u64,
        name: &str,
    ) -> Result<Option<Ivar>, VmiError> {
        if !self.ensure_layout(vmi)? {
            return Ok(None);
        }
        let mut current = pointer(class);
        for _ in 0..CLASS_DEPTH {
            if current == 0 || !self.load_class(vmi, current)? {
                return Ok(None);
            }
            let (ro, superclass) = match self.classes.get(&current) {
                Some(metadata) => (metadata.ro, metadata.info.superclass),
                None => return Ok(None),
            };
            let list = pointer(vmi.read_u64(Va(ro + RO_IVARS))?);
            if list != 0 {
                let size = vmi.read_u32(Va(list))?;
                let count = vmi.read_u32(Va(list + 4))?;
                if !(IVAR_SIZE..=4096).contains(&size) || count > ENTRY_LIMIT {
                    return Ok(None);
                }
                for index in 0..count {
                    let entry = list + 8 + u64::from(index) * u64::from(size);
                    let name_address = pointer(vmi.read_u64(Va(entry + IVAR_NAME))?);
                    if !text_matches(vmi, name_address, name)? {
                        continue;
                    }
                    let offset_address = pointer(vmi.read_u64(Va(entry))?);
                    if offset_address == 0 {
                        return Ok(None);
                    }
                    let offset = match u64::try_from(vmi.read_u32(Va(offset_address))? as i32) {
                        Ok(offset) => offset,
                        Err(_) => return Ok(None),
                    };
                    let type_address = pointer(vmi.read_u64(Va(entry + IVAR_TYPE))?);
                    let type_encoding = if type_address == 0 {
                        String::new()
                    }
                    else {
                        match read_text(vmi, type_address, ENCODING_LIMIT)? {
                            Some(encoding) => encoding,
                            None => return Ok(None),
                        }
                    };
                    return Ok(Some(Ivar {
                        offset,
                        size: vmi.read_u32(Va(entry + IVAR_BYTES))?,
                        type_encoding,
                    }));
                }
            }
            if superclass == current {
                break;
            }
            current = superclass;
        }
        Ok(None)
    }

    /// Decodes a logical tagged-pointer tag and its unsigned 60-bit or 52-bit
    /// payload.
    ///
    /// Basic logical tags are zero through six, extended tags eight through
    /// 263. Extended tags 136 through 263 carry the no-obfuscation bit 62
    /// (objc4-951.7 `runtime/objc-internal.h:693-706, 765-787`).
    pub fn decode_tagged(
        &mut self,
        vmi: &VmiContext<MacOs<Driver>>,
        object: u64,
    ) -> Result<Option<(u16, u64)>, VmiError> {
        if !self.ensure_layout(vmi)? {
            return Ok(None);
        }
        let layout = match self.layout.as_ref() {
            Some(layout) => layout,
            None => return Ok(None),
        };
        if object & layout.tagged_mask == 0 {
            return Ok(None);
        }
        let slot = (object & 7) as usize;
        let extended = slot == 7;
        let encoded_ext = ((object >> 55) & 255) as u16;
        let unobfuscated = extended && encoded_ext >= 128;
        let decoded = if unobfuscated {
            object
        }
        else {
            object ^ layout.obfuscator
        };
        let tag = if extended {
            8 + if unobfuscated {
                encoded_ext
            }
            else {
                ((decoded >> 55) & 255) as u16
            }
        }
        else {
            match layout.permutations[..7]
                .iter()
                .position(|encoded| usize::from(*encoded) == slot)
            {
                Some(tag) => tag as u16,
                None => return Ok(None),
            }
        };
        let (left, right) = if extended {
            layout.extended_shifts
        }
        else {
            layout.payload_shifts
        };
        Ok(Some((tag, (decoded << left) >> right)))
    }

    /// Resolves message and selected objc_opt entry semantics without guest
    /// calls.
    pub fn invocation(
        &mut self,
        vmi: &VmiContext<MacOs<Driver>>,
        function: &str,
    ) -> Result<Option<Invocation>, VmiError> {
        let function = function.strip_prefix('_').unwrap_or(function);
        let optimized = semantic_spec(function);
        let super2 = matches!(function, "objc_msgSendSuper2" | "objc_msgSendSuper2_debug");
        let super_call = super2 || function == "objc_msgSendSuper";
        let forwarded_entry = matches!(
            function,
            "objc_msgForward"
                | "_objc_msgForward"
                | "objc_msgForward_impcache"
                | "_objc_msgForward_impcache"
        );
        if optimized.is_none()
            && !super_call
            && !forwarded_entry
            && !matches!(
                function,
                "objc_msgSend" | "objc_msgSend_noarg" | "objc_msgSend_debug"
            )
        {
            return Ok(None);
        }
        let registers = vmi.registers();
        let mut receiver = registers.regs[0];
        let selector = if optimized.is_some() {
            0
        }
        else {
            pointer(registers.regs[1])
        };
        let mut lookup = 0;
        if super_call {
            let record = pointer(receiver);
            receiver = vmi.read_u64(Va(record))?;
            lookup = pointer(vmi.read_u64(Va(record + 8))?);
            if super2 && lookup != 0 {
                lookup = pointer(vmi.read_u64(Va(lookup + CLASS_SUPERCLASS))?);
            }
        }
        let supported = self.ensure_layout(vmi)?;
        let class = if supported && receiver != 0 {
            self.receiver_class(vmi, receiver)?
        }
        else {
            0
        };
        let mut is_class = false;
        if class != 0 && self.load_class(vmi, class)? {
            is_class = self.info(class).is_some_and(|info| info.is_metaclass);
        }
        if !super_call {
            lookup = class;
        }
        let argument_base = if optimized.is_some() { 1 } else { 2 };
        let (method, status) = match optimized {
            Some((name, encoding)) => {
                let method = match self.semantic.get(name) {
                    Some(method) => Arc::clone(method),
                    None => {
                        let signature = match parse_method_encoding(encoding) {
                            Some(signature) => signature,
                            None => return Ok(None),
                        };
                        let method = Arc::new(Method {
                            selector: name.to_owned(),
                            signature,
                        });
                        self.semantic.insert(name, Arc::clone(&method));
                        method
                    }
                };
                (
                    method,
                    if receiver == 0 {
                        DispatchStatus::Nil
                    }
                    else {
                        DispatchStatus::Resolved
                    },
                )
            }
            None => {
                let text = self.selector_text(vmi, selector)?;
                let found = if supported && receiver != 0 && lookup != 0 {
                    self.resolve_method(vmi, lookup, selector, &text)?
                }
                else {
                    None
                };
                match found {
                    Some(found) => found,
                    None => {
                        let method = match self.unknown.get(&selector) {
                            Some(method) => Arc::clone(method),
                            None => {
                                let method = Arc::new(Method {
                                    selector: text.to_string(),
                                    signature: MethodSignature {
                                        result: AbiType::scalar(AbiKind::Unknown, 0),
                                        arguments: Vec::new(),
                                    },
                                });
                                if self.unknown.len() == METHOD_LIMIT {
                                    self.unknown.clear();
                                }
                                self.unknown.insert(selector, Arc::clone(&method));
                                method
                            }
                        };
                        let status = if receiver == 0 {
                            DispatchStatus::Nil
                        }
                        else if !supported {
                            DispatchStatus::UnsupportedLayout
                        }
                        else {
                            DispatchStatus::Unresolved
                        };
                        (method, status)
                    }
                }
            }
        };
        let status = if forwarded_entry {
            DispatchStatus::Forwarded
        }
        else {
            status
        };
        Ok(Some(Invocation {
            receiver,
            class,
            is_class,
            method,
            argument_base,
            status,
        }))
    }

    /// Reads the named runtime globals once and checks the supported encodings.
    fn ensure_layout(&mut self, vmi: &VmiContext<MacOs<Driver>>) -> Result<bool, VmiError> {
        if self.layout.is_some() {
            return Ok(true);
        }
        let cache = match self.cache.as_ref() {
            Some(cache) => cache,
            None => return Ok(false),
        };
        let globals = &self.globals;
        if !globals.complete() {
            return Ok(false);
        }
        if globals.isa_class_mask != 0 {
            let published = vmi.read_u64(Va(globals.isa_class_mask))?;
            if published != ISA_CLASS_MASK {
                tracing::warn!(
                    published = format_args!("{published:#x}"),
                    used = format_args!("{ISA_CLASS_MASK:#x}"),
                    "objc_debug_isa_class_mask differs from ISA_MASK_NOSIG"
                );
            }
        }
        let isa_mask = ISA_CLASS_MASK;
        let data_mask = vmi.read_u64(Va(globals.class_rw_data_mask))?;
        if data_mask != POINTER_MASK & !7 {
            return Ok(false);
        }
        let tagged_mask = vmi.read_u64(Va(globals.tagged_mask))?;
        if !matches!(tagged_mask, 0 | 0x8000_0000_0000_0000) {
            return Ok(false);
        }
        let slot_mask = vmi.read_u64(Va(globals.slot_mask))?;
        let ext_mask = vmi.read_u64(Va(globals.ext_mask))?;
        let ext_shift = vmi.read_u64(Va(globals.ext_slot_shift))?;
        let ext_slots = vmi.read_u64(Va(globals.ext_slot_mask))?;
        if slot_mask != 7
            || ext_mask != 0x8000_0000_0000_0007
            || ext_shift != 55
            || ext_slots != 255
        {
            return Ok(false);
        }
        let payload_shifts = (
            vmi.read_u32(Va(globals.payload_lshift))?,
            vmi.read_u32(Va(globals.payload_rshift))?,
        );
        let extended_shifts = (
            vmi.read_u32(Va(globals.ext_payload_lshift))?,
            vmi.read_u32(Va(globals.ext_payload_rshift))?,
        );
        if payload_shifts != (1, 4) || extended_shifts != (9, 12) {
            return Ok(false);
        }
        let mut basic_bytes = [0_u8; 64];
        let mut extended_bytes = [0_u8; 2048];
        let mut permutations = [0_u8; 8];
        vmi.read(Va(globals.tagged_classes), &mut basic_bytes)?;
        vmi.read(Va(globals.ext_classes), &mut extended_bytes)?;
        vmi.read(Va(globals.permutations), &mut permutations)?;
        if tagged_mask != 0 {
            let mut seen = 0_u8;
            for slot in &permutations[..7] {
                if *slot >= 7 || seen & (1_u8 << *slot) != 0 {
                    return Ok(false);
                }
                seen |= 1_u8 << *slot;
            }
            if permutations[7] != 7 {
                return Ok(false);
            }
        }
        let mut tagged_classes = [0; 8];
        let mut extended_classes = [0; 256];
        for (index, bytes) in basic_bytes.as_chunks::<8>().0.iter().enumerate() {
            tagged_classes[index] = pointer(u64::from_le_bytes(*bytes));
        }
        for (index, bytes) in extended_bytes.as_chunks::<8>().0.iter().enumerate() {
            extended_classes[index] = pointer(u64::from_le_bytes(*bytes));
        }
        let obfuscator = vmi.read_u64(Va(globals.obfuscator))?;
        if obfuscator & !0x3fff_ffff_ffff_fff8 != 0 {
            return Ok(false);
        }
        // dyld consults libobjc's objc_opt_t only for caches without
        // objcOpts (dyld-1378 common/DyldSharedCache.cpp:1942-1952).
        let string_base = if cache.objc_opts || self.opt_data == 0 {
            cache.string_base
        }
        else if vmi.read_u32(Va(self.opt_data))? == OBJC_OPT_VERSION {
            let offset = vmi.read_u64(Va(self.opt_data + OBJC_OPT_SELECTOR_BASE))?;
            if offset == 0 {
                None
            }
            else {
                Some(self.opt_data.wrapping_add(offset))
            }
        }
        else {
            None
        };
        self.layout = Some(Layout {
            isa_mask,
            data_mask,
            cache_start: cache.start,
            cache_end: cache.end,
            string_base,
            headers: globals.header_info_rws,
            disable_preattached: (self.disable_preattached != 0)
                .then_some(self.disable_preattached),
            tagged_mask,
            tagged_classes,
            extended_classes,
            permutations,
            obfuscator,
            payload_shifts,
            extended_shifts,
        });
        Ok(true)
    }

    /// Reads one isa on the ordinary warmed path, no object read for tags.
    fn receiver_class(
        &self,
        vmi: &VmiContext<MacOs<Driver>>,
        receiver: u64,
    ) -> Result<u64, VmiError> {
        let layout = match self.layout.as_ref() {
            Some(layout) => layout,
            None => return Ok(0),
        };
        if receiver & layout.tagged_mask != 0 {
            let slot = (receiver & 7) as usize;
            Ok(if slot == 7 {
                layout.extended_classes[((receiver >> 55) & 255) as usize]
            }
            else {
                layout.tagged_classes[slot]
            })
        }
        else {
            Ok(vmi.read_u64(Va(pointer(receiver)))? & layout.isa_mask)
        }
    }

    /// Loads RO or realized RW/extension metadata without requiring a catalog.
    fn load_class(
        &mut self,
        vmi: &VmiContext<MacOs<Driver>>,
        class: u64,
    ) -> Result<bool, VmiError> {
        if self.classes.contains_key(&class) {
            return Ok(true);
        }
        if class == 0 || class & 7 != 0 {
            return Ok(false);
        }
        let data_mask = match self.layout.as_ref() {
            Some(layout) => layout.data_mask,
            None => return Ok(false),
        };
        let bits = vmi.read_u64(Va(class + CLASS_BITS))?;
        let data = bits & data_mask;
        if data == 0 {
            return Ok(false);
        }
        let rw = if bits & FAST_IS_RW_POINTER != 0 {
            data
        }
        else {
            0
        };
        let ro = if rw != 0 {
            let reference = vmi.read_u64(Va(rw + RW_RO_OR_EXT))?;
            if reference & 1 != 0 {
                pointer(vmi.read_u64(Va(pointer(reference) & !1))?)
            }
            else {
                pointer(reference)
            }
        }
        else {
            data
        };
        if ro == 0 {
            return Ok(false);
        }
        let flags = vmi.read_u32(Va(ro))?;
        let name_address = pointer(vmi.read_u64(Va(ro + RO_NAME))?);
        let name = match read_text(vmi, name_address, NAME_LIMIT)? {
            Some(name) if !name.is_empty() => name,
            _ => return Ok(false),
        };
        let superclass = pointer(vmi.read_u64(Va(class + CLASS_SUPERCLASS))?);
        if self.classes.len() == CLASS_LIMIT {
            self.classes.clear();
            self.methods.clear();
        }
        self.classes.insert(
            class,
            ClassMetadata {
                info: ClassInfo {
                    name,
                    is_metaclass: flags & RO_META != 0,
                    superclass,
                },
                ro,
                rw,
            },
        );
        Ok(true)
    }

    /// Returns an interned selector string without per-call string copies.
    fn selector_text(
        &mut self,
        vmi: &VmiContext<MacOs<Driver>>,
        selector: u64,
    ) -> Result<Arc<str>, VmiError> {
        if let Some(text) = self.selectors.get(&selector) {
            return Ok(Arc::clone(text));
        }
        let text: Arc<str> = match read_text(vmi, selector, NAME_LIMIT)? {
            Some(text) => Arc::from(text),
            None => Arc::from("<unreadable-selector>"),
        };
        if self.selectors.len() == METHOD_LIMIT {
            self.selectors.clear();
        }
        self.selectors.insert(selector, Arc::clone(&text));
        Ok(text)
    }

    /// Searches live method collections in precedence order through
    /// inheritance.
    fn resolve_method(
        &mut self,
        vmi: &VmiContext<MacOs<Driver>>,
        class: u64,
        selector: u64,
        text: &str,
    ) -> Result<Option<(Arc<Method>, DispatchStatus)>, VmiError> {
        if let Some(method) = self.methods.get(&(class, selector)) {
            return Ok(Some((Arc::clone(method), DispatchStatus::Resolved)));
        }
        let mut current = class;
        let mut budget = LIST_LIMIT;
        for _ in 0..CLASS_DEPTH {
            if current == 0 || !self.load_class(vmi, current)? {
                break;
            }
            let metadata = match self.classes.get(&current) {
                Some(metadata) => metadata,
                None => break,
            };
            let superclass = metadata.info.superclass;
            // class_rw_ext_t::methods is a list_array_tt whose storage tags
            // are list, array and relative list of lists (objc4-951.7
            // runtime/objc-runtime-new.h:1909-1919). class_ro_t::baseMethods
            // tags only the relative list of lists, mapped here to tag two.
            let collection = if metadata.rw != 0 {
                let reference = vmi.read_u64(Va(metadata.rw + RW_RO_OR_EXT))?;
                if reference & 1 != 0 {
                    vmi.read_u64(Va((pointer(reference) & !1) + RWE_METHODS))?
                }
                else {
                    let base = vmi.read_u64(Va(metadata.ro + RO_BASE_METHODS))?;
                    if base & 1 != 0 {
                        (pointer(base) & !1) | 2
                    }
                    else {
                        base
                    }
                }
            }
            else {
                let base = vmi.read_u64(Va(metadata.ro + RO_BASE_METHODS))?;
                if base & 1 != 0 {
                    (pointer(base) & !1) | 2
                }
                else {
                    base
                }
            };
            if let Some((entry, kind)) =
                self.search_collection(vmi, collection, selector, &mut budget)?
            {
                let layout = match self.layout.as_ref() {
                    Some(layout) => layout,
                    None => return Ok(None),
                };
                let types = match kind {
                    EntryKind::Relative { shared_types } => {
                        let offset = vmi.read_u32(Va(entry + 4))? as i32;
                        if offset == 0 {
                            return Ok(None);
                        }
                        if shared_types {
                            match layout.string_base {
                                Some(base) => relative(base, offset),
                                None => return Ok(None),
                            }
                        }
                        else {
                            relative(entry + 4, offset)
                        }
                    }
                    EntryKind::Absolute => pointer(vmi.read_u64(Va(entry + 8))?),
                };
                let encoding = match read_text(vmi, types, ENCODING_LIMIT)? {
                    Some(encoding) => encoding,
                    None => return Ok(None),
                };
                let signature = match parse_method_encoding(&encoding) {
                    Some(signature) => signature,
                    None => return Ok(None),
                };
                let implementation = match kind {
                    EntryKind::Relative { .. } => 0,
                    EntryKind::Absolute => pointer(vmi.read_u64(Va(entry + 16))?),
                };
                let forwarded = implementation != 0 && self.forwarders.contains(&implementation);
                let method = Arc::new(Method {
                    selector: text.to_owned(),
                    signature,
                });
                if !forwarded {
                    if self.methods.len() == METHOD_LIMIT {
                        self.methods.clear();
                    }
                    self.methods.insert((class, selector), Arc::clone(&method));
                }
                return Ok(Some((
                    method,
                    if forwarded {
                        DispatchStatus::Forwarded
                    }
                    else {
                        DispatchStatus::Resolved
                    },
                )));
            }
            if superclass == current {
                break;
            }
            current = superclass;
        }
        Ok(None)
    }

    /// Traverses a direct list, writable list array or preattached relative
    /// lists.
    fn search_collection(
        &self,
        vmi: &VmiContext<MacOs<Driver>>,
        collection: u64,
        selector: u64,
        budget: &mut u32,
    ) -> Result<Option<(u64, EntryKind)>, VmiError> {
        let base = pointer(collection) & !3;
        if base == 0 || *budget == 0 {
            return Ok(None);
        }
        match collection & 3 {
            0 => self.search_list(vmi, collection, selector, budget),
            1 => {
                // list_array_tt::array_t is a 32-bit count, then pointers at
                // offset eight (objc4-951.7 runtime/objc-runtime-new.h:1687-1689).
                let count = vmi.read_u32(Va(base))?;
                if count > LIST_LIMIT {
                    return Ok(None);
                }
                for index in 0..count {
                    let list = vmi.read_u64(Va(base + 8 + u64::from(index) * 8))?;
                    if let Some(found) = self.search_list(vmi, list, selector, budget)? {
                        return Ok(Some(found));
                    }
                }
                Ok(None)
            }
            2 => {
                // relative_list_list_t entries hold a 16-bit image index and
                // a 48-bit offset from the entry (objc4-951.7
                // runtime/objc-runtime-new.h:1364-1372, 1380-1393). With
                // DisablePreattachedCategories only the last list counts
                // (lines 1459-1475).
                let layout = match self.layout.as_ref() {
                    Some(layout) => layout,
                    None => return Ok(None),
                };
                let disable_preattached = match layout.disable_preattached {
                    Some(address) => address,
                    None => return Ok(None),
                };
                let size = vmi.read_u32(Va(base))?;
                let count = vmi.read_u32(Va(base + 4))?;
                if size != 8 || count > LIST_LIMIT {
                    return Ok(None);
                }
                let disabled = vmi.read_u32(Va(disable_preattached))? != 0;
                let headers = pointer(vmi.read_u64(Va(layout.headers))?);
                if headers == 0 {
                    return Ok(None);
                }
                for index in 0..count {
                    if disabled && index + 1 != count {
                        continue;
                    }
                    let address = base + 8 + u64::from(index) * 8;
                    let encoded = vmi.read_u64(Va(address))?;
                    let header = encoded & 0xffff;
                    if vmi.read_u8(Va(headers + 8 + header * HEADER_INFO_RW_SIZE))? & 1 == 0 {
                        continue;
                    }
                    let list = address.wrapping_add_signed((encoded as i64) >> 16);
                    if let Some(found) = self.search_list(vmi, list, selector, budget)? {
                        return Ok(Some(found));
                    }
                }
                Ok(None)
            }
            _ => Ok(None),
        }
    }

    /// Searches compact cache, selector-reference-relative or absolute entries.
    ///
    /// Compact names in shared-cache lists are offsets from the relative
    /// selector base, elsewhere offsets to a selector reference (objc4-951.7
    /// `runtime/objc-runtime-new.h:1028-1037`).
    fn search_list(
        &self,
        vmi: &VmiContext<MacOs<Driver>>,
        raw: u64,
        selector: u64,
        budget: &mut u32,
    ) -> Result<Option<(u64, EntryKind)>, VmiError> {
        let list = pointer(raw) & !3;
        if list == 0 || *budget == 0 {
            return Ok(None);
        }
        *budget -= 1;
        let flags = vmi.read_u32(Va(list))?;
        let count = vmi.read_u32(Va(list + 4))?;
        let size = u64::from(flags & METHOD_SIZE_MASK);
        let authenticated = raw & BIG_SIGNED_METHOD_LIST != 0;
        let compact = flags & SMALL_METHOD_LIST != 0 && !authenticated;
        let expected = if compact {
            SMALL_METHOD_SIZE
        }
        else {
            BIG_METHOD_SIZE
        };
        if count > ENTRY_LIMIT || size < expected || size > 4096 {
            return Ok(None);
        }
        let layout = match self.layout.as_ref() {
            Some(layout) => layout,
            None => return Ok(None),
        };
        let shared = compact && layout.in_cache(list);
        let string_base = if shared {
            match layout.string_base {
                Some(base) => base,
                None => return Ok(None),
            }
        }
        else {
            0
        };
        let kind = if compact {
            EntryKind::Relative {
                shared_types: shared && flags & METHOD_LIST_TYPE_OFFSETS != 0,
            }
        }
        else {
            EntryKind::Absolute
        };
        let name_at = |index: u32| -> Result<u64, VmiError> {
            let entry = list + 8 + u64::from(index) * size;
            if compact {
                let offset = vmi.read_u32(Va(entry))? as i32;
                if shared {
                    Ok(relative(string_base, offset))
                }
                else {
                    Ok(pointer(vmi.read_u64(Va(relative(entry, offset)))?))
                }
            }
            else {
                Ok(pointer(vmi.read_u64(Va(entry))?))
            }
        };
        if flags & METHOD_LIST_SORTED == METHOD_LIST_SORTED && size == expected {
            let mut low = 0;
            let mut high = count;
            while low < high {
                let middle = low + (high - low) / 2;
                if name_at(middle)? < selector {
                    low = middle + 1;
                }
                else {
                    high = middle;
                }
            }
            if low < count && name_at(low)? == selector {
                return Ok(Some((list + 8 + u64::from(low) * size, kind)));
            }
        }
        else {
            for index in 0..count {
                if name_at(index)? == selector {
                    return Ok(Some((list + 8 + u64::from(index) * size, kind)));
                }
            }
        }
        Ok(None)
    }
}

/// Returns the `MUTATION_HOOKS` index a libobjc symbol names, if any.
fn mutation_hook(symbol: &str) -> Option<usize> {
    let base = function_base(symbol)?;
    MUTATION_HOOKS.iter().position(|hook| *hook == base)
}

/// Returns the unqualified function name of a plain or Itanium-mangled symbol.
///
/// Parses only `_Z[L]<length><name>` and `_ZN[K][L]<length><name>...E`
/// prefixes, enough to ignore the parameter manglings objc4 appends between
/// releases. Local entities (`_ZZ`), special names and compiler-split
/// `.cold` parts are not entry points and yield nothing.
fn function_base(symbol: &str) -> Option<&str> {
    if symbol.contains(".cold") {
        return None;
    }
    let symbol = match symbol.split_once('.') {
        Some((base, _)) => base,
        None => symbol,
    };
    let mangled = match symbol.strip_prefix("_Z") {
        Some(mangled) => mangled,
        None => return Some(symbol),
    };
    match mangled.strip_prefix('N') {
        Some(nested) => {
            let nested = nested.strip_prefix('K').unwrap_or(nested);
            let mut rest = nested.strip_prefix('L').unwrap_or(nested);
            let mut last = None;
            loop {
                if let Some(parameters) = rest.strip_prefix('E') {
                    return if parameters.is_empty() { None } else { last };
                }
                let (name, after) = source_name(rest)?;
                last = Some(name);
                rest = after;
            }
        }
        None => {
            let (name, parameters) = source_name(mangled.strip_prefix('L').unwrap_or(mangled))?;
            if parameters.is_empty() {
                None
            }
            else {
                Some(name)
            }
        }
    }
}

/// Splits an Itanium `<source-name>` (decimal length, then identifier) off a
/// mangling.
fn source_name(text: &str) -> Option<(&str, &str)> {
    let digits = text.bytes().take_while(u8::is_ascii_digit).count();
    if digits == 0 || text.starts_with('0') {
        return None;
    }
    let length: usize = text[..digits].parse().ok()?;
    let rest = &text[digits..];
    if length > rest.len() || !rest.is_char_boundary(length) {
        return None;
    }
    Some(rest.split_at(length))
}

/// Reads a little-endian `u32` from a header buffer at a fixed in-bounds
/// offset.
fn read_u32_le(bytes: &[u8], offset: usize) -> u32 {
    let mut word = [0_u8; 4];
    word.copy_from_slice(&bytes[offset..offset + 4]);
    u32::from_le_bytes(word)
}

/// Reads a dyld cache header field only when the header declares it.
///
/// `mappingOffset` is the size of the header the cache was built with, so a
/// field exists only when it ends at or below that offset. This is dyld's own
/// version test (dyld-1378 `common/DyldSharedCache.cpp:402, 471`).
fn cache_field(header: &[u8], offset: usize, size: usize) -> Option<u64> {
    let end = offset.checked_add(size)?;
    if header.len() < CACHE_MAPPING_OFFSET + 4 || end > header.len() {
        return None;
    }
    if (read_u32_le(header, CACHE_MAPPING_OFFSET) as usize) < end {
        return None;
    }
    let mut word = [0_u8; 8];
    word[..size].copy_from_slice(&header[offset..end]);
    Some(u64::from_le_bytes(word))
}

/// Returns `sharedRegionSize` when the header has subcache fields.
///
/// Older headers derive the size from their mapping table instead
/// (dyld-1378 `common/DyldSharedCache.cpp:399-417`).
fn shared_region_size(header: &[u8]) -> Option<u64> {
    cache_field(header, CACHE_SUB_CACHE_COUNT, 4)?;
    cache_field(header, CACHE_SHARED_REGION_SIZE, 8)
}

/// Computes the mapped size from the mapping table of a header without
/// subcaches.
///
/// Mirrors `DyldSharedCache::mappedSize` and `forEachRegion` (dyld-1378
/// `common/DyldSharedCache.cpp:169-189, 399-417`).
fn mapping_span(
    vmi: &VmiContext<MacOs<Driver>>,
    header: u64,
    bytes: &[u8],
) -> Result<Option<u64>, VmiError> {
    let offset = read_u32_le(bytes, CACHE_MAPPING_OFFSET);
    let count = read_u32_le(bytes, CACHE_MAPPING_COUNT);
    if offset > CACHE_MAPPING_OFFSET_LIMIT || count == 0 || count > CACHE_MAPPING_COUNT_LIMIT {
        return Ok(None);
    }
    let mut start = 0_u64;
    let mut end = 0_u64;
    for index in 0..u64::from(count) {
        let mapping = header + u64::from(offset) + index * CACHE_MAPPING_SIZE;
        let address = vmi.read_u64(Va(mapping))?;
        let size = vmi.read_u64(Va(mapping + 8))?;
        if index == 0 {
            start = address;
        }
        end = end.max(address.saturating_add(size));
    }
    Ok(end.checked_sub(start))
}

/// Returns the `ObjCOptimizationHeader` offset and size when declared and
/// present.
fn objc_opts(header: &[u8]) -> Option<(u64, u64)> {
    let offset = cache_field(header, CACHE_OBJC_OPTS_OFFSET, 8)?;
    let size = cache_field(header, CACHE_OBJC_OPTS_SIZE, 8)?;
    (offset != 0 && size != 0).then_some((offset, size))
}

/// Strips PAC and top-byte flags for identification, not authentication.
fn pointer(raw: u64) -> u64 {
    raw & POINTER_MASK
}

/// Computes a signed compact-entry offset without debug-build overflow.
fn relative(base: u64, offset: i32) -> u64 {
    base.wrapping_add_signed(i64::from(offset))
}

/// Compares a NUL-terminated guest string with `expected` without copying it.
///
/// Reads stay within one page per block, so a shorter string at the end of
/// a mapping does not fault on the following page.
fn text_matches(
    vmi: &VmiContext<MacOs<Driver>>,
    address: u64,
    expected: &str,
) -> Result<bool, VmiError> {
    if address == 0 {
        return Ok(false);
    }
    let expected = expected.as_bytes();
    let total = expected.len() + 1;
    let mut offset = 0;
    while offset < total {
        let current = address + offset as u64;
        let count = (total - offset)
            .min(64)
            .min(4096 - (current as usize & 4095));
        let mut block = [0_u8; 64];
        vmi.read(Va(current), &mut block[..count])?;
        for (index, byte) in block[..count].iter().enumerate() {
            let wanted = expected.get(offset + index).copied().unwrap_or(0);
            if *byte != wanted {
                return Ok(false);
            }
        }
        offset += count;
    }
    Ok(true)
}

/// Reads a bounded, explicitly terminated UTF-8 metadata string.
fn read_text(
    vmi: &VmiContext<MacOs<Driver>>,
    address: u64,
    limit: usize,
) -> Result<Option<String>, VmiError> {
    if address == 0 {
        return Ok(None);
    }
    let mut bytes = Vec::with_capacity(64);
    let mut offset = 0;
    while offset < limit {
        let current = address + offset as u64;
        let count = (limit - offset)
            .min(64)
            .min(4096 - (current as usize & 4095));
        let mut block = [0_u8; 64];
        vmi.read(Va(current), &mut block[..count])?;
        match block[..count].iter().position(|byte| *byte == 0) {
            Some(end) => {
                bytes.extend_from_slice(&block[..end]);
                return Ok(String::from_utf8(bytes).ok());
            }
            None => bytes.extend_from_slice(&block[..count]),
        }
        offset += count;
    }
    Ok(None)
}

/// Checked semantic selector and ABI for optimized entry points.
fn semantic_spec(function: &str) -> Option<(&'static str, &'static str)> {
    match function {
        "objc_opt_class" => Some(("class", "#16@0:8")),
        "objc_opt_self" => Some(("self", "@16@0:8")),
        "objc_opt_isKindOfClass" => Some(("isKindOfClass:", "B24@0:8#16")),
        "objc_opt_respondsToSelector" => Some(("respondsToSelector:", "B24@0:8:16")),
        _ => None,
    }
}

/// Symbol matching and versioned cache header boundaries.
#[cfg(test)]
mod tests {
    use super::{
        CACHE_HEADER_SIZE, CACHE_MAPPING_OFFSET, CACHE_OBJC_OPTS_OFFSET, CACHE_OBJC_OPTS_SIZE,
        CACHE_SHARED_REGION_SIZE, cache_field, function_base, mutation_hook, objc_opts,
        shared_region_size,
    };

    /// Builds a header whose declared size is `mapping_offset` with known field
    /// values.
    fn header(mapping_offset: u32) -> [u8; CACHE_HEADER_SIZE] {
        let mut bytes = [0_u8; CACHE_HEADER_SIZE];
        bytes[..7].copy_from_slice(b"dyld_v1");
        bytes[CACHE_MAPPING_OFFSET..CACHE_MAPPING_OFFSET + 4]
            .copy_from_slice(&mapping_offset.to_le_bytes());
        bytes[CACHE_SHARED_REGION_SIZE..CACHE_SHARED_REGION_SIZE + 8]
            .copy_from_slice(&0x4000_0000_u64.to_le_bytes());
        bytes[CACHE_OBJC_OPTS_OFFSET..CACHE_OBJC_OPTS_OFFSET + 8]
            .copy_from_slice(&0x2000_u64.to_le_bytes());
        bytes[CACHE_OBJC_OPTS_SIZE..CACHE_OBJC_OPTS_SIZE + 8]
            .copy_from_slice(&0x48_u64.to_le_bytes());
        bytes
    }

    /// Mangled locals match by base name whatever parameters follow.
    #[test]
    fn mangled_locals_match_by_base_name() {
        assert_eq!(
            function_base("_ZL16attachCategoriesP10objc_classPK21locstamped_category_tjS0_i"),
            Some("attachCategories")
        );
        assert_eq!(
            function_base("_ZL16attachCategoriesP10objc_classPK21locstamped_category_tji"),
            Some("attachCategories")
        );
        assert_eq!(
            function_base("_ZL17addMethods_finishP10objc_classP13method_list_t"),
            Some("addMethods_finish")
        );
        assert_eq!(
            function_base("_ZN4objc16attachCategoriesEP10objc_class"),
            Some("attachCategories")
        );
        assert_eq!(
            function_base("_ZNK15DyldSharedCache10mappedSizeEv"),
            Some("mappedSize")
        );
        assert_eq!(
            function_base("map_images_nolock"),
            Some("map_images_nolock")
        );
        assert_eq!(
            function_base("_ZL17addMethods_finishP10objc_classP13method_list_t.llvm.42"),
            Some("addMethods_finish")
        );
    }

    /// Local entities, blocks, split parts and malformed lengths never match a
    /// hook.
    #[test]
    fn non_entry_symbols_do_not_match() {
        assert_eq!(
            mutation_hook(
                "_ZZL16attachCategoriesP10objc_classPK21locstamped_category_tjS0_iENK3$_0clEPZL16attachCategoriesS0_S3_jS0_iE5Listsb"
            ),
            None
        );
        assert_eq!(
            mutation_hook("__ZL17addMethods_finishP10objc_classP13method_list_t_block_invoke"),
            None
        );
        assert_eq!(
            mutation_hook("_ZL16attachCategoriesP10objc_class.cold.1"),
            None
        );
        assert_eq!(mutation_hook("_ZL16attachCategories"), None);
        assert_eq!(mutation_hook("_ZL99attachCategoriesP10objc_class"), None);
        assert_eq!(mutation_hook("_ZL016attachCategoriesP10objc_class"), None);
        assert_eq!(mutation_hook("map_images"), None);
        assert_eq!(mutation_hook("map_images_nolock"), Some(0));
        assert_eq!(
            mutation_hook("_ZL17addMethods_finishP10objc_classP13method_list_t"),
            Some(2)
        );
    }

    /// Fields beyond the declared header size are absent, fields within it
    /// present.
    #[test]
    fn header_fields_require_mapping_offset_coverage() {
        let short = header(0x18c);
        assert_eq!(
            cache_field(&short, CACHE_SHARED_REGION_SIZE, 8),
            Some(0x4000_0000)
        );
        assert_eq!(shared_region_size(&short), None);
        assert_eq!(objc_opts(&short), None);

        let subcaches = header(0x190);
        assert_eq!(shared_region_size(&subcaches), Some(0x4000_0000));
        assert_eq!(objc_opts(&subcaches), None);

        let partial = header(0x1d8);
        assert_eq!(objc_opts(&partial), None);

        let full = header(0x238);
        assert_eq!(shared_region_size(&full), Some(0x4000_0000));
        assert_eq!(objc_opts(&full), Some((0x2000, 0x48)));

        assert_eq!(cache_field(&full, CACHE_HEADER_SIZE - 4, 8), None);
        assert_eq!(cache_field(&full[..8], CACHE_SHARED_REGION_SIZE, 8), None);
    }
}
