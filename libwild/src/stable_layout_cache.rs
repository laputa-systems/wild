//! Opt-in persistent stable-layout patches for ARM64 Mach-O executables.
//!
//! This is deliberately narrower than a general incremental linker. A cache hit requires a small,
//! bounded group of changed direct `MH_OBJECT` inputs, unchanged link-visible files and arguments,
//! unchanged object structure, unchanged relocation source fields, mutually disjoint output patch
//! ranges, and a cache-owned output image that exactly matches the cached baseline. Rustc's
//! equal-content temporary `.rlib` copies are the sole path exception: their directory spelling
//! may change only after every old-path byte is proved to be a rewritable `N_OSO` debug-map entry.
//! The fast path only changes ranges whose old layout is therefore still valid, then rebuilds the
//! UUID and ad-hoc signature. Every mismatch is a cache miss and performs the ordinary link; the
//! cache is never an exact-input output-reuse shortcut.

use crate::args::InputSpec;
use crate::args::macho::MachOArgs;
use crate::layout::FileLayout;
use crate::layout::Layout;
use crate::layout::ObjectLayout;
use crate::macho;
use crate::macho::MachO;
use crate::macho::output_section_id;
use crate::platform::Args as _;
use crate::platform::ObjectFile as _;
use crate::resolution::SectionSlot;
use crate::timing_phase;
use object::Endianness;
use object::macho::LC_UUID;
use object::macho::N_PEXT;
use rayon::prelude::*;
use std::collections::BTreeMap;
use std::collections::BTreeSet;
#[cfg(target_os = "macos")]
use std::ffi::CString;
use std::env;
use std::fs;
use std::io::Write as _;
use std::mem::size_of;
#[cfg(target_os = "macos")]
use std::os::unix::ffi::OsStrExt as _;
#[cfg(unix)]
use std::os::unix::fs::MetadataExt as _;
use std::path::Path;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::Mutex;
use std::sync::OnceLock;
use std::sync::atomic::AtomicBool;
use std::sync::atomic::Ordering;
use std::time::SystemTime;

const MAGIC: &[u8; 16] = b"WILD-MACHO-INC\0\0";
const STATE_MAGIC: &[u8; 16] = b"WILD-MACHO-STATE";
const VERSION: u32 = 11;
const STATE_VERSION: u32 = 6;
const HASH_SIZE: usize = 32;
const MAX_RECORDS: usize = 100_000;
/// Cache hits may compose a small group of independent direct objects. Bounding both dimensions
/// keeps an unexpectedly broad rebuild on the normal-link path instead of retaining many mapped
/// inputs or spending an unbounded amount of time validating their structures.
// Cargo's `linker-stress` profile can regenerate more than one object per codegen unit for a
// fixed-width source edit. Keep the multi-object cache path explicitly bounded, but cover the
// observed 18-object Rustc transition rather than falling back to a full link at 16.
const MAX_CHANGED_DIRECT_OBJECTS: usize = 32;
const MAX_CHANGED_DIRECT_OBJECT_BYTES: usize = 16 * 1024 * 1024;
const DIAGNOSTICS_ENV: &str = "WILD_MACHO_INCREMENTAL_CACHE_DIAGNOSTICS";
/// Domains the v5 structural digest away from ordinary byte hashes and older cache layouts.
const STRUCTURE_DIGEST_DOMAIN: &[u8] = b"wild-macho-stable-layout-structure-v5\0";
/// Rustc can regenerate private LLVM discriminator suffixes and reorder otherwise identical
/// relocation groups after a one-line incremental edit. This separate digest normalizes only that
/// compiler-private metadata while keeping every load command, section footprint, non-private
/// symbol, relocation group, and raw patch source bound to the baseline.
const RUSTC_PRIVATE_METADATA_DIGEST_DOMAIN: &[u8] =
    b"wild-macho-stable-layout-rustc-private-metadata-v1\0";
/// The sidecar is not an authenticated input, but random or torn sidecar corruption must become
/// a conservative cache miss before any persisted patch mapping is used.
const MANIFEST_CHECKSUM_DOMAIN: &[u8] = b"wild-macho-stable-layout-manifest-v10\0";
const STATE_CHECKSUM_DOMAIN: &[u8] = b"wild-macho-stable-layout-state-v6\0";
const CACHE_UUID_SEED_DOMAIN: &[u8] = b"wild-macho-stable-layout-cache-uuid-v1\0";
const CACHE_IMAGE_TOKEN_DOMAIN: &[u8] = b"wild-macho-stable-layout-cache-image-token-v1\0";
#[cfg(target_os = "macos")]
const CACHE_IMAGE_TOKEN_XATTR: &str = "com.wild.stable-layout-token";

#[derive(Clone, Debug)]
struct InputDigest {
    path: String,
    digest: [u8; HASH_SIZE],
    /// A changed direct object remains mapped until every selected patch has been validated and
    /// applied. It is intentionally process-local and excluded from manifest identity.
    direct_object_bytes: Option<DirectObjectSnapshot>,
    /// Filesystem identity captured around the full digest and persisted in the immutable
    /// manifest and mutable image state. Cache hits use it to avoid rehashing unchanged
    /// link-visible inputs.
    metadata: InputFileMetadata,
}

/// The changed object's bytes stay alive until patching completes. On macOS this is a read-only
/// mapping rather than a second 4MiB userspace copy. It is selected by strong file metadata;
/// the cache validates its nonpatch structure and protected relocation bytes before use.
#[derive(Clone, Debug)]
enum DirectObjectSnapshot {
    #[cfg(target_os = "macos")]
    Mapped(Arc<memmap2::Mmap>),
    InMemory(Arc<[u8]>),
}

impl DirectObjectSnapshot {
    fn bytes(&self) -> &[u8] {
        match self {
            #[cfg(target_os = "macos")]
            Self::Mapped(bytes) => bytes,
            Self::InMemory(bytes) => bytes,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct InputFileMetadata {
    len: u64,
    modified_seconds: u64,
    modified_nanoseconds: u32,
    device: u64,
    inode: u64,
    changed_seconds: i64,
    changed_nanoseconds: i64,
}

impl PartialEq for InputDigest {
    fn eq(&self, other: &Self) -> bool {
        self.path == other.path && self.digest == other.digest
    }
}

impl Eq for InputDigest {
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct PatchRange {
    input_offset: u64,
    output_offset: u64,
    len: u64,
}

/// An input-byte range excluded from the direct object's structural digest. Unlike a
/// [`PatchRange`], this has no raw-byte output mapping: linker-private nlist values are
/// recomputed from their containing section rather than copied from the input.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct InputRange {
    input_offset: u64,
    len: u64,
}

/// A fixed-width `n_value` rewrite for an otherwise structurally identical linker-private Mach-O
/// symbol.
///
/// The stable-layout cache normally treats every input nlist value as structural because moving a
/// symbol can also move an export, relocation target, unwind record, or debug-map function. A
/// record is emitted only for the deliberately narrow no-relocation, no-STABS case where the
/// symbol is local, its containing input section keeps its footprint, and the final nlist entry
/// has one independently identified baseline location. The source and destination values are
/// checked again on a hit before this eight-byte patch is applied.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct SymbolValuePatch {
    input_value_offset: u64,
    input_section_address: u64,
    input_section_size: u64,
    output_value_offset: u64,
    output_section_address: u64,
    baseline_value: u64,
}

impl SymbolValuePatch {
    fn signature_range(self) -> PatchRange {
        PatchRange {
            input_offset: 0,
            output_offset: self.output_value_offset,
            len: size_of::<u64>() as u64,
        }
    }
}

/// A byte range in the cache-owned output whose meaning is independently checked before a cache
/// hit changes it. This is intentionally distinct from [`PatchRange`], which maps bytes from a
/// changed direct object into the old output layout.
#[derive(Clone, Debug, Eq, PartialEq)]
struct OutputPathPatch {
    output_offset: u64,
    expected: Vec<u8>,
    replacement: Vec<u8>,
}

impl OutputPathPatch {
    fn signature_range(&self) -> PatchRange {
        PatchRange {
            input_offset: 0,
            output_offset: self.output_offset,
            len: self.replacement.len() as u64,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct ProtectedRange {
    input_offset: u64,
    bytes: Vec<u8>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct ObjectRecord {
    /// Position of this direct object in `Manifest::inputs`. Rustc gives rebuilt codegen objects
    /// a new hash-bearing pathname, so this stable positional role is the safe identity across a
    /// bounded incremental invocation.
    input_index: u32,
    structure_digest: [u8; HASH_SIZE],
    patches: Vec<PatchRange>,
    structure_masks: Vec<InputRange>,
    symbol_values: Vec<SymbolValuePatch>,
    protected: Vec<ProtectedRange>,
    /// A narrowly proven Rustc metadata equivalence relation. It is deliberately independent of
    /// the ordinary structural digest: generic Mach-O inputs continue to require byte-identical
    /// relocation and symbol-table metadata.
    rustc_private: Option<RustcPrivateObject>,
}

/// Output symbol spellings whose only permitted mutation is Rustc's terminal
/// `.llvm.<decimal>` discriminator. The output slot is exact and exclusive, so rewriting a
/// shorter replacement leaves its original NUL-terminated string allocation valid without
/// repacking the whole link-edit segment.
#[derive(Clone, Debug, Eq, PartialEq)]
struct RustcPrivateSymbolPatch {
    input_symbol_index: u32,
    canonical_name: Vec<u8>,
    expected: Vec<u8>,
    output_offset: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct RustcPrivateObject {
    metadata_digest: [u8; HASH_SIZE],
    symbols: Vec<RustcPrivateSymbolPatch>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct SignatureInfo {
    /// First byte excluded from the code-directory hash slots.
    code_limit: u64,
    /// First hash slot in the code signature.
    hashes_offset: u64,
    hash_count: u32,
    uuid_offset: u64,
    /// Identifier bytes in the code directory, between the fixed headers and hash slots.
    identifier_offset: u64,
    identifier_capacity: u64,
}

/// Identity for a cache-owned output after excluding the self-derived UUID and CodeDirectory
/// hash slots. The UUID must match the normalized digest and the slots have a separate digest,
/// so together these values still bind every byte in the output without an extra full-file pass
/// after `refresh_uuid_and_signature` has already calculated the normalized digest.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct OutputIdentity {
    normalized_digest: [u8; HASH_SIZE],
    signature_hashes_digest: [u8; HASH_SIZE],
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct Manifest {
    arguments_digest: [u8; HASH_SIZE],
    /// Original output path, retained as provenance for cache diagnostics. The cache owns a
    /// separate baseline image because Cargo can retire this hash-bearing artifact before the
    /// next linker invocation.
    baseline_output_path: String,
    output_identity: OutputIdentity,
    output_len: u64,
    signature: SignatureInfo,
    inputs: Vec<InputDigest>,
    /// Rustc recreates these rlibs under a fresh temporary directory for every final link. An
    /// index appears here only when the baseline image contains none of that input's exact path
    /// bytes, proving the pathname is not an observable part of this cached executable.
    cache_approved_rustc_temporary_archives: Vec<u32>,
    /// Direct objects may receive a new Cargo/rustc pathname even when their bytes did not
    /// change. An index appears here only when the raw argument spelling is canonical and the
    /// entire baseline image proves that spelling is not output-visible.
    cache_approved_moved_direct_objects: Vec<u32>,
    objects: Vec<ObjectRecord>,
}

/// Checked, allocation-free view of the immutable topology manifest used only on a cache hit.
///
/// The normal-link publication path still decodes [`Manifest`] into owned records because it
/// needs its complete input list. On a hit, however, the mutable image state already owns those
/// input identities. Rebuilding 13k patch records and their protected-relocation byte vectors
/// merely to inspect a selected rebuilt object showed up directly in the incremental-link profile.
/// This view validates the on-disk shape and yields the selected object's serialized ranges
/// without allocating patch records; it owns only the small path-approval index list.
struct ManifestView<'a> {
    arguments_digest: [u8; HASH_SIZE],
    /// The verified checksum also binds [`ImageState`] to this exact immutable topology, so a
    /// cache hit does not need a second full manifest hash after decoding it.
    checksum: [u8; HASH_SIZE],
    signature: SignatureInfo,
    input_count: usize,
    cache_approved_rustc_temporary_archives: Vec<u32>,
    cache_approved_moved_direct_objects: Vec<u32>,
    object_records: &'a [u8],
    object_count: usize,
}

struct ObjectRecordView<'a> {
    input_index: u32,
    structure_digest: [u8; HASH_SIZE],
    patch_bytes: &'a [u8],
    structure_mask_bytes: &'a [u8],
    symbol_value_bytes: &'a [u8],
    protected_bytes: &'a [u8],
    protected_count: usize,
    rustc_private: Option<RustcPrivateObjectView<'a>>,
}

#[derive(Clone, Copy)]
struct RustcPrivateObjectView<'a> {
    metadata_digest: [u8; HASH_SIZE],
    symbol_bytes: &'a [u8],
    symbol_count: usize,
}

/// A changed direct input paired with its immutable manifest record. Both contracts must hold
/// independently before their output patches can be composed on a cache-owned image.
struct ChangedObject<'manifest, 'input> {
    object: ObjectRecordView<'manifest>,
    bytes: &'input [u8],
    output_patches: Vec<OutputPathPatch>,
}

#[derive(Clone)]
struct PatchRangeIter<'a> {
    bytes: std::slice::ChunksExact<'a, u8>,
}

#[derive(Clone)]
struct InputRangeIter<'a> {
    bytes: std::slice::ChunksExact<'a, u8>,
}

#[derive(Clone, Copy)]
struct ProtectedRangeRef<'a> {
    input_offset: u64,
    bytes: &'a [u8],
}

struct ProtectedRangeIter<'a> {
    bytes: &'a [u8],
    offset: usize,
    remaining: usize,
}

/// Mutable identity for the cache-owned baseline image. Keeping this separate from the immutable
/// patch topology avoids rewriting tens of thousands of patch records after every cache hit.
/// It tracks every current input so consecutive bounded direct-object changes can affect different
/// objects while exact-input invocations still miss.
#[derive(Clone, Debug, Eq, PartialEq)]
struct ImageState {
    arguments_digest: [u8; HASH_SIZE],
    /// Binds this mutable state to exactly one immutable patch topology. Publishing a new image
    /// and state before its structural manifest can therefore only cause a safe cache miss.
    manifest_checksum: [u8; HASH_SIZE],
    /// The cache-owned image carries this xattr generation token. APFS clones and explicit
    /// benchmark snapshot copies retain it, while an unrelated image at the same cache path does
    /// not become a patch source merely because it has a plausible size.
    cache_image_token: [u8; 16],
    /// A deterministic chain of bounded changed-object bytes. It drives the next `LC_UUID`
    /// without a full-file BLAKE3 pass; code-directory pages are still refreshed exactly.
    uuid_seed: [u8; HASH_SIZE],
    output_len: u64,
    inputs: Vec<InputDigest>,
}

struct Candidate {
    bytes: Vec<u8>,
    patches: Vec<PatchRange>,
    structure_masks: Vec<InputRange>,
    symbol_values: Vec<SymbolValuePatch>,
    protected: Vec<ProtectedRange>,
    rustc_private_symbols: Option<Vec<RustcPrivateSymbolPatch>>,
}

#[derive(Clone, Debug)]
struct RustcPrivateMetadata {
    digest: [u8; HASH_SIZE],
    symbols: Vec<InputSymbol>,
}

#[derive(Clone, Debug)]
struct InputSymbol {
    index: usize,
    name: Vec<u8>,
    n_type: u8,
    n_sect: u8,
    n_desc: u16,
    n_value: u64,
}

/// The cache normally patches an owned image in memory. On APFS, a cloned temporary lets the
/// kernel keep unchanged output pages shared while preserving the same atomic replacement rule.
enum MutableOutput {
    InMemory(Vec<u8>),
    #[cfg(target_os = "macos")]
    Cloned {
        staged_path: PathBuf,
        mapping: memmap2::MmapMut,
    },
}

enum PreparedOutput {
    InMemory(Vec<u8>),
    #[cfg(target_os = "macos")]
    Cloned(PathBuf),
}

/// A cache service owns at most one current image. Keeping the image in the service removes the
/// repeated full-image read/allocation from consecutive links while the normal disk sidecars
/// remain the recovery source if that service exits.
struct ResidentImage {
    cache_image: PathBuf,
    state: ImageState,
    storage: ResidentImageStorage,
}

enum ResidentImageStorage {
    InMemory(Vec<u8>),
    #[cfg(target_os = "macos")]
    Cloned(PathBuf),
}

static RESIDENT_IMAGE_CACHE_ENABLED: AtomicBool = AtomicBool::new(false);
static RESIDENT_IMAGE: OnceLock<Mutex<Option<ResidentImage>>> = OnceLock::new();

pub(crate) fn enable_resident_image_cache() {
    RESIDENT_IMAGE_CACHE_ENABLED.store(true, Ordering::Relaxed);
    if env::var_os(DIAGNOSTICS_ENV).is_some() {
        eprintln!("wild: Mach-O stable-layout resident image cache enabled");
    }
}

/// Releases the service-only staged image before the cache service exits. The disk cache image
/// remains the ordinary crash-recovery baseline; this clone only exists to make the next resident
/// request copy-on-write without holding an extra full output after the bounded idle lifetime.
pub(crate) fn clear_resident_image_cache() {
    let Some(resident) = RESIDENT_IMAGE.get() else {
        return;
    };
    let Ok(mut resident) = resident.lock() else {
        return;
    };
    let Some(image) = resident.take() else {
        return;
    };
    #[cfg(target_os = "macos")]
    if let ResidentImageStorage::Cloned(path) = image.storage {
        let _ = fs::remove_file(path);
    }
}

fn resident_image_cache_enabled() -> bool {
    RESIDENT_IMAGE_CACHE_ENABLED.load(Ordering::Relaxed)
}

fn resident_image_state(cache_image: &Path) -> Option<ImageState> {
    let state = resident_image_cache_enabled().then(|| {
        RESIDENT_IMAGE
            .get_or_init(|| Mutex::new(None))
            .lock()
            .ok()?
            .as_ref()
            .filter(|image| image.cache_image == cache_image)
            .map(|image| image.state.clone())
    })?;
    if env::var_os(DIAGNOSTICS_ENV).is_some() {
        eprintln!(
            "wild: Mach-O stable-layout resident image state {} for {}",
            if state.is_some() { "hit" } else { "miss" },
            cache_image.display()
        );
    }
    state
}

fn take_resident_image(cache_image: &Path, state: &ImageState) -> Option<ResidentImageStorage> {
    resident_image_cache_enabled().then(|| {
        let mut resident = RESIDENT_IMAGE.get_or_init(|| Mutex::new(None)).lock().ok()?;
        (resident.as_ref().is_some_and(|image| {
            image.cache_image == cache_image && image.state == *state
        }))
        .then(|| match &resident.as_ref().expect("resident image was checked").storage {
            ResidentImageStorage::InMemory(_) => {
                resident.take().expect("resident image was checked").storage
            }
            #[cfg(target_os = "macos")]
            ResidentImageStorage::Cloned(path) => ResidentImageStorage::Cloned(path.clone()),
        })
    })?
}

fn store_resident_image(cache_image: PathBuf, state: ImageState, storage: ResidentImageStorage) {
    if resident_image_cache_enabled() {
        if let Ok(mut resident) = RESIDENT_IMAGE.get_or_init(|| Mutex::new(None)).lock() {
            if env::var_os(DIAGNOSTICS_ENV).is_some() {
                eprintln!(
                    "wild: Mach-O stable-layout resident image store: {} for {}",
                    match &storage {
                        ResidentImageStorage::InMemory(bytes) => format!("{} in-memory bytes", bytes.len()),
                        #[cfg(target_os = "macos")]
                        ResidentImageStorage::Cloned(path) => format!("clone {}", path.display()),
                    },
                    cache_image.display()
                );
            }
            #[cfg(target_os = "macos")]
            let new_clone_path = match &storage {
                ResidentImageStorage::InMemory(_) => None,
                ResidentImageStorage::Cloned(path) => Some(path.clone()),
            };
            let previous = resident.replace(ResidentImage {
                cache_image,
                state,
                storage,
            });
            #[cfg(target_os = "macos")]
            if let Some(ResidentImage {
                storage: ResidentImageStorage::Cloned(path),
                ..
            }) = previous
            {
                if new_clone_path.as_ref() != Some(&path) {
                    let _ = fs::remove_file(path);
                }
            }
        }
    }
}

#[cfg(target_os = "macos")]
fn clone_resident_image(path: &Path, args: &MachOArgs) -> Option<MutableOutput> {
    let staged_path = clone_temporary_path(args.output());
    clone_file(path, &staged_path).ok()?;
    let file = match fs::OpenOptions::new().read(true).write(true).open(&staged_path) {
        Ok(file) => file,
        Err(_) => {
            let _ = fs::remove_file(&staged_path);
            return None;
        }
    };
    if crate::make_executable(&file).is_err() {
        let _ = fs::remove_file(&staged_path);
        return None;
    }
    let mapping = match unsafe { memmap2::MmapOptions::new().map_mut(&file) } {
        Ok(mapping) => mapping,
        Err(_) => {
            let _ = fs::remove_file(&staged_path);
            return None;
        }
    };
    Some(MutableOutput::Cloned {
        staged_path,
        mapping,
    })
}

#[cfg(target_os = "macos")]
fn store_resident_clone(cache_dir: &Path, args: &MachOArgs, cache_image: PathBuf, state: ImageState) {
    if !resident_image_cache_enabled() {
        return;
    }
    let destination = resident_image_path(cache_dir, args);
    let staged_path = clone_temporary_path(&destination);
    if clone_file(args.output(), &staged_path).is_err() {
        return;
    }
    if fs::rename(&staged_path, &destination).is_err() {
        let _ = fs::remove_file(staged_path);
        return;
    }
    store_resident_image(cache_image, state, ResidentImageStorage::Cloned(destination));
}

impl MutableOutput {
    fn bytes(&self) -> &[u8] {
        match self {
            Self::InMemory(bytes) => bytes,
            #[cfg(target_os = "macos")]
            Self::Cloned { mapping, .. } => mapping,
        }
    }

    fn bytes_mut(&mut self) -> &mut [u8] {
        match self {
            Self::InMemory(bytes) => bytes,
            #[cfg(target_os = "macos")]
            Self::Cloned { mapping, .. } => mapping,
        }
    }

    /// Match the ordinary Mach-O writer's final `MS_INVALIDATE` after updating an embedded code
    /// signature. Without it, a clonefile-backed mapping can retain stale kernel signature state
    /// for its inode: `codesign` accepts the final bytes, yet `exec` receives SIGKILL.
    fn invalidate_code_signature_cache(&mut self) {
        #[cfg(target_os = "macos")]
        if let Self::Cloned { mapping, .. } = self {
            unsafe {
                libc::msync(
                    mapping.as_mut_ptr().cast(),
                    mapping.len(),
                    libc::MS_INVALIDATE,
                );
            }
        }
    }

    fn discard(self) {
        #[cfg(target_os = "macos")]
        if let Self::Cloned { staged_path, .. } = self {
            let _ = fs::remove_file(staged_path);
        }
    }

    fn finish(self) -> PreparedOutput {
        match self {
            Self::InMemory(bytes) => PreparedOutput::InMemory(bytes),
            #[cfg(target_os = "macos")]
            Self::Cloned {
                staged_path,
                mapping,
            } => {
                // Dropping the mapping before cloning/renaming makes all patched pages visible
                // through the staged file without imposing an fsync durability contract.
                drop(mapping);
                PreparedOutput::Cloned(staged_path)
            }
        }
    }
}

impl PreparedOutput {
    fn discard(self) {
        #[cfg(target_os = "macos")]
        if let Self::Cloned(path) = self {
            let _ = fs::remove_file(path);
        }
    }
}

/// Emits opt-in diagnostics for a conservative miss without changing ordinary linker stderr.
/// This is intentionally separate from the cache-hit marker, which benchmark automation uses as
/// proof that a changed direct link took the fast path.
fn cache_miss(reason: &str) -> bool {
    if std::env::var_os(DIAGNOSTICS_ENV).is_some() {
        eprintln!("wild: Mach-O stable-layout cache miss: {reason}");
    }
    false
}

/// Attempts a bounded, independently validated stable-layout patch. All errors are intentionally
/// cache misses: the caller will run the normal linker, which is both the correctness fallback
/// and cache recovery path for interrupted writers or manually deleted cache data.
pub(crate) fn try_apply(args: &MachOArgs) -> bool {
    let hit = try_apply_inner(args);
    if !hit {
        // A normal link is the recovery path for every cache miss. Do not leave a previous
        // image/state pair available for that link's next invocation: if staging the new
        // baseline fails, retaining the old pair would let a later changed-object invocation
        // patch an output from a different layout lineage. Removing only these exact sidecars
        // is fail-closed and keeps the ordinary link authoritative.
        discard_cache_sidecars(args);
    }
    hit
}

fn try_apply_inner(args: &MachOArgs) -> bool {
    let Some(cache_dir) = args.incremental_cache.as_deref() else {
        return false;
    };
    if args.incremental_cache_attempted.swap(true, Ordering::Relaxed) {
        return false;
    }
    if !cache_is_eligible(args) {
        return false;
    }
    timing_phase!("Try Mach-O stable-layout cache");
    let cache_path = cache_path(cache_dir, args);
    let manifest_bytes = {
        timing_phase!("Mach-O stable-layout cache: read manifest");
        let Ok(bytes) = fs::read(cache_path) else {
            return cache_miss("logical manifest is absent");
        };
        bytes
    };
    let manifest = {
        timing_phase!("Mach-O stable-layout cache: decode manifest");
        let Ok(manifest) = ManifestView::decode(&manifest_bytes) else {
            return cache_miss("logical manifest is corrupt or incompatible");
        };
        manifest
    };
    let arguments_match = {
        timing_phase!("Mach-O stable-layout cache: verify arguments");
        manifest.arguments_digest == arguments_digest(args)
    };
    if !arguments_match {
        return cache_miss("normalized argument digest differs");
    }
    let cache_image = cache_image_path(cache_dir, args);
    let mut state = if let Some(state) = resident_image_state(&cache_image) {
        state
    } else {
        let state_bytes = {
            timing_phase!("Mach-O stable-layout cache: read image state");
            let Ok(bytes) = fs::read(cache_state_path(cache_dir, args)) else {
                return cache_miss("image state is absent");
            };
            bytes
        };
        {
            timing_phase!("Mach-O stable-layout cache: decode image state");
            let Ok(state) = ImageState::decode(&state_bytes) else {
                return cache_miss("image state is corrupt or incompatible");
            };
            state
        }
    };
    let state_matches_manifest = {
        timing_phase!("Mach-O stable-layout cache: verify image state");
        state.arguments_digest == manifest.arguments_digest
            && state.manifest_checksum == manifest.checksum
            && state.inputs.len() == manifest.input_count
    };
    if !state_matches_manifest {
        return cache_miss("image state does not match the structural manifest");
    }
    // The cache image, rather than Cargo's current `-o` pathname, is the baseline for every
    // replay. Cargo can remove or replace that pathname before invoking us; treating it as an
    // input used to force two full-image reads on the hot path. The image is cache-owned and
    // guarded by its device/inode/ctime identity before and after the APFS clone below.
    let cache_image_metadata = {
        timing_phase!("Mach-O stable-layout cache: verify cache image identity");
        input_file_metadata(&cache_image.to_string_lossy())
    };
    if cache_image_token(&cache_image) != Some(state.cache_image_token) {
        return cache_miss("cache-owned baseline image identity differs");
    }

    let current_inputs = {
        timing_phase!("Mach-O stable-layout cache: fingerprint inputs");
        let Some(inputs) = input_digests_for_cache_hit(
            args,
            &state.inputs,
            &manifest.cache_approved_rustc_temporary_archives,
            &manifest.cache_approved_moved_direct_objects,
        ) else {
            return cache_miss("unable to read every link-visible input");
        };
        inputs
    };
    if current_inputs.len() != state.inputs.len() {
        return cache_miss("link-visible input count differs");
    }
    let changed = {
        timing_phase!("Mach-O stable-layout cache: select changed inputs");
        current_inputs
            .iter()
            .zip(&state.inputs)
            .enumerate()
            .filter_map(|(index, (current, cached))| {
                input_identity_changed(
                    current,
                    cached,
                    u32::try_from(index).is_ok_and(|input_index| {
                        manifest
                            .cache_approved_rustc_temporary_archives
                            .binary_search(&input_index)
                            .is_ok()
                    }),
                    u32::try_from(index).is_ok_and(|input_index| {
                        manifest
                            .cache_approved_moved_direct_objects
                            .binary_search(&input_index)
                            .is_ok()
                    }),
                )
                .then_some(index)
            })
            .collect::<Vec<_>>()
    };
    if !changed_object_count_is_supported(changed.len()) {
        // Deliberately do not reuse an output for an exact-input invocation. The cache patches a
        // small, bounded group of independently verified direct objects; all other topology goes
        // through a normal link rather than becoming an output-copy/cache hit.
        return cache_miss(&format!(
            "input comparison found {} changed inputs (expected 1..={MAX_CHANGED_DIRECT_OBJECTS})",
            changed.len(),
        ));
    }
    let changed_input_indices = changed
        .iter()
        .map(|&index| {
            let changed_input = &current_inputs[index];
            let cached_input = &state.inputs[index];
            if !is_mach_object_path(&changed_input.path) || !is_mach_object_path(&cached_input.path) {
                return Err(cache_miss(&format!(
                    "changed input {index} is not a direct Mach-O object: {}",
                    changed_input.path
                )));
            }
            u32::try_from(index).map_err(|_| cache_miss("changed input index is not representable"))
        })
        .collect::<Result<Vec<_>, _>>();
    let Ok(changed_input_indices) = changed_input_indices else {
        return false;
    };
    let objects = {
        timing_phase!("Mach-O stable-layout cache: find cached object records");
        let objects = match changed_input_indices.as_slice() {
            [input_index] => manifest
                .object_for_input(*input_index)
                .ok()
                .flatten()
                .map(|object| vec![object]),
            _ => manifest.objects_for_inputs(&changed_input_indices).ok(),
        };
        let Some(objects) = objects else {
            let missing = changed_input_indices.iter().find(|input_index| {
                manifest
                    .object_for_input(**input_index)
                    .ok()
                    .flatten()
                    .is_none()
            });
            return cache_miss(&format!(
                "a changed object has no cached positional record{}",
                missing.map(|input_index| format!(" at input {input_index}")).unwrap_or_default()
            ));
        };
        objects
    };

    let changed_objects = {
        timing_phase!("Mach-O stable-layout cache: validate changed object snapshots");
        let mut changed_objects = Vec::with_capacity(objects.len());
        let mut total_object_bytes = 0_usize;
        for (changed_index, object) in changed.iter().copied().zip(objects) {
            let changed_input = &current_inputs[changed_index];
            let Some(current_object) = changed_input
                .direct_object_bytes
                .as_ref()
                .map(DirectObjectSnapshot::bytes)
            else {
                return cache_miss("changed direct object snapshot is absent");
            };
            let Some(next_total_object_bytes) = total_object_bytes.checked_add(current_object.len()) else {
                return cache_miss("changed direct object byte count overflows");
            };
            if next_total_object_bytes > MAX_CHANGED_DIRECT_OBJECT_BYTES {
                return cache_miss(&format!(
                    "changed direct objects total {next_total_object_bytes} bytes (maximum {MAX_CHANGED_DIRECT_OBJECT_BYTES})"
                ));
            }
            total_object_bytes = next_total_object_bytes;

            // This immutable snapshot is the exact mapping selected by the initial metadata scan.
            // The metadata recheck below guards against its source pathname being replaced before
            // we publish the composed patched output.
            let (structure_matches, output_patches) = {
                timing_phase!("Mach-O stable-layout cache: compute object structure digest");
                let ordinary = object.structure_digest
                    == masked_digest_from_iter(current_object, object.structure_masks());
                if ordinary {
                    (true, Vec::new())
                } else {
                    match object.rustc_private_output_patches(current_object) {
                        Some(patches) => (true, patches),
                        None => (false, Vec::new()),
                    }
                }
            };
            if !structure_matches {
                return cache_miss("changed object structural digest differs");
            }
            let relocation_sources_match = {
                timing_phase!("Mach-O stable-layout cache: validate relocation source");
                protected_ranges_match_from_iter(current_object, object.protected())
            };
            if !relocation_sources_match {
                return cache_miss("changed object relocation storage differs");
            }
            changed_objects.push(ChangedObject {
                object,
                bytes: current_object,
                output_patches,
            });
        }
        changed_objects
    };

    let mut output = {
        timing_phase!("Mach-O stable-layout cache: materialize cache-owned image");
        #[cfg(target_os = "macos")]
        let output = if resident_image_cache_enabled() {
            take_resident_image(&cache_image, &state)
                .and_then(|storage| match storage {
                    ResidentImageStorage::InMemory(bytes) => Some(MutableOutput::InMemory(bytes)),
                    ResidentImageStorage::Cloned(path) => clone_resident_image(&path, args),
                })
                // First resident request can stage the immutable cache image as an APFS COW
                // clone. This avoids both a 29 MiB userspace copy and a 29 MiB output write.
                .or_else(|| clone_baseline_image(cache_dir, args))
                .or_else(|| fs::read(&cache_image).ok().map(MutableOutput::InMemory))
        } else {
            fs::read(&cache_image).ok().map(MutableOutput::InMemory)
        };
        #[cfg(not(target_os = "macos"))]
        let output = take_resident_image(&cache_image, &state)
            .and_then(|storage| match storage {
                ResidentImageStorage::InMemory(bytes) => Some(MutableOutput::InMemory(bytes)),
            })
            .or_else(|| fs::read(&cache_image).ok().map(MutableOutput::InMemory));
        let Some(output) = output else {
            return cache_miss("owned baseline image is absent");
        };
        if output.bytes().len() as u64 != state.output_len
            || cache_image_metadata.is_none()
            || input_file_metadata(&cache_image.to_string_lossy()) != cache_image_metadata
            || cache_image_token(&cache_image) != Some(state.cache_image_token)
        {
            output.discard();
            return cache_miss("cache-owned baseline image changed while cloning");
        }
        output
    };
    if !moved_direct_object_paths_are_unobservable(
        output.bytes(),
        args,
        &current_inputs,
        &state.inputs,
        &manifest.cache_approved_moved_direct_objects,
    ) {
        output.discard();
        return cache_miss("a moved direct-object pathname is visible in the baseline image");
    };
    let archive_path_patches = {
        timing_phase!("Mach-O stable-layout cache: prepare rustc archive debug paths");
        let Some(patches) = rustc_temporary_archive_path_patches(
            output.bytes(),
            args,
            &current_inputs,
            &state.inputs,
            &manifest.cache_approved_rustc_temporary_archives,
        ) else {
            output.discard();
            return cache_miss("rustc archive path is not safely rewritable in the debug map");
        };
        patches
    };
    let next_uuid_seed = cache_uuid_seed(state.uuid_seed, &changed_objects);
    {
        timing_phase!("Mach-O stable-layout cache: patch and sign");
        if let [changed] = changed_objects.as_slice() {
            // Retain the existing one-object hot path. The immutable record already proves that
            // its raw and symbol-value ranges do not overlap, so sorting them merely to prove a
            // cross-record invariant would tax the common single-object case.
            if !apply_output_path_patches(output.bytes_mut(), &archive_path_patches)
                || !apply_output_path_patches(output.bytes_mut(), &changed.output_patches)
                || !apply_patches_from_iter(
                    output.bytes_mut(),
                    changed.bytes,
                    changed.object.patches(),
                )
                || !apply_symbol_value_patches_from_iter(
                    output.bytes_mut(),
                    changed.bytes,
                    changed.object.symbol_values(),
                )
            {
                output.discard();
                return cache_miss("patch mapping or signature refresh is not valid");
            }
            if !refresh_uuid_and_signature(
                output.bytes_mut(),
                &manifest.signature,
                args,
                &next_uuid_seed,
                changed
                    .object
                    .patches()
                    .chain(changed.object.symbol_values().map(SymbolValuePatch::signature_range))
                    .chain(changed.output_patches.iter().map(OutputPathPatch::signature_range))
                    .chain(archive_path_patches.iter().map(OutputPathPatch::signature_range)),
            ) {
                output.discard();
                return cache_miss("patch mapping or signature refresh is not valid");
            }
            output.invalidate_code_signature_cache();
        } else {
            let changed_output_ranges = changed_objects
                .iter()
                .flat_map(|changed| {
                    changed
                        .object
                        .patches()
                        .chain(changed.object.symbol_values().map(SymbolValuePatch::signature_range))
                        .chain(changed.output_patches.iter().map(OutputPathPatch::signature_range))
                })
                .chain(archive_path_patches.iter().map(OutputPathPatch::signature_range))
                .collect::<Vec<_>>();
            if !output_patch_ranges_are_disjoint(
                output.bytes().len(),
                changed_output_ranges.iter().copied(),
            ) || !output_path_patches_are_applicable(output.bytes(), &archive_path_patches)
                || !changed_objects.iter().all(|changed| {
                    output_path_patches_are_applicable(output.bytes(), &changed.output_patches)
                        &&
                    patch_ranges_are_applicable(
                        output.bytes().len(),
                        changed.bytes,
                        changed.object.patches(),
                    ) && symbol_value_patches_are_applicable(
                        output.bytes(),
                        changed.bytes,
                        changed.object.symbol_values(),
                    )
                })
            {
                output.discard();
                return cache_miss("patch mapping overlaps or is not valid");
            }
            let patch_mapping_applied = {
                let output_bytes = output.bytes_mut();
                apply_output_path_patches(output_bytes, &archive_path_patches)
                    && changed_objects.iter().all(|changed| {
                        apply_output_path_patches(output_bytes, &changed.output_patches)
                            && apply_patches_from_iter(output_bytes, changed.bytes, changed.object.patches())
                            && apply_symbol_value_patches_from_iter(
                                output_bytes,
                                changed.bytes,
                                changed.object.symbol_values(),
                            )
                    })
            };
            if !patch_mapping_applied {
                output.discard();
                return cache_miss("patch mapping or signature refresh is not valid");
            }
            if !refresh_uuid_and_signature(
                output.bytes_mut(),
                &manifest.signature,
                args,
                &next_uuid_seed,
                changed_output_ranges.iter().copied(),
            ) {
                output.discard();
                return cache_miss("patch mapping or signature refresh is not valid");
            }
            output.invalidate_code_signature_cache();
        }
    }

    // Recheck the filesystem identity captured around the initial full input hash immediately
    // before publishing. This is the normal linker's mtime race guard, strengthened on Unix with
    // device, inode, length, and ctime checks, without paying for a second full input hash.
    {
        timing_phase!("Mach-O stable-layout cache: recheck input metadata");
        if !input_metadata_snapshots_match(args, &current_inputs) {
            output.discard();
            return cache_miss("an input changed before output publication");
        }
    }

    let output_len = output.bytes().len() as u64;
    let output = output.finish();

    // Mach-O code-signature verification is cached by vnode on macOS. Never mutate the previous
    // executable's inode in place: write and atomically replace it, matching the normal Mach-O
    // writer's `UnlinkAndReplace` policy.
    {
        timing_phase!("Mach-O stable-layout cache: atomically replace output");
        let write_result = match &output {
            PreparedOutput::InMemory(bytes) => write_output_atomic(args.output(), bytes),
            #[cfg(target_os = "macos")]
            PreparedOutput::Cloned(staged_path) => {
                replace_output_after_detaching_previous(staged_path, args.output())
            }
        };
        if write_result.is_err() {
            output.discard();
            return cache_miss("atomic current-output replacement failed");
        }
    }

    state.uuid_seed = next_uuid_seed;
    state.output_len = output_len;
    // The direct object is the one patched input, but equal-content rlibs can move between
    // rustc's per-link temporary directories. Retain every current physical identity so the
    // metadata race guard checks the paths that produced this image on the next cache hit. Keep
    // the initial image/state pair until the bounded patch group is full: successive one-object
    // edits can patch directly from that immutable baseline, avoiding a second full-image write
    // on the hot path. A full group checkpoints the current image so the next edit starts a new
    // bounded lineage rather than accumulating an unbounded patch set.
    let resident_state = resident_state_after_hit(&state, current_inputs);
    if changed.len() == MAX_CHANGED_DIRECT_OBJECTS {
        state = resident_state.clone();
        // Publish the owned image before its matching mutable state. An interrupted update can
        // leave an image and state with different digests, which is deliberately a cache miss
        // rather than a potentially stale patch source. The structural manifest is immutable on
        // cache hits.
        {
            timing_phase!("Mach-O stable-layout cache: atomically update sidecars");
            let image_result = match &output {
                PreparedOutput::InMemory(bytes) => write_cache_image_atomic(cache_dir, args, bytes),
                #[cfg(target_os = "macos")]
                PreparedOutput::Cloned(_) => clone_cache_image_atomic(cache_dir, args),
            };
            if image_result.is_err() {
                return cache_miss("atomic baseline-image replacement failed");
            }
            let image_path = cache_image_path(cache_dir, args);
            if !set_cache_image_token(&image_path, state.cache_image_token)
                || cache_image_token(&image_path) != Some(state.cache_image_token)
            {
                return cache_miss("published baseline image token is unavailable");
            }
            if write_image_state_atomic(cache_dir, args, &state).is_err() {
                return cache_miss("image state replacement failed");
            }
        }
    }
    if resident_image_cache_enabled() {
        match output {
            PreparedOutput::InMemory(bytes) => {
                store_resident_image(cache_image, resident_state, ResidentImageStorage::InMemory(bytes));
            }
            #[cfg(target_os = "macos")]
            PreparedOutput::Cloned(_) => {
                store_resident_clone(cache_dir, args, cache_image, resident_state);
            }
        }
    }
    eprintln!(
        "wild: Mach-O stable-layout cache hit: {}",
        args.output().display()
    );
    true
}

fn changed_object_count_is_supported(count: usize) -> bool {
    (1..=MAX_CHANGED_DIRECT_OBJECTS).contains(&count)
}

/// Records the actual changed-object digest only in the service's mutable state. A cache hit
/// already has the bounded changed object mapped for patching, so this avoids a second file read
/// while ensuring the next resident request can distinguish a new object from an equal-content
/// moved direct object. The on-disk state still checkpoints only at the bounded group limit.
fn resident_state_after_hit(state: &ImageState, current_inputs: Vec<InputDigest>) -> ImageState {
    ImageState {
        inputs: current_inputs
            .into_iter()
            .map(|mut input| {
                if let Some(snapshot) = &input.direct_object_bytes {
                    input.digest = *blake3::hash(snapshot.bytes()).as_bytes();
                }
                input.direct_object_bytes = None;
                input
            })
            .collect(),
        ..state.clone()
    }
}

#[cfg(test)]
#[derive(Debug, Eq, PartialEq)]
enum ExistingOutputBaseline {
    Absent,
    Matched(Vec<u8>),
    Mismatch,
}

#[cfg(test)]
fn read_existing_output_baseline(
    path: &Path,
    output_len: u64,
    output_identity: &OutputIdentity,
    signature: &SignatureInfo,
) -> ExistingOutputBaseline {
    let bytes = match fs::read(path) {
        Ok(bytes) => bytes,
        // Cargo can retire the old hash-bearing output before invoking the linker. That is the
        // one absence the owned baseline image is designed to cover; every other I/O error is an
        // unverifiable existing lineage and must fall back to a normal link.
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return ExistingOutputBaseline::Absent;
        }
        Err(_) => return ExistingOutputBaseline::Mismatch,
    };
    if bytes.len() as u64 != output_len {
        return ExistingOutputBaseline::Mismatch;
    }
    output_matches_identity(&bytes, signature, output_identity)
        .then_some(ExistingOutputBaseline::Matched(bytes))
        .unwrap_or(ExistingOutputBaseline::Mismatch)
}

fn discard_cache_sidecars(args: &MachOArgs) {
    let Some(cache_dir) = args.incremental_cache.as_deref() else {
        return;
    };
    for path in [
        cache_path(cache_dir, args),
        cache_image_path(cache_dir, args),
        cache_state_path(cache_dir, args),
        staged_cache_path(cache_dir, args),
        staged_cache_image_path(cache_dir, args),
        staged_cache_state_path(cache_dir, args),
    ] {
        let _ = fs::remove_file(path);
    }
}

/// Persists a new baseline after a normal link. A failure is intentionally invisible to linking:
/// the opt-in cache must never make a successful ordinary link fail.
pub(crate) fn stage_after_link(layout: &Layout<'_, MachO>, output: &[u8]) {
    let args = layout.args();
    let Some(cache_dir) = args.incremental_cache.as_deref() else {
        return;
    };
    if !cache_is_eligible(args) {
        let _ = cache_miss("normal link is not eligible to stage a stable-layout baseline");
        return;
    }
    if !layout.symbol_db.output_kind.is_executable() {
        let _ = cache_miss("normal link did not produce an executable baseline");
        return;
    }

    let Some(inputs) = input_digests(args) else {
        let _ = cache_miss("unable to fingerprint every link-visible input for a baseline");
        return;
    };
    let cache_approved_rustc_temporary_archives =
        cache_approved_rustc_temporary_archives(args, &inputs, output);
    let cache_approved_moved_direct_objects =
        cache_approved_moved_direct_objects(args, &inputs, output);
    let Some(signature) = signature_info(layout, output) else {
        let _ = cache_miss("normal-link code signature is not usable as a cache baseline");
        return;
    };
    let Some(output_identity) = output_identity(output, &signature) else {
        let _ = cache_miss("normal-link output identity is not usable as a cache baseline");
        return;
    };
    let Some(objects) = object_records(layout, &inputs, output) else {
        let _ = cache_miss("unable to construct cache patch records for direct objects");
        return;
    };
    if objects.is_empty() {
        let _ = cache_miss("normal link has no cacheable direct-object patch record");
        return;
    }
    let Some(baseline_output_path) = args.output().to_str().map(str::to_owned) else {
        let _ = cache_miss("normal-link output path is not valid UTF-8 for the cache baseline");
        return;
    };

    let manifest = Manifest {
        arguments_digest: arguments_digest(args),
        baseline_output_path,
        output_identity,
        output_len: output.len() as u64,
        signature,
        inputs,
        cache_approved_rustc_temporary_archives,
        cache_approved_moved_direct_objects,
        objects,
    };
    let manifest_bytes = manifest.encode();
    let manifest_checksum: [u8; HASH_SIZE] = manifest_bytes[manifest_bytes.len() - HASH_SIZE..]
        .try_into()
        .expect("manifest encoding ends with a fixed-width checksum");
    // Stage the image first. `publish_staged` exposes it only after generic linking confirms no
    // input was replaced during layout/writing.
    if write_staged_image_atomic(cache_dir, args, output).is_err() {
        let _ = cache_miss("unable to stage the baseline image or state");
        return;
    }
    let staged_image = staged_cache_image_path(cache_dir, args);
    let cache_image_token = cache_image_token_for_manifest(&manifest);
    if !set_cache_image_token(&staged_image, cache_image_token) {
        let _ = cache_miss("unable to mark the staged baseline image");
        return;
    }
    let state = ImageState {
        arguments_digest: manifest.arguments_digest,
        manifest_checksum,
        cache_image_token,
        uuid_seed: manifest.output_identity.normalized_digest,
        output_len: manifest.output_len,
        inputs: manifest.inputs.clone(),
    };
    if write_staged_image_state_atomic(cache_dir, args, &state).is_err() {
        let _ = cache_miss("unable to stage the baseline image state");
        return;
    }
    if write_staged_manifest_atomic(cache_dir, args, &manifest).is_err() {
        let _ = cache_miss("unable to stage the baseline manifest");
    }
}

/// Publishes a writer-created sidecar only after `Linker::link_for_arch` has completed its normal
/// input-identity verification. If an input changed while a full link was running, the staged
/// snapshot is discarded instead of pairing an old output image with new input digests.
pub(crate) fn publish_staged(args: &MachOArgs) {
    let Some(cache_dir) = args.incremental_cache.as_deref() else {
        return;
    };
    let staged = staged_cache_path(cache_dir, args);
    let staged_image = staged_cache_image_path(cache_dir, args);
    let staged_state = staged_cache_state_path(cache_dir, args);
    let Ok(bytes) = fs::read(&staged) else {
        return;
    };
    let Ok(manifest) = Manifest::decode(&bytes) else {
        let _ = cache_miss("staged baseline manifest is corrupt or incompatible");
        let _ = fs::remove_file(staged);
        let _ = fs::remove_file(staged_image);
        let _ = fs::remove_file(staged_state);
        return;
    };
    let Ok(state_bytes) = fs::read(&staged_state) else {
        let _ = cache_miss("staged baseline image state is absent");
        let _ = fs::remove_file(staged);
        let _ = fs::remove_file(staged_image);
        return;
    };
    let Ok(state) = ImageState::decode(&state_bytes) else {
        let _ = cache_miss("staged baseline image state is corrupt or incompatible");
        let _ = fs::remove_file(staged);
        let _ = fs::remove_file(staged_image);
        let _ = fs::remove_file(staged_state);
        return;
    };
    let manifest_checksum: [u8; HASH_SIZE] = bytes[bytes.len() - HASH_SIZE..]
        .try_into()
        .expect("decoded manifest ends with a fixed-width checksum");
    if manifest.arguments_digest != arguments_digest(args)
        || state.arguments_digest != manifest.arguments_digest
        || state.manifest_checksum != manifest_checksum
        || state.inputs != manifest.inputs
        || state.output_len != manifest.output_len
        || input_digests(args).as_ref() != Some(&manifest.inputs)
    {
        let _ = cache_miss("link-visible inputs changed before baseline publication");
        let _ = fs::remove_file(staged);
        let _ = fs::remove_file(staged_image);
        let _ = fs::remove_file(staged_state);
        return;
    }
    if fs::rename(staged_image, cache_image_path(cache_dir, args)).is_err() {
        let _ = cache_miss("unable to publish the staged baseline image");
        let _ = fs::remove_file(staged);
        let _ = fs::remove_file(staged_state);
        return;
    }
    let image_path = cache_image_path(cache_dir, args);
    if cache_image_token(&image_path) != Some(state.cache_image_token) {
        let _ = cache_miss("published baseline image token differs");
        let _ = fs::remove_file(staged);
        let _ = fs::remove_file(staged_state);
        return;
    }
    if write_image_state_atomic(cache_dir, args, &state).is_err() {
        let _ = cache_miss("unable to publish the staged baseline image state");
        let _ = fs::remove_file(staged);
        return;
    }
    let _ = fs::remove_file(staged_state);
    if fs::rename(staged, cache_path(cache_dir, args)).is_err() {
        let _ = cache_miss("unable to publish the staged baseline manifest");
    }
}

fn cache_is_eligible(args: &MachOArgs) -> bool {
    let common = args.common();
    args.output_kind == crate::args::macho::MachOOutputKind::Executable
        // The export-list pathname is in the semantic argument key, but its contents are read
        // separately from `common.inputs`. Reject it until it has a separately versioned input
        // record; otherwise an edited list could reuse a stale export set and output layout.
        && args.export_list_path.is_none()
        && args.dependency_file().is_none()
        && !args.should_write_trace_file()
        && !common.save_dir.is_enabled()
        // A cache hit deliberately has no `Layout`, so it cannot skip a caller-visible layout
        // dump, validation pass, allocation check, or allocation diagnostic requested by a
        // normal link.
        && !common.write_layout
        && !common.verify_allocation_consistency
        && !common.validate_output
        && common.print_allocations.is_none()
        // The fast path writes an atomic replacement itself, so do not silently substitute it
        // for a caller-selected output writer mode. Debug fuel and symbol-info requests are
        // similarly observable normal-link behaviour rather than layout semantics.
        && common.file_replacement_mode.is_none()
        && common.file_write_mode.is_none()
        && common.debug_fuel.is_none()
        && common.sym_info.is_none()
}

fn cache_path(cache_dir: &Path, args: &MachOArgs) -> PathBuf {
    cache_paths(cache_dir, args).0
}

fn cache_image_path(cache_dir: &Path, args: &MachOArgs) -> PathBuf {
    cache_paths(cache_dir, args).1
}

/// The service-only image is an APFS clone of the last successful output. It lets the next
/// resident request stage a copy-on-write output without depending on Cargo to preserve its
/// public output pathname between compiler processes.
#[cfg(target_os = "macos")]
fn resident_image_path(cache_dir: &Path, args: &MachOArgs) -> PathBuf {
    let image = cache_image_path(cache_dir, args);
    let name = image.file_name().and_then(|name| name.to_str()).unwrap_or("image");
    cache_dir.join(format!(".{name}.resident"))
}

fn cache_state_path(cache_dir: &Path, args: &MachOArgs) -> PathBuf {
    cache_path(cache_dir, args).with_extension("state")
}

fn cache_paths(cache_dir: &Path, args: &MachOArgs) -> (PathBuf, PathBuf) {
    // Rustc changes its final artifact's hash suffix when a source file changes. Preserve the
    // output directory and logical basename to keep independently linked executables separate,
    // but discard only that compiler-generated suffix.
    let mut hasher = blake3::Hasher::new();
    let output = args.output();
    hasher.update(
        output
            .parent()
            .unwrap_or_else(|| Path::new("."))
            .as_os_str()
            .as_encoded_bytes(),
    );
    hasher.update(&[0]);
    hasher.update(stable_output_basename(
        output.file_name().unwrap_or_else(|| std::ffi::OsStr::new("output")).as_encoded_bytes(),
    ));
    hasher.update(&arguments_digest(args));
    let base = format!("macho-arm64-{}", hasher.finalize().to_hex());
    (cache_dir.join(format!("{base}.bin")), cache_dir.join(format!("{base}.image")))
}

fn staged_cache_path(cache_dir: &Path, args: &MachOArgs) -> PathBuf {
    let final_path = cache_path(cache_dir, args);
    cache_dir.join(format!(
        ".{}.{}.pending",
        final_path
            .file_name()
            .and_then(|name| name.to_str())
            .unwrap_or("macho-arm64"),
        std::process::id()
    ))
}

fn staged_cache_image_path(cache_dir: &Path, args: &MachOArgs) -> PathBuf {
    let final_path = cache_image_path(cache_dir, args);
    cache_dir.join(format!(
        ".{}.{}.pending",
        final_path
            .file_name()
            .and_then(|name| name.to_str())
            .unwrap_or("macho-arm64.image"),
        std::process::id()
    ))
}

fn staged_cache_state_path(cache_dir: &Path, args: &MachOArgs) -> PathBuf {
    let final_path = cache_state_path(cache_dir, args);
    cache_dir.join(format!(
        ".{}.{}.pending",
        final_path
            .file_name()
            .and_then(|name| name.to_str())
            .unwrap_or("macho-arm64.state"),
        std::process::id()
    ))
}

fn arguments_digest(args: &MachOArgs) -> [u8; HASH_SIZE] {
    // Keep this fingerprint to arguments which can affect bytes or layout in the produced Mach-O.
    // In particular, do not fingerprint the parser's runtime state: a Cargo-launched link has a
    // jobserver and a different available-thread count from the benchmark's bare direct replay.
    // Those states control scheduling, diagnostics, saving, timing, and process management, not
    // the linked image. The cache's separate eligibility checks retain output-side-effect
    // contracts that its fast writer cannot reproduce.
    let common = args.common();
    let mut semantic_arguments = format!(
        "MachOStableLayoutArguments {{ version: {:?}, relocation_model: {:?}, numeric_experiments: \
         {:?}, inputs: {:?}, \
         platform_version: {:?}, sysroot: {:?}, lib_search_path: {:?}, framework_search_path: \
         {:?}, dead_strip_dylibs: {:?}, gc_sections: {:?}, const_selrefs: {:?}, output_kind: \
         {:?}, strip: {:?}, install_name: {:?}, export_list_path: {:?}, rpaths: {:?}, entry: \
         {:?} }}",
        common.version,
        common.relocation_model,
        common.numeric_experiments,
        common.inputs,
        args.platform_version,
        args.sysroot,
        args.lib_search_path,
        args.framework_search_path,
        args.dead_strip_dylibs,
        args.gc_sections,
        args.const_selrefs,
        args.output_kind,
        args.strip,
        args.install_name,
        args.export_list_path,
        args.rpaths,
        args.entry,
    );
    for (index, input) in args.common().inputs.iter().enumerate() {
        let InputSpec::File(path) = &input.spec else {
            continue;
        };
        if path.extension().is_some_and(|extension| extension == "o") {
            semantic_arguments = semantic_arguments.replace(
                path.to_string_lossy().as_ref(),
                &format!("<direct-mach-object-{index}>"),
            );
        } else if is_rustc_temporary_archive_path(path) {
            // Rustc reconstructs rlibs in a fresh `rustcXXXXXX` directory for each final link.
            // Retain the archive basename in the semantic key; the cache accepts the changed
            // directory only when its immutable baseline image proves the original path is not
            // emitted, then verifies the complete replacement bytes below.
            semantic_arguments = semantic_arguments.replace(
                path.to_string_lossy().as_ref(),
                &format!(
                    "<rustc-temporary-archive-{index}:{}>",
                    path.file_name().unwrap().to_string_lossy()
                ),
            );
        }
    }
    semantic_arguments = semantic_arguments.replace(args.output().to_string_lossy().as_ref(), "<output>");
    *blake3::hash(semantic_arguments.as_bytes()).as_bytes()
}

fn is_mach_object_path(path: &str) -> bool {
    Path::new(path)
        .extension()
        .is_some_and(|extension| extension == "o")
}

fn stable_output_basename(name: &[u8]) -> &[u8] {
    let Some(separator) = name.iter().rposition(|byte| *byte == b'-') else {
        return name;
    };
    let suffix = &name[separator + 1..];
    // Rustc's artifact disambiguator is a hexadecimal digest. Keep user-provided hyphens and
    // ordinary output names intact, so only this compiler-generated suffix is normalized.
    if suffix.len() >= 8 && suffix.iter().all(u8::is_ascii_hexdigit) {
        &name[..separator]
    } else {
        name
    }
}

fn input_digests(args: &MachOArgs) -> Option<Vec<InputDigest>> {
    args.common()
        .inputs
        .iter()
        .map(|input| {
            let path = canonical_input_path(args, input)?;
            read_hashed_input(path)
        })
        .collect()
}

/// Fingerprints only potentially changed direct objects. Every path-identical input with
/// unchanged stored metadata reuses its baseline BLAKE3 digest. A baseline image can additionally
/// approve equal-content Rust temporary archives and moved direct objects only after it proves
/// their old path is not link-visible; those exceptional inputs are fully hashed before
/// acceptance. All other non-direct changes remain normal-link fallbacks.
fn input_digests_for_cache_hit(
    args: &MachOArgs,
    cached_inputs: &[InputDigest],
    cache_approved_rustc_temporary_archives: &[u32],
    cache_approved_moved_direct_objects: &[u32],
) -> Option<Vec<InputDigest>> {
    (args.common().inputs.len() == cached_inputs.len()).then_some(())?;
    let input_digests = args
        .common()
        .inputs
        .par_iter()
        .zip(cached_inputs.par_iter())
        .enumerate()
        .map(|(index, (input, cached))| {
            let path = cache_hit_input_path(args, input, cached)?;
            let metadata = input_file_metadata(&path)?;
            if path == cached.path && metadata == cached.metadata {
                return Some(InputDigest {
                    path,
                    digest: cached.digest,
                    direct_object_bytes: None,
                    metadata,
                });
            }
            if is_mach_object_path(&path) && is_mach_object_path(&cached.path) {
                let cache_approved = u32::try_from(index).is_ok_and(|input_index| {
                    cache_approved_moved_direct_objects
                        .binary_search(&input_index)
                        .is_ok()
                });
                if cache_approved {
                    let current = read_hashed_input(path.clone())?;
                    if current.digest == cached.digest {
                        return Some(current);
                    }
                }
                return read_changed_direct_object(path, cached);
            }
            let cache_approved = u32::try_from(index).is_ok_and(|input_index| {
                cache_approved_rustc_temporary_archives
                    .binary_search(&input_index)
                    .is_ok()
            });
            if reusable_rustc_temporary_archive(&path, &cached.path, cache_approved) {
                let current = read_hashed_input(path)?;
                return (current.digest == cached.digest).then_some(current);
            }
            None
        })
        .collect::<Vec<_>>();
    input_digests.into_iter().collect()
}

/// Finds precisely the Rustc-owned archive paths whose temporary-directory spelling is not
/// link-visible. An absent path is always safe. A present path is safe only when every occurrence
/// is the archive portion of a checked `N_OSO` debug-map entry, which a cache hit rewrites before
/// re-signing. This is stronger than Cargo's `strip=symbols`: that profile flag does not
/// necessarily request Mach-O debug stripping.
fn cache_approved_rustc_temporary_archives(
    args: &MachOArgs,
    inputs: &[InputDigest],
    output: &[u8],
) -> Vec<u32> {
    args.common()
        .inputs
        .iter()
        .zip(inputs)
        .enumerate()
        .filter_map(|(index, (argument, input))| {
            let InputSpec::File(argument_path) = &argument.spec else {
                return None;
            };
            // The emitted `N_OSO` spelling comes from the link argument rather than its resolved
            // filesystem identity. Do not treat a symlink's canonical target as proof about that
            // distinct path string.
            (argument_path.to_str().is_some_and(|path| path == input.path)
                && is_rustc_temporary_archive_path(Path::new(&input.path))
                && n_oso_archive_path_patches(output, &input.path, &input.path).is_some())
            .then(|| u32::try_from(index).ok())
            .flatten()
        })
        .collect()
}

/// Direct Cargo/rustc objects can have a fresh hash-bearing path on a rebuild even if their bytes
/// are identical. Permit that movement only when the original link argument was already the
/// canonical file identity and no occurrence of it is present in the output image. This proves
/// that changing the spelling cannot leave an old debug-map or other pathname observable.
fn cache_approved_moved_direct_objects(
    args: &MachOArgs,
    inputs: &[InputDigest],
    output: &[u8],
) -> Vec<u32> {
    args.common()
        .inputs
        .iter()
        .zip(inputs)
        .enumerate()
        .filter_map(|(index, (argument, input))| {
            let InputSpec::File(argument_path) = &argument.spec else {
                return None;
            };
            (is_mach_object_path(&input.path)
                && argument_path.to_str().is_some_and(|path| path == input.path)
                && memchr::memmem::find(output, input.path.as_bytes()).is_none())
            .then(|| u32::try_from(index).ok())
            .flatten()
        })
        .collect()
}

/// The stable-layout cache needs only the fixed-width 64-bit nlist records. This deliberately
/// rejects malformed or duplicate `LC_SYMTAB` commands rather than relying on a permissive
/// object parser while patching a cache-owned executable.
#[derive(Clone, Copy)]
struct MachOSymtab {
    command_offset: usize,
    symbol_offset: usize,
    symbol_count: usize,
    string_offset: usize,
    string_size: usize,
}

impl MachOSymtab {
    fn input_symbols(self, bytes: &[u8]) -> Option<Vec<InputSymbol>> {
        let string_end = self.string_offset.checked_add(self.string_size)?;
        let mut symbols = Vec::with_capacity(self.symbol_count);
        for index in 0..self.symbol_count {
            let entry_offset = self.entry_offset(index)?;
            let string_index = usize::try_from(read_u32(bytes, entry_offset)?).ok()?;
            if string_index >= self.string_size {
                return None;
            }
            let name_offset = self.string_offset.checked_add(string_index)?;
            let name = bytes.get(name_offset..string_end)?;
            let name_end = name.iter().position(|byte| *byte == 0)?;
            symbols.push(InputSymbol {
                index,
                name: name[..name_end].to_vec(),
                n_type: *bytes.get(entry_offset.checked_add(4)?)?,
                n_sect: *bytes.get(entry_offset.checked_add(5)?)?,
                n_desc: read_u16(bytes, entry_offset.checked_add(6)?)?,
                n_value: read_u64(bytes, entry_offset.checked_add(8)?)?,
            });
        }
        Some(symbols)
    }

    fn has_stabs(self, bytes: &[u8]) -> bool {
        (0..self.symbol_count).any(|index| {
            self.entry_offset(index)
                .and_then(|offset| bytes.get(offset.checked_add(4)?))
                .is_some_and(|n_type| *n_type & object::macho::N_STAB != 0)
        })
    }

    fn value_offset_for_symbol(self, index: usize) -> Option<usize> {
        self.entry_offset(index)?.checked_add(8)
    }

    fn unique_symbol_value_offset(
        self,
        bytes: &[u8],
        expected_name: &[u8],
        expected_type: u8,
        expected_desc: u16,
        expected_value: u64,
    ) -> Option<usize> {
        let mut matched = None;
        for index in 0..self.symbol_count {
            let entry_offset = self.entry_offset(index)?;
            if bytes.get(entry_offset.checked_add(4)?) != Some(&expected_type)
                || bytes.get(entry_offset.checked_add(5)?) == Some(&0)
                || read_u16(bytes, entry_offset.checked_add(6)?)? != expected_desc
                || read_u64(bytes, entry_offset.checked_add(8)?)? != expected_value
            {
                continue;
            }
            let string_index = usize::try_from(read_u32(bytes, entry_offset)?).ok()?;
            if string_index >= self.string_size {
                return None;
            }
            let name_offset = self.string_offset.checked_add(string_index)?;
            let string_end = self.string_offset.checked_add(self.string_size)?;
            let name = bytes.get(name_offset..string_end)?;
            let name_end = name.iter().position(|byte| *byte == 0)?;
            if &name[..name_end] != expected_name {
                continue;
            }
            if matched.replace(entry_offset.checked_add(8)?).is_some() {
                return None;
            }
        }
        matched
    }

    fn unique_symbol_string_offset(
        self,
        bytes: &[u8],
        expected_name: &[u8],
        expected_type: u8,
        expected_desc: u16,
    ) -> Option<usize> {
        let mut matched = None;
        for index in 0..self.symbol_count {
            let entry_offset = self.entry_offset(index)?;
            if bytes.get(entry_offset.checked_add(4)?) != Some(&expected_type)
                || bytes.get(entry_offset.checked_add(5)?) == Some(&0)
                || read_u16(bytes, entry_offset.checked_add(6)?)? != expected_desc
            {
                continue;
            }
            let string_index = usize::try_from(read_u32(bytes, entry_offset)?).ok()?;
            if string_index >= self.string_size {
                return None;
            }
            let name_offset = self.string_offset.checked_add(string_index)?;
            let string_end = self.string_offset.checked_add(self.string_size)?;
            let name = bytes.get(name_offset..string_end)?;
            let name_end = name.iter().position(|byte| *byte == 0)?;
            if &name[..name_end] != expected_name {
                continue;
            }
            if matched.replace(name_offset).is_some() {
                return None;
            }
        }
        matched
    }

    fn entry_offset(self, index: usize) -> Option<usize> {
        (index < self.symbol_count)
            .then(|| index.checked_mul(16))
            .flatten()
            .and_then(|offset| self.symbol_offset.checked_add(offset))
    }
}

fn macho_symtab(bytes: &[u8]) -> Option<MachOSymtab> {
    if read_u32(bytes, 0)? != object::macho::MH_MAGIC_64 {
        return None;
    }
    let ncmds = usize::try_from(read_u32(bytes, 16)?).ok()?;
    let mut command_offset = 32usize;
    let mut symtab = None;
    for _ in 0..ncmds {
        let command = read_u32(bytes, command_offset)?;
        let command_size = usize::try_from(read_u32(bytes, command_offset.checked_add(4)?)?).ok()?;
        let command_end = command_offset.checked_add(command_size)?;
        if command_size < 8 || command_end > bytes.len() {
            return None;
        }
        if command == object::macho::LC_SYMTAB.0 {
            if command_size < 24 || symtab.is_some() {
                return None;
            }
            symtab = Some(MachOSymtab {
                command_offset,
                symbol_offset: usize::try_from(read_u32(bytes, command_offset.checked_add(8)?)?).ok()?,
                symbol_count: usize::try_from(read_u32(bytes, command_offset.checked_add(12)?)?).ok()?,
                string_offset: usize::try_from(read_u32(bytes, command_offset.checked_add(16)?)?).ok()?,
                string_size: usize::try_from(read_u32(bytes, command_offset.checked_add(20)?)?).ok()?,
            });
        }
        command_offset = command_end;
    }
    let symtab = symtab?;
    let symbol_table_end = symtab
        .symbol_offset
        .checked_add(symtab.symbol_count.checked_mul(16)?)?;
    let string_end = symtab.string_offset.checked_add(symtab.string_size)?;
    (symbol_table_end <= bytes.len() && string_end <= bytes.len()).then_some(symtab)
}

/// Produces equal-width output patches for Rustc archive paths that moved between compiler-owned
/// temporary directories. The parser is deliberately small and fail-closed: it accepts exactly
/// one 64-bit Mach-O symbol table, matches only `N_OSO` strings of the form
/// `archive.rlib(member.o)`, and proves that the old path occurs nowhere else in the image.
///
/// A path can appear once per selected archive member. Rewriting every such symbol string keeps
/// `dsymutil` pointed at the current archive without claiming that an arbitrary output string is
/// non-semantic.
fn n_oso_archive_path_patches(
    output: &[u8],
    expected_path: &str,
    replacement_path: &str,
) -> Option<Vec<OutputPathPatch>> {
    let expected = expected_path.as_bytes();
    let replacement = replacement_path.as_bytes();
    if expected.is_empty() || expected.len() != replacement.len() {
        return None;
    }
    if memchr::memmem::find(output, expected).is_none() {
        return Some(Vec::new());
    }

    let ncmds = usize::try_from(read_u32(output, 16)?).ok()?;
    let mut command_offset = 32usize;
    let mut symtab = None;
    for _ in 0..ncmds {
        let command = read_u32(output, command_offset)?;
        let command_size = usize::try_from(read_u32(output, command_offset.checked_add(4)?)?).ok()?;
        let command_end = command_offset.checked_add(command_size)?;
        if command_size < 8 || command_end > output.len() {
            return None;
        }
        if command == object::macho::LC_SYMTAB.0 {
            if command_size < 24 || symtab.is_some() {
                return None;
            }
            symtab = Some((
                usize::try_from(read_u32(output, command_offset.checked_add(8)?)?).ok()?,
                usize::try_from(read_u32(output, command_offset.checked_add(12)?)?).ok()?,
                usize::try_from(read_u32(output, command_offset.checked_add(16)?)?).ok()?,
                usize::try_from(read_u32(output, command_offset.checked_add(20)?)?).ok()?,
            ));
        }
        command_offset = command_end;
    }
    let (symbol_offset, symbol_count, string_offset, string_size) = symtab?;
    let symbol_table_size = symbol_count.checked_mul(16)?;
    let symbol_table_end = symbol_offset.checked_add(symbol_table_size)?;
    let string_end = string_offset.checked_add(string_size)?;
    if symbol_table_end > output.len() || string_end > output.len() {
        return None;
    }

    let mut n_oso_offsets = Vec::new();
    for index in 0..symbol_count {
        let entry_offset = symbol_offset.checked_add(index.checked_mul(16)?)?;
        if output.get(entry_offset.checked_add(4)?) != Some(&object::macho::N_OSO.0) {
            continue;
        }
        let string_index = usize::try_from(read_u32(output, entry_offset)?).ok()?;
        if string_index >= string_size {
            return None;
        }
        let name_offset = string_offset.checked_add(string_index)?;
        let name = output.get(name_offset..string_end)?;
        let name_end = name.iter().position(|byte| *byte == 0)?;
        let name = &name[..name_end];
        if name
            .strip_prefix(expected)
            .is_some_and(|suffix| suffix.starts_with(b"("))
        {
            n_oso_offsets.push(name_offset);
        }
    }
    n_oso_offsets.sort_unstable();
    n_oso_offsets.dedup();

    let mut raw_offsets = Vec::new();
    let mut search_start = 0usize;
    while let Some(found) = memchr::memmem::find(&output[search_start..], expected) {
        let offset = search_start.checked_add(found)?;
        raw_offsets.push(offset);
        search_start = offset.checked_add(1)?;
    }
    (raw_offsets == n_oso_offsets).then(|| {
        n_oso_offsets
            .into_iter()
            .map(|output_offset| OutputPathPatch {
                output_offset: output_offset as u64,
                expected: expected.to_vec(),
                replacement: replacement.to_vec(),
            })
            .collect()
    })
}

/// Rewrites a moved compiler temporary archive only when its current command-line spelling is
/// the same resolved path used for the cache input identity. That matches the `N_OSO` producer:
/// it records the link argument's spelling rather than a filesystem canonicalisation.
fn rustc_temporary_archive_path_patches(
    output: &[u8],
    args: &MachOArgs,
    current_inputs: &[InputDigest],
    cached_inputs: &[InputDigest],
    cache_approved_rustc_temporary_archives: &[u32],
) -> Option<Vec<OutputPathPatch>> {
    let mut patches = Vec::new();
    for input_index in cache_approved_rustc_temporary_archives {
        let index = usize::try_from(*input_index).ok()?;
        let current = current_inputs.get(index)?;
        let cached = cached_inputs.get(index)?;
        if current.path == cached.path {
            continue;
        }
        if !reusable_rustc_temporary_archive(&current.path, &cached.path, true) {
            return None;
        }
        let InputSpec::File(argument_path) = &args.common().inputs.get(index)?.spec else {
            return None;
        };
        if argument_path.to_str()? != current.path {
            return None;
        }
        patches.extend(n_oso_archive_path_patches(
            output,
            &cached.path,
            &current.path,
        )?);
    }
    patches.sort_unstable_by_key(|patch| patch.output_offset);
    patches
        .windows(2)
        .all(|pair| {
            let Some(end) = usize::try_from(pair[0].output_offset)
                .ok()
                .and_then(|start| start.checked_add(pair[0].replacement.len()))
            else {
                return false;
            };
            usize::try_from(pair[1].output_offset).is_ok_and(|next| end <= next)
        })
        .then_some(patches)
}

/// Rustc writes final-link archive copies under `rustc` plus six random alphanumeric bytes. The
/// directory changes on every link, while the archive's basename remains a real semantic input.
/// Only accept that one compiler-owned spelling; arbitrary temporary directories must preserve
/// the ordinary linker's pathname-sensitive behavior.
fn is_rustc_temporary_archive_path(path: &Path) -> bool {
    path.extension().is_some_and(|extension| extension == "rlib")
        && path.parent().and_then(Path::file_name).and_then(std::ffi::OsStr::to_str).is_some_and(
            |directory| {
                directory.len() == "rustc".len() + 6
                    && directory.starts_with("rustc")
                    && directory["rustc".len()..].bytes().all(|byte| byte.is_ascii_alphanumeric())
            },
        )
}

fn reusable_rustc_temporary_archive(current: &str, cached: &str, cache_approved: bool) -> bool {
    cache_approved
        && is_rustc_temporary_archive_path(Path::new(current))
        && is_rustc_temporary_archive_path(Path::new(cached))
        && Path::new(current).file_name() == Path::new(cached).file_name()
}

fn reusable_moved_direct_object(
    current: &InputDigest,
    cached: &InputDigest,
    cache_approved: bool,
) -> bool {
    cache_approved
        && current.digest == cached.digest
        && current.direct_object_bytes.is_none()
        && is_mach_object_path(&current.path)
        && is_mach_object_path(&cached.path)
}

fn input_identity_changed(
    current: &InputDigest,
    cached: &InputDigest,
    cache_approved_rustc_temporary_archive: bool,
    cache_approved_moved_direct_object: bool,
) -> bool {
    current.digest != cached.digest
        || (current.path != cached.path || current.metadata != cached.metadata)
            && !reusable_rustc_temporary_archive(
                &current.path,
                &cached.path,
                cache_approved_rustc_temporary_archive,
            )
            && !reusable_moved_direct_object(
                current,
                cached,
                cache_approved_moved_direct_object,
            )
}

/// Before a cache hit accepts a new direct-object pathname, reapply the baseline proof retained
/// in the manifest. The old spelling must remain absent from the image and the current command
/// must spell its canonical path exactly; otherwise an N_OSO/debug or caller-visible pathname may
/// need a normal relink rather than a byte patch.
fn moved_direct_object_paths_are_unobservable(
    output: &[u8],
    args: &MachOArgs,
    current_inputs: &[InputDigest],
    cached_inputs: &[InputDigest],
    cache_approved_moved_direct_objects: &[u32],
) -> bool {
    cache_approved_moved_direct_objects.iter().all(|input_index| {
        let Ok(index) = usize::try_from(*input_index) else {
            return false;
        };
        let (Some(current), Some(cached), Some(input)) = (
            current_inputs.get(index),
            cached_inputs.get(index),
            args.common().inputs.get(index),
        ) else {
            return false;
        };
        if current.path == cached.path {
            return true;
        }
        let InputSpec::File(argument_path) = &input.spec else {
            return false;
        };
        is_mach_object_path(&current.path)
            && is_mach_object_path(&cached.path)
            && argument_path.to_str().is_some_and(|path| path == current.path)
            && memchr::memmem::find(output, cached.path.as_bytes()).is_none()
    })
}

/// Return a canonical path only when the command's spelling cannot already identify the cached
/// file. Cargo supplies absolute direct file paths, so the common case can stat the exact
/// persisted pathname rather than resolving and canonicalising every rlib on every hit. A
/// relative path, symlink spelling, `-l`, or framework input still takes full resolution; that
/// preserves the ordinary linker's search and symlink semantics before a digest is reused.
fn cache_hit_input_path(
    args: &MachOArgs,
    input: &crate::args::Input,
    cached: &InputDigest,
) -> Option<String> {
    if let InputSpec::File(path) = &input.spec {
        if path.to_str().is_some_and(|path| path == cached.path) {
            return Some(cached.path.clone());
        }
    }
    canonical_input_path(args, input)
}

fn canonical_input_path(args: &MachOArgs, input: &crate::args::Input) -> Option<String> {
    let path = resolve_input_path(args, input.search_first.as_deref(), &input.spec)?;
    fs::canonicalize(path).ok()?.to_str().map(str::to_owned)
}

/// Hashes an input only after its filesystem identity is stable across the read. This baseline
/// snapshot is what later lets an incremental hit stat unchanged inputs instead of hashing them.
fn read_hashed_input(path: String) -> Option<InputDigest> {
    let metadata_before = input_file_metadata(&path)?;
    // Rustc's transient rlibs are rehashed on every hit before their moved path can be reused.
    // Avoid copying those multi-megabyte archives into a short-lived allocation: BLAKE3 can read
    // the same immutable file mapping directly, and the metadata check below still rejects a
    // concurrent replacement. An empty or otherwise unmappable input retains the ordinary read
    // fallback so cache eligibility never depends on mmap support.
    #[cfg(target_os = "macos")]
    let digest = fs::File::open(&path)
        .ok()
        .and_then(|file| unsafe { memmap2::MmapOptions::new().map(&file) }.ok())
        .map(|bytes| *blake3::hash(&bytes).as_bytes())
        .or_else(|| fs::read(&path).ok().map(|bytes| *blake3::hash(&bytes).as_bytes()))?;
    #[cfg(not(target_os = "macos"))]
    let digest = *blake3::hash(&fs::read(&path).ok()?).as_bytes();
    let metadata = input_file_metadata(&path)?;
    (metadata_before == metadata).then_some(())?;
    Some(InputDigest {
        path,
        digest,
        direct_object_bytes: None,
        metadata,
    })
}

/// Capture a direct object selected by path/metadata change without a redundant raw object digest.
/// Normal-link staging still hashes every input. On a hit, each changed object's complete mapped
/// bytes are validated against the persisted structural and relocation contracts, then their
/// metadata is checked again before publication. This is the same filesystem-change boundary the
/// normal linker uses, strengthened by the persisted device/inode/ctime snapshot.
fn read_changed_direct_object(path: String, cached: &InputDigest) -> Option<InputDigest> {
    let metadata_before = input_file_metadata(&path)?;
    #[cfg(target_os = "macos")]
    let mapping = fs::File::open(&path)
        .ok()
        .and_then(|file| unsafe { memmap2::MmapOptions::new().map(&file) }.ok())
        .map(|mapping| DirectObjectSnapshot::Mapped(Arc::new(mapping)));
    #[cfg(target_os = "macos")]
    let snapshot = match mapping {
        Some(snapshot) => snapshot,
        None => DirectObjectSnapshot::InMemory(Arc::from(fs::read(&path).ok()?)),
    };
    #[cfg(not(target_os = "macos"))]
    let snapshot = DirectObjectSnapshot::InMemory(Arc::from(fs::read(&path).ok()?));
    let metadata = input_file_metadata(&path)?;
    (metadata_before == metadata).then_some(())?;
    Some(InputDigest {
        path,
        // A changed object is selected by its path or metadata, not a new full digest. Retaining
        // the baseline digest avoids another 4MiB BLAKE3 pass and is safe because an unchanged
        // path-identical input is deliberately not an output-reuse cache hit.
        digest: cached.digest,
        direct_object_bytes: Some(snapshot),
        metadata,
    })
}

fn input_file_metadata(path: &str) -> Option<InputFileMetadata> {
    let metadata = fs::metadata(path).ok()?;
    let modified = metadata
        .modified()
        .ok()?
        .duration_since(SystemTime::UNIX_EPOCH)
        .ok()?;
    Some(InputFileMetadata {
        len: metadata.len(),
        modified_seconds: modified.as_secs(),
        modified_nanoseconds: modified.subsec_nanos(),
        #[cfg(unix)]
        device: metadata.dev(),
        #[cfg(not(unix))]
        device: 0,
        #[cfg(unix)]
        inode: metadata.ino(),
        #[cfg(not(unix))]
        inode: 0,
        #[cfg(unix)]
        changed_seconds: metadata.ctime(),
        #[cfg(not(unix))]
        changed_seconds: 0,
        #[cfg(unix)]
        changed_nanoseconds: metadata.ctime_nsec(),
        #[cfg(not(unix))]
        changed_nanoseconds: 0,
    })
}

fn input_metadata_snapshots_match(args: &MachOArgs, inputs: &[InputDigest]) -> bool {
    args.common().inputs.len() == inputs.len()
        && args
            .common()
            .inputs
            .par_iter()
            .zip(inputs.par_iter())
            .all(|(input, snapshot)| {
                let Some(path) = cache_hit_input_path(args, input, snapshot) else {
                    return false;
                };
                path == snapshot.path && input_file_metadata(&path).as_ref() == Some(&snapshot.metadata)
            })
}

fn resolve_input_path(
    args: &MachOArgs,
    search_first: Option<&Path>,
    spec: &InputSpec,
) -> Option<PathBuf> {
    let mut search_paths = Vec::new();
    if let Some(path) = search_first {
        search_paths.push(path.to_path_buf());
    }
    search_paths.extend(args.lib_search_path.iter().map(|path| path.to_path_buf()));

    match spec {
        InputSpec::File(path) => path.exists().then(|| path.to_path_buf()),
        InputSpec::Lib(name) => search_paths.iter().find_map(|directory| {
            [
                format!("lib{name}.dylib"),
                format!("lib{name}.tbd"),
                format!("lib{name}.a"),
            ]
                .into_iter()
                .map(|filename| directory.join(filename))
                .find(|path| path.exists())
        }),
        InputSpec::Search(name) => {
            let path = Path::new(name.as_ref());
            path.exists()
                .then(|| path.to_path_buf())
                .or_else(|| {
                    search_paths
                        .iter()
                        .map(|directory| directory.join(name.as_ref()))
                        .find(|path| path.exists())
                })
        }
        InputSpec::Framework(name) => args.framework_search_path.iter().find_map(|directory| {
            let framework = directory.join(format!("{name}.framework"));
            [framework.join(name.as_ref()), framework.join(format!("{name}.tbd"))]
                .into_iter()
                .find(|path| path.exists())
        }),
    }
}

fn object_records(
    layout: &Layout<'_, MachO>,
    inputs: &[InputDigest],
    output: &[u8],
) -> Option<Vec<ObjectRecord>> {
    let mut direct_object_indices = BTreeMap::new();
    let mut repeated_direct_object_paths = BTreeSet::new();
    for (index, input) in inputs
        .iter()
        .enumerate()
        .filter(|(_, input)| is_mach_object_path(&input.path))
    {
        // A repeated direct object has no unambiguous incremental-cache role.
        if direct_object_indices.contains_key(input.path.as_str()) {
            direct_object_indices.remove(input.path.as_str());
            repeated_direct_object_paths.insert(input.path.as_str());
        } else if !repeated_direct_object_paths.contains(input.path.as_str()) {
            direct_object_indices.insert(input.path.as_str(), index);
        }
    }

    let mut candidates = BTreeMap::new();
    let mut ambiguous_input_indices = BTreeSet::new();
    for group in &layout.group_layouts {
        for file in &group.files {
            let FileLayout::Object(object) = file else {
                continue;
            };
            let path = fs::canonicalize(object.input.file.filename).ok()?;
            let path = path.to_str()?.to_owned();
            let Some(&input_index) = direct_object_indices.get(path.as_str()) else {
                continue;
            };
            if ambiguous_input_indices.contains(&input_index) {
                continue;
            }
            // Every direct input is still fingerprinted in `ImageState`. An object that cannot
            // supply a proven patch mapping is therefore safe to leave unrecorded: changing it
            // has no `ObjectRecord` and must take the normal-link fallback, while another direct
            // object with a verified mapping can still use a cache baseline.
            let Some(candidate) = object_candidate(layout, object, output) else {
                continue;
            };
            if candidates.insert(input_index, candidate).is_some() {
                candidates.remove(&input_index);
                ambiguous_input_indices.insert(input_index);
            }
        }
    }

    Some(cacheable_records_from_candidates(
        candidates
            .into_iter()
            .map(|(input_index, candidate)| (input_index, Some(candidate))),
    ))
}

/// Converts only individually proven direct-object mappings into manifest records. Inputs without
/// a record remain part of the baseline fingerprint, so a later change to one cannot become a
/// cache hit. Keeping that per-input fallback lets an unsupported Rust codegen object coexist with
/// a separately safe changed object instead of suppressing the whole baseline.
fn cacheable_records_from_candidates(
    candidates: impl IntoIterator<Item = (usize, Option<Candidate>)>,
) -> Vec<ObjectRecord> {
    candidates
        .into_iter()
        .filter_map(|(input_index, candidate)| {
            let mut candidate = candidate?;
            if candidate.patches.is_empty() {
                return None;
            }
            normalise_ranges(&mut candidate.patches)?;
            candidate.structure_masks = candidate
                .patches
                .iter()
                .map(|patch| InputRange {
                    input_offset: patch.input_offset,
                    len: patch.len,
                })
                .collect();
            candidate
                .structure_masks
                .extend(candidate.symbol_values.iter().map(|symbol| InputRange {
                    input_offset: symbol.input_value_offset,
                    len: size_of::<u64>() as u64,
                }));
            normalise_input_ranges(&mut candidate.structure_masks)?;
            normalise_symbol_value_patches(&mut candidate.symbol_values)?;
            normalise_protected_ranges(&mut candidate.protected)?;
            let rustc_private = candidate.rustc_private_symbols.and_then(|symbols| {
                rustc_private_metadata(&candidate.bytes, &candidate.patches).map(|metadata| {
                    RustcPrivateObject {
                        metadata_digest: metadata.digest,
                        symbols,
                    }
                })
            });
            Some(ObjectRecord {
                input_index: u32::try_from(input_index).ok()?,
                structure_digest: masked_digest_for_input_ranges(
                    &candidate.bytes,
                    &candidate.structure_masks,
                ),
                patches: candidate.patches,
                structure_masks: candidate.structure_masks,
                symbol_values: candidate.symbol_values,
                protected: candidate.protected,
                rustc_private,
            })
        })
        .collect()
}

fn object_candidate(
    layout: &Layout<'_, MachO>,
    object: &ObjectLayout<'_, MachO>,
    output: &[u8],
) -> Option<Candidate> {
    let mut patches = Vec::new();
    let mut protected = Vec::new();
    let data = object.object.data;

    for (index, slot) in object.sections.iter().enumerate() {
        let section_index = object::SectionIndex(index);
        match slot {
            SectionSlot::Loaded(section) => {
                let header = object.object.section(section_index).ok()?;
                let raw = object.object.raw_section_data(header).ok()?;
                if raw.is_empty() {
                    continue;
                }
                let input_offset = slice_offset(data, raw)?;
                let part_id = object.section_part_id(section_index, &layout.symbol_db.section_part_ids);
                if !layout
                    .output_sections
                    .has_data_in_file(part_id.output_section_id::<MachO>())
                {
                    continue;
                }
                let section_address = object.section_resolutions.get(index)?.address()?;
                let part = layout.section_part_layouts.get(part_id);
                let section_protected = collect_protected_relocation_ranges(
                    object,
                    section_index,
                    input_offset,
                    raw.len(),
                    data,
                )?;
                if let Some(subsections) = object.live_input_ranges(section_index) {
                    // Atom-level dead stripping compacts each surviving input atom. Persist one
                    // patch per live atom; `output_offset_for_input` is the same authoritative
                    // mapping used by relocation and symbol writers.
                    for subsection in subsections {
                        let input_start = usize::try_from(subsection.range.start).ok()?;
                        let input_end = usize::try_from(subsection.range.end).ok()?.min(raw.len());
                        if input_start >= input_end {
                            continue;
                        }
                        let compacted = object.output_offset_for_input(section_index, subsection.range.start)?;
                        let output_offset = part.file_offset.checked_add(
                            usize::try_from(
                                section_address
                                    .checked_add(compacted)?
                                    .checked_sub(part.mem_offset)?,
                            )
                            .ok()?,
                        )?;
                        add_patch_ranges_excluding_protected(
                            &mut patches,
                            input_offset.checked_add(input_start)?,
                            output_offset,
                            input_end - input_start,
                            &section_protected,
                        )?;
                    }
                } else {
                    let output_offset = part.file_offset.checked_add(
                        usize::try_from(section_address.checked_sub(part.mem_offset)?).ok()?,
                    )?;
                    let len = usize::try_from(section.size).ok()?.min(raw.len());
                    add_patch_ranges_excluding_protected(
                        &mut patches,
                        input_offset,
                        output_offset,
                        len,
                        &section_protected,
                    )?;
                }
                protected.extend(section_protected);
            }
            // A merged string can be shared, or can change the merger's bucket and string
            // topology without changing its source section size. Leaving it outside `patches`
            // keeps it in the structural digest and turns all such edits into normal links.
            SectionSlot::MergeStrings(_) => {}
            _ => {}
        }
    }

    let symbol_values = linker_private_symbol_value_patches(layout, object, output);
    let rustc_private_symbols = rustc_private_symbol_patches(object, output);
    Some(Candidate {
        bytes: data.to_vec(),
        patches,
        structure_masks: Vec::new(),
        symbol_values,
        protected,
        rustc_private_symbols,
    })
}

/// Finds the linker-private-symbol updates for the one cache shape whose address calculation
/// remains entirely section-relative. Requiring no relocations, no STABS, no subsection
/// compaction, and a private-external symbol intentionally leaves exports, unwind metadata,
/// chained fixups, and debug maps on the normal link path. A missing or ambiguous output nlist
/// simply declines this optional extension; the ordinary raw-section cache record remains valid
/// for unchanged symbol values.
fn linker_private_symbol_value_patches(
    layout: &Layout<'_, MachO>,
    object: &ObjectLayout<'_, MachO>,
    output: &[u8],
) -> Vec<SymbolValuePatch> {
    if !layout.args().should_strip_debug() {
        return Vec::new();
    }
    let Some(input_symtab) = macho_symtab(object.object.data) else {
        return Vec::new();
    };
    let Some(output_symtab) = macho_symtab(output) else {
        return Vec::new();
    };
    if output_symtab.has_stabs(output) {
        return Vec::new();
    }
    for (section_index, _) in object.object.enumerate_sections() {
        if object.live_input_ranges(section_index).is_some()
            || !object
                .relocations(section_index)
                .is_ok_and(|relocations| relocations.relocations.is_empty())
        {
            return Vec::new();
        }
    }

    let mut patches = Vec::new();
    for (symbol_index, symbol) in object.object.enumerate_symbols() {
        if symbol.n_type.is_stab()
            || symbol.n_type.typ() != object::macho::N_SECT
            || !symbol.n_type.is_pext()
        {
            continue;
        }
        let Some(section_index) = object.object.symbol_section(symbol, symbol_index).ok().flatten() else {
            continue;
        };
        let Some(SectionSlot::Loaded(_)) = object.sections.get(section_index.0) else {
            continue;
        };
        let Ok(input_section) = object.object.section(section_index) else {
            continue;
        };
        let Ok(raw_section) = object.object.raw_section_data(input_section) else {
            continue;
        };
        let input_section_address = input_section.addr.get(Endianness::Little);
        let Ok(input_section_size) = u64::try_from(raw_section.len()) else {
            continue;
        };
        if input_section_size == 0 || input_section.size.get(Endianness::Little) != input_section_size {
            continue;
        }
        let Ok(input_offset) = object
            .object
            .symbol_offset_in_section(symbol, section_index)
        else {
            continue;
        };
        if input_offset >= input_section_size {
            continue;
        }
        let Some(input_value_offset) = input_symtab.value_offset_for_symbol(symbol_index.0) else {
            continue;
        };
        if read_u64(object.object.data, input_value_offset) != Some(symbol.n_value.get(Endianness::Little)) {
            continue;
        }
        let Some(output_section_address) = object
            .section_resolutions
            .get(section_index.0)
            .and_then(|resolution| resolution.address())
        else {
            continue;
        };
        let Some(baseline_value) = output_section_address.checked_add(input_offset) else {
            continue;
        };
        let Ok(name) = object.object.symbol_name(symbol) else {
            continue;
        };
        let Some(output_value_offset) = output_symtab.unique_symbol_value_offset(
            output,
            name,
            symbol.n_type.0,
            symbol.n_desc.get(Endianness::Little).0,
            baseline_value,
        ) else {
            continue;
        };
        patches.push(SymbolValuePatch {
            input_value_offset: input_value_offset as u64,
            input_section_address,
            input_section_size,
            output_value_offset: output_value_offset as u64,
            output_section_address,
            baseline_value,
        });
    }
    normalise_symbol_value_patches(&mut patches)
        .map(|()| patches)
        .unwrap_or_default()
}

/// Builds the output-string patch map for one especially narrow Rustc incremental shape.
///
/// Rustc uses terminal `.llvm.<decimal>` discriminators for private external implementation
/// details. A small source edit can regenerate those numbers and reorder relocation records while
/// preserving every selected atom and final address. We may reuse the old link-edit allocation
/// only when the old spelling occurs exactly once, in the output nlist string table, and its
/// replacement will fit the same NUL-terminated slot. Anything caller-visible, ambiguous, or
/// structurally different remains an ordinary cache miss.
fn rustc_private_symbol_patches(
    object: &ObjectLayout<'_, MachO>,
    output: &[u8],
) -> Option<Vec<RustcPrivateSymbolPatch>> {
    let input_symtab = macho_symtab(object.object.data)?;
    let input_symbols = input_symtab.input_symbols(object.object.data)?;
    let output_symtab = macho_symtab(output)?;
    let mut patches = Vec::new();
    let mut saw_private_llvm_symbol = false;

    for (symbol_index, _) in object.object.enumerate_symbols() {
        let source = input_symbols.get(symbol_index.0)?;
        let Some(canonical_name) = rustc_private_symbol_base(&source.name) else {
            continue;
        };
        saw_private_llvm_symbol = true;
        if !is_rustc_private_symbol(source.n_type) {
            return None;
        }
        // Undefined references have no output nlist record. Their coordinated rename is bound
        // by the metadata digest; only a section-defined private external needs an output-string
        // patch.
        if source.n_type & N_PEXT.0 == 0 {
            continue;
        }

        let mut occurrences = memchr::memmem::find_iter(output, &source.name);
        let Some(occurrence) = occurrences.next() else {
            continue;
        };
        if occurrences.next().is_some() {
            return None;
        }

        let output_offset = output_symtab.unique_symbol_string_offset(
            output,
            &source.name,
            source.n_type,
            source.n_desc,
        )?;
        if occurrence != output_offset {
            return None;
        }
        patches.push(RustcPrivateSymbolPatch {
            input_symbol_index: u32::try_from(source.index).ok()?,
            canonical_name: canonical_name.to_vec(),
            expected: source.name.clone(),
            output_offset: output_offset as u64,
        });
    }

    saw_private_llvm_symbol.then(|| {
        patches.sort_by_key(|patch| patch.input_symbol_index);
        patches
    })
}

/// Returns the stable part of a Rustc-generated private LLVM symbol. Deliberately do not accept a
/// generic substring replacement: the decimal suffix must be terminal, nonempty, and retain a
/// nonempty symbol prefix.
fn rustc_private_symbol_base(name: &[u8]) -> Option<&[u8]> {
    let marker = b".llvm.";
    let marker_offset = name.windows(marker.len()).rposition(|window| window == marker)?;
    let suffix_start = marker_offset.checked_add(marker.len())?;
    let suffix = name.get(suffix_start..)?;
    (!suffix.is_empty()
        && suffix.iter().all(u8::is_ascii_digit)
        && marker_offset != 0)
        .then_some(&name[..marker_offset + marker.len()])
}

/// Rustc's LLVM discriminator is used only on compiler-private definitions and their external
/// references. Keeping this classification exact is what lets the cache canonicalize a suffix
/// without accepting a user-visible symbol whose spelling happens to end in `.llvm.<decimal>`.
fn is_rustc_private_symbol(n_type: u8) -> bool {
    let symbol_type = n_type & object::macho::N_TYPE;
    (symbol_type == object::macho::N_SECT.0 && n_type & N_PEXT.0 != 0)
        || (symbol_type == object::macho::N_UNDF.0
            && n_type & object::macho::N_EXT.0 != 0
            && n_type & N_PEXT.0 == 0)
}

/// Canonicalizes exactly the compiler-private names accepted by
/// [`rustc_private_symbol_base`]. A tag prevents a literal symbol from colliding with a stripped
/// private suffix in the metadata digest.
fn update_canonical_symbol_name(hasher: &mut blake3::Hasher, name: &[u8]) {
    match rustc_private_symbol_base(name) {
        Some(base) => {
            hasher.update(&[1]);
            hasher.update(&(base.len() as u64).to_le_bytes());
            hasher.update(base);
        }
        None => {
            hasher.update(&[0]);
            hasher.update(&(name.len() as u64).to_le_bytes());
            hasher.update(name);
        }
    }
}

/// Produces a cache-hit equivalence digest for the Rustc-private shape described above.
///
/// The normal structural digest still guards every ordinary Mach-O object. This path excludes
/// only the input nlist/string table and relocation record storage from its byte digest, then
/// rebinds them with stricter semantic digests: nlists retain type, section, descriptor, value,
/// order, and every non-private name; relocation groups retain their exact bytes and pairing but
/// may move as complete independent groups. Rustc's string table must remain the terminal file
/// region, so a changed string-table length cannot hide appended object data.
fn rustc_private_metadata(bytes: &[u8], patches: &[PatchRange]) -> Option<RustcPrivateMetadata> {
    let symtab = macho_symtab(bytes)?;
    let string_end = symtab.string_offset.checked_add(symtab.string_size)?;
    if string_end != bytes.len() {
        return None;
    }
    let symbols = symtab.input_symbols(bytes)?;
    if !symbols
        .iter()
        .any(|symbol| rustc_private_symbol_base(&symbol.name).is_some())
    {
        return None;
    }
    if symbols.iter().any(|symbol| {
        rustc_private_symbol_base(&symbol.name).is_some()
            && !is_rustc_private_symbol(symbol.n_type)
    }) {
        return None;
    }
    let (relocation_digest, relocation_ranges) = rustc_relocation_metadata(bytes)?;

    let mut masks = patches
        .iter()
        .map(|patch| InputRange {
            input_offset: patch.input_offset,
            len: patch.len,
        })
        .collect::<Vec<_>>();
    masks.push(InputRange {
        input_offset: symtab.symbol_offset as u64,
        len: u64::try_from(symtab.symbol_count.checked_mul(16)?).ok()?,
    });
    // `strsize` alone is allowed to change because the trailing input string table is omitted
    // from this digest. `stroff` stays bound by the unmasked command byte and prefix length.
    masks.push(InputRange {
        input_offset: u64::try_from(symtab.command_offset.checked_add(20)?).ok()?,
        len: size_of::<u32>() as u64,
    });
    masks.extend(relocation_ranges);
    normalise_input_ranges(&mut masks)?;
    let prefix = bytes.get(..symtab.string_offset)?;
    if masks.iter().any(|mask| {
        mask.input_offset
            .checked_add(mask.len)
            .is_none_or(|end| end > prefix.len() as u64)
    }) {
        return None;
    }
    let structure_digest = masked_digest_from_iter(prefix, masks.iter().copied());

    let mut symbols_hasher = blake3::Hasher::new();
    symbols_hasher.update(RUSTC_PRIVATE_METADATA_DIGEST_DOMAIN);
    symbols_hasher.update(b"symbols\0");
    symbols_hasher.update(&(symbols.len() as u64).to_le_bytes());
    for symbol in &symbols {
        symbols_hasher.update(&[symbol.n_type, symbol.n_sect]);
        symbols_hasher.update(&symbol.n_desc.to_le_bytes());
        symbols_hasher.update(&symbol.n_value.to_le_bytes());
        update_canonical_symbol_name(&mut symbols_hasher, &symbol.name);
    }

    let mut digest = blake3::Hasher::new();
    digest.update(RUSTC_PRIVATE_METADATA_DIGEST_DOMAIN);
    digest.update(&structure_digest);
    digest.update(symbols_hasher.finalize().as_bytes());
    digest.update(&relocation_digest);
    Some(RustcPrivateMetadata {
        digest: *digest.finalize().as_bytes(),
        symbols,
    })
}

/// Normalizes relocation-table ordering without loosening any relocation contents. Mach-O stores
/// a few same-address companion records as ordered pairs; they remain one byte-exact group. Only
/// complete groups at distinct source addresses may reorder, which is independent of relocation
/// semantics and is the exact variation Rustc exhibits for this cache shape.
fn rustc_relocation_metadata(bytes: &[u8]) -> Option<([u8; HASH_SIZE], Vec<InputRange>)> {
    if read_u32(bytes, 0)? != object::macho::MH_MAGIC_64 {
        return None;
    }
    let ncmds = usize::try_from(read_u32(bytes, 16)?).ok()?;
    let mut command_offset = 32usize;
    let mut section_index = 0usize;
    let mut ranges = Vec::new();
    let mut hasher = blake3::Hasher::new();
    hasher.update(RUSTC_PRIVATE_METADATA_DIGEST_DOMAIN);
    hasher.update(b"relocations\0");

    for _ in 0..ncmds {
        let command = read_u32(bytes, command_offset)?;
        let command_size = usize::try_from(read_u32(bytes, command_offset.checked_add(4)?)?).ok()?;
        let command_end = command_offset.checked_add(command_size)?;
        if command_size < 8 || command_end > bytes.len() {
            return None;
        }
        if command == object::macho::LC_SEGMENT_64.0 {
            let section_count = usize::try_from(read_u32(bytes, command_offset.checked_add(64)?)?).ok()?;
            let sections_offset = command_offset.checked_add(72)?;
            let sections_end = sections_offset.checked_add(section_count.checked_mul(80)?)?;
            if sections_end > command_end {
                return None;
            }
            for index in 0..section_count {
                let offset = sections_offset.checked_add(index.checked_mul(80)?)?;
                let relocation_offset = usize::try_from(read_u32(bytes, offset.checked_add(56)?)?).ok()?;
                let relocation_count = usize::try_from(read_u32(bytes, offset.checked_add(60)?)?).ok()?;
                hasher.update(&(section_index as u64).to_le_bytes());
                section_index = section_index.checked_add(1)?;
                if relocation_count == 0 {
                    hasher.update(&0_u64.to_le_bytes());
                    continue;
                }
                let relocation_len = relocation_count.checked_mul(8)?;
                let relocation_end = relocation_offset.checked_add(relocation_len)?;
                let table = bytes.get(relocation_offset..relocation_end)?;
                ranges.push(InputRange {
                    input_offset: relocation_offset as u64,
                    len: relocation_len as u64,
                });
                let mut groups = Vec::<Vec<u8>>::new();
                let mut seen_addresses = BTreeSet::new();
                for record in table.chunks_exact(8) {
                    let address = i32::from_le_bytes(record[..4].try_into().ok()?);
                    let starts_group = groups.last().is_none_or(|group| {
                        i32::from_le_bytes(group[..4].try_into().expect("relocation group starts with a record"))
                            != address
                    });
                    if starts_group {
                        if !seen_addresses.insert(address) {
                            return None;
                        }
                        groups.push(record.to_vec());
                    } else {
                        groups.last_mut()?.extend_from_slice(record);
                    }
                }
                groups.sort_unstable();
                hasher.update(&(groups.len() as u64).to_le_bytes());
                for group in groups {
                    hasher.update(&(group.len() as u64).to_le_bytes());
                    hasher.update(&group);
                }
            }
        }
        command_offset = command_end;
    }
    Some((*hasher.finalize().as_bytes(), ranges))
}

fn collect_protected_relocation_ranges(
    object: &ObjectLayout<'_, MachO>,
    section_index: object::SectionIndex,
    section_input_offset: usize,
    raw_len: usize,
    data: &[u8],
) -> Option<Vec<ProtectedRange>> {
    let mut protected = Vec::new();
    for relocation in macho::paired_relocations(object.relocations(section_index).ok()?.relocations) {
        let relocation = relocation.ok()?;
        let field_offset = usize::try_from(relocation.info.r_address).ok()?;
        let width = 1usize.checked_shl(u32::from(relocation.info.r_length))?;
        let end = field_offset.checked_add(width)?;
        if end > raw_len || !object.input_range_is_live(section_index, field_offset as u64..end as u64) {
            continue;
        }
        let input_offset = section_input_offset.checked_add(field_offset)?;
        let bytes = data.get(input_offset..input_offset.checked_add(width)?)?.to_vec();
        protected.push(ProtectedRange {
            input_offset: input_offset as u64,
            bytes,
        });
    }
    normalise_protected_ranges(&mut protected)?;
    Some(protected)
}

/// A relocated word in the baseline already contains its resolved final address. Copying the
/// current object's pre-relocation bytes over that word would corrupt the executable, even when
/// the relocation record itself did not change. Split every raw section patch around protected
/// relocation fields so those baseline words remain intact.
fn add_patch_ranges_excluding_protected(
    patches: &mut Vec<PatchRange>,
    input_offset: usize,
    output_offset: usize,
    len: usize,
    protected: &[ProtectedRange],
) -> Option<()> {
    let end = input_offset.checked_add(len)?;
    let mut cursor = input_offset;
    for protected in protected {
        let protected_start = usize::try_from(protected.input_offset).ok()?;
        let protected_end = protected_start.checked_add(protected.bytes.len())?;
        if protected_end <= input_offset || protected_start >= end {
            continue;
        }
        if protected_start < cursor || protected_end > end {
            return None;
        }
        if cursor < protected_start {
            patches.push(PatchRange {
                input_offset: cursor as u64,
                output_offset: output_offset.checked_add(cursor - input_offset)? as u64,
                len: (protected_start - cursor) as u64,
            });
        }
        cursor = protected_end;
    }
    if cursor < end {
        patches.push(PatchRange {
            input_offset: cursor as u64,
            output_offset: output_offset.checked_add(cursor - input_offset)? as u64,
            len: (end - cursor) as u64,
        });
    }
    Some(())
}

fn normalise_ranges(ranges: &mut Vec<PatchRange>) -> Option<()> {
    ranges.sort_by_key(|range| range.input_offset);
    let mut out = Vec::<PatchRange>::with_capacity(ranges.len());
    for range in ranges.drain(..) {
        if range.len == 0 {
            continue;
        }
        let input_end = range.input_offset.checked_add(range.len)?;
        let _ = range.output_offset.checked_add(range.len)?;
        if let Some(previous) = out.last() {
            if previous.input_offset.checked_add(previous.len)? > range.input_offset {
                return None;
            }
        }
        let _ = input_end;
        out.push(range);
    }
    let mut output_order = out.clone();
    output_order.sort_by_key(|range| range.output_offset);
    if output_order.windows(2).any(|pair| {
        pair[0]
            .output_offset
            .checked_add(pair[0].len)
            .is_none_or(|end| end > pair[1].output_offset)
    }) {
        return None;
    }
    *ranges = out;
    Some(())
}

fn normalise_protected_ranges(ranges: &mut Vec<ProtectedRange>) -> Option<()> {
    ranges.sort_by_key(|range| range.input_offset);
    ranges.dedup_by(|left, right| {
        left.input_offset == right.input_offset && left.bytes == right.bytes
    });
    ranges
        .windows(2)
        .all(|pair| {
            pair[0]
                .input_offset
                .checked_add(pair[0].bytes.len() as u64)
                .is_some_and(|end| end <= pair[1].input_offset)
        })
        .then_some(())
}

fn normalise_input_ranges(ranges: &mut Vec<InputRange>) -> Option<()> {
    ranges.sort_by_key(|range| range.input_offset);
    ranges.dedup();
    ranges
        .iter()
        .all(|range| range.len != 0 && range.input_offset.checked_add(range.len).is_some())
        .then_some(())?;
    ranges
        .windows(2)
        .all(|pair| {
            pair[0]
                .input_offset
                .checked_add(pair[0].len)
                .is_some_and(|end| end <= pair[1].input_offset)
        })
        .then_some(())
}

fn input_ranges_are_normalized(mut ranges: impl Iterator<Item = InputRange>) -> bool {
    let mut previous_end = 0_u64;
    ranges.all(|range| {
        range.len != 0
            && range
                .input_offset
                .checked_add(range.len)
                .is_some_and(|end| {
                    let valid = range.input_offset >= previous_end;
                    previous_end = end;
                    valid
                })
    })
}

fn normalise_symbol_value_patches(patches: &mut Vec<SymbolValuePatch>) -> Option<()> {
    patches.sort_by_key(|patch| patch.input_value_offset);
    symbol_value_patches_are_normalized_from_iter(patches.iter().copied()).then_some(())
}

fn symbol_value_patches_are_normalized(patches: &[SymbolValuePatch]) -> bool {
    symbol_value_patches_are_normalized_from_iter(patches.iter().copied())
}

fn symbol_value_patches_are_normalized_from_iter(
    mut patches: impl Iterator<Item = SymbolValuePatch>,
) -> bool {
    let mut previous_input_end = 0_u64;
    let mut output_offsets = Vec::new();
    patches.all(|patch| {
        let Some(input_end) = patch.input_value_offset.checked_add(size_of::<u64>() as u64) else {
            return false;
        };
        let Some(output_end) = patch.output_value_offset.checked_add(size_of::<u64>() as u64) else {
            return false;
        };
        let valid = patch.input_section_size != 0
            && patch
                .input_section_address
                .checked_add(patch.input_section_size)
                .is_some()
            && patch
                .output_section_address
                .checked_add(patch.input_section_size)
                .is_some()
            && patch.input_value_offset >= previous_input_end;
        previous_input_end = input_end;
        output_offsets.push((patch.output_value_offset, output_end));
        valid
    }) && {
        output_offsets.sort_unstable_by_key(|(start, _)| *start);
        output_offsets
            .windows(2)
            .all(|pair| pair[0].1 <= pair[1].0)
    }
}

fn slice_offset(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    let start = needle.as_ptr() as usize;
    let base = haystack.as_ptr() as usize;
    let offset = start.checked_sub(base)?;
    (offset <= haystack.len() && needle.len() <= haystack.len().checked_sub(offset)?)
        .then_some(offset)
}

#[cfg(test)]
fn masked_digest(bytes: &[u8], ranges: &[PatchRange]) -> [u8; HASH_SIZE] {
    let ranges = ranges
        .iter()
        .map(|range| InputRange {
            input_offset: range.input_offset,
            len: range.len,
        })
        .collect::<Vec<_>>();
    masked_digest_for_input_ranges(bytes, &ranges)
}

fn masked_digest_for_input_ranges(bytes: &[u8], ranges: &[InputRange]) -> [u8; HASH_SIZE] {
    masked_digest_from_iter(bytes, ranges.iter().copied())
}

fn masked_digest_from_iter<I>(bytes: &[u8], ranges: I) -> [u8; HASH_SIZE]
where
    I: Clone + ExactSizeIterator<Item = InputRange>,
{
    // A structural digest intentionally ignores patchable input bytes. Persist all input range
    // locations before the retained bytes, then hash one contiguous preimage. Dead-strip-heavy
    // Rust objects can have thousands of tiny live ranges; avoiding several Hasher::update calls
    // per range matters on the incremental hot path. Output offsets are baseline patch targets,
    // not a property of the new object, so the object-structure contract binds only its input
    // ranges and length.
    let mut cursor = 0usize;
    let mut ignored_len = 0usize;
    for range in ranges.clone() {
        let Some(start) = usize::try_from(range.input_offset).ok() else {
            return [0; HASH_SIZE];
        };
        let Some(end) = start.checked_add(usize::try_from(range.len).unwrap_or(usize::MAX)) else {
            return [0; HASH_SIZE];
        };
        if start < cursor || end > bytes.len() {
            return [0; HASH_SIZE];
        }
        let Some(next_ignored_len) = ignored_len.checked_add(end - start) else {
            return [0; HASH_SIZE];
        };
        ignored_len = next_ignored_len;
        cursor = end;
    }
    let Some(range_metadata_len) = ranges.len().checked_mul(2 * size_of::<u64>()) else {
        return [0; HASH_SIZE];
    };
    let Some(capacity) = STRUCTURE_DIGEST_DOMAIN
        .len()
        .checked_add(2 * size_of::<u64>())
        .and_then(|capacity| capacity.checked_add(range_metadata_len))
        .and_then(|capacity| capacity.checked_add(bytes.len().saturating_sub(ignored_len)))
    else {
        return [0; HASH_SIZE];
    };
    let mut preimage = Vec::with_capacity(capacity);
    preimage.extend_from_slice(STRUCTURE_DIGEST_DOMAIN);
    preimage.extend_from_slice(&(bytes.len() as u64).to_le_bytes());
    preimage.extend_from_slice(&(ranges.len() as u64).to_le_bytes());
    for range in ranges.clone() {
        preimage.extend_from_slice(&range.input_offset.to_le_bytes());
        preimage.extend_from_slice(&range.len.to_le_bytes());
    }
    cursor = 0;
    for range in ranges {
        let Some(start) = usize::try_from(range.input_offset).ok() else {
            return [0; HASH_SIZE];
        };
        let Some(end) = start.checked_add(usize::try_from(range.len).unwrap_or(usize::MAX)) else {
            return [0; HASH_SIZE];
        };
        preimage.extend_from_slice(&bytes[cursor..start]);
        cursor = end;
    }
    preimage.extend_from_slice(&bytes[cursor..]);
    *blake3::hash(&preimage).as_bytes()
}

#[cfg(test)]
fn protected_ranges_match(bytes: &[u8], ranges: &[ProtectedRange]) -> bool {
    protected_ranges_match_from_iter(
        bytes,
        ranges.iter().map(|range| ProtectedRangeRef {
            input_offset: range.input_offset,
            bytes: &range.bytes,
        }),
    )
}

fn protected_ranges_match_from_iter<'a>(
    bytes: &[u8],
    mut ranges: impl Iterator<Item = ProtectedRangeRef<'a>>,
) -> bool {
    ranges.all(|range| {
        usize::try_from(range.input_offset)
            .ok()
            .and_then(|start| start.checked_add(range.bytes.len()))
            .and_then(|end| bytes.get(end - range.bytes.len()..end))
            == Some(range.bytes)
    })
}

/// Every source type must own disjoint output bytes before a multi-object hit mutates its private
/// output image. Individual records already prove their own ranges; this check closes the
/// cross-record, symbol-value, and rewritten-debug-path gap before patch order could matter.
fn output_patch_ranges_are_disjoint(
    output_len: usize,
    ranges: impl IntoIterator<Item = PatchRange>,
) -> bool {
    let mut ranges = ranges.into_iter().collect::<Vec<_>>();
    ranges.sort_unstable_by_key(|range| range.output_offset);
    let mut previous_end = 0_usize;
    ranges.into_iter().all(|range| {
        let Some(start) = usize::try_from(range.output_offset).ok() else {
            return false;
        };
        let Some(len) = usize::try_from(range.len).ok() else {
            return false;
        };
        let Some(end) = start.checked_add(len) else {
            return false;
        };
        let valid = len != 0 && start >= previous_end && end <= output_len;
        previous_end = end;
        valid
    })
}

fn patch_ranges_are_applicable(
    output_len: usize,
    input: &[u8],
    mut ranges: impl Iterator<Item = PatchRange>,
) -> bool {
    ranges.all(|range| {
        let Some(input_start) = usize::try_from(range.input_offset).ok() else {
            return false;
        };
        let Some(output_start) = usize::try_from(range.output_offset).ok() else {
            return false;
        };
        let Some(len) = usize::try_from(range.len).ok() else {
            return false;
        };
        let Some(input_end) = input_start.checked_add(len) else {
            return false;
        };
        let Some(output_end) = output_start.checked_add(len) else {
            return false;
        };
        len != 0 && input_end <= input.len() && output_end <= output_len
    })
}

fn symbol_value_patches_are_applicable(
    output: &[u8],
    input: &[u8],
    mut patches: impl Iterator<Item = SymbolValuePatch>,
) -> bool {
    patches.all(|patch| {
        let Some(input_offset) = usize::try_from(patch.input_value_offset).ok() else {
            return false;
        };
        let Some(output_offset) = usize::try_from(patch.output_value_offset).ok() else {
            return false;
        };
        let Some(input_end) = input_offset.checked_add(size_of::<u64>()) else {
            return false;
        };
        let Some(output_end) = output_offset.checked_add(size_of::<u64>()) else {
            return false;
        };
        let Some(input_value) = input
            .get(input_offset..input_end)
            .and_then(|bytes| bytes.try_into().ok())
            .map(u64::from_le_bytes)
        else {
            return false;
        };
        let Some(current_output) = output
            .get(output_offset..output_end)
            .and_then(|bytes| bytes.try_into().ok())
            .map(u64::from_le_bytes)
        else {
            return false;
        };
        let Some(input_section_offset) = input_value.checked_sub(patch.input_section_address)
        else {
            return false;
        };
        input_section_offset < patch.input_section_size
            && current_output == patch.baseline_value
            && patch
                .output_section_address
                .checked_add(input_section_offset)
                .is_some()
    })
}

fn output_path_patches_are_applicable(output: &[u8], patches: &[OutputPathPatch]) -> bool {
    let mut previous_end = 0_usize;
    patches.iter().all(|patch| {
        if patch.expected.len() != patch.replacement.len() || patch.expected.is_empty() {
            return false;
        }
        let Some(start) = usize::try_from(patch.output_offset).ok() else {
            return false;
        };
        let Some(end) = start.checked_add(patch.expected.len()) else {
            return false;
        };
        let valid = start >= previous_end && output.get(start..end) == Some(patch.expected.as_slice());
        previous_end = end;
        valid
    })
}

#[cfg(test)]
fn apply_patches(output: &mut [u8], input: &[u8], ranges: &[PatchRange]) -> bool {
    apply_patches_from_iter(output, input, ranges.iter().copied())
}

fn apply_patches_from_iter(
    output: &mut [u8],
    input: &[u8],
    mut ranges: impl Iterator<Item = PatchRange>,
) -> bool {
    ranges.all(|range| {
        let Some(input_start) = usize::try_from(range.input_offset).ok() else {
            return false;
        };
        let Some(output_start) = usize::try_from(range.output_offset).ok() else {
            return false;
        };
        let Some(len) = usize::try_from(range.len).ok() else {
            return false;
        };
        let Some(input_end) = input_start.checked_add(len) else {
            return false;
        };
        let Some(output_end) = output_start.checked_add(len) else {
            return false;
        };
        let (Some(source), Some(destination)) = (
            input.get(input_start..input_end),
            output.get_mut(output_start..output_end),
        ) else {
            return false;
        };
        destination.copy_from_slice(source);
        true
    })
}

#[cfg(test)]
fn apply_symbol_value_patches(
    output: &mut [u8],
    input: &[u8],
    patches: &[SymbolValuePatch],
) -> bool {
    apply_symbol_value_patches_from_iter(output, input, patches.iter().copied())
}

fn apply_symbol_value_patches_from_iter(
    output: &mut [u8],
    input: &[u8],
    mut patches: impl Iterator<Item = SymbolValuePatch>,
) -> bool {
    patches.all(|patch| {
        let Some(input_offset) = usize::try_from(patch.input_value_offset).ok() else {
            return false;
        };
        let Some(output_offset) = usize::try_from(patch.output_value_offset).ok() else {
            return false;
        };
        let Some(input_end) = input_offset.checked_add(size_of::<u64>()) else {
            return false;
        };
        let Some(output_end) = output_offset.checked_add(size_of::<u64>()) else {
            return false;
        };
        let Some(input_value) = input
            .get(input_offset..input_end)
            .and_then(|bytes| bytes.try_into().ok())
            .map(u64::from_le_bytes)
        else {
            return false;
        };
        let Some(current_output) = output
            .get(output_offset..output_end)
            .and_then(|bytes| bytes.try_into().ok())
            .map(u64::from_le_bytes)
        else {
            return false;
        };
        let Some(input_section_offset) = input_value.checked_sub(patch.input_section_address)
        else {
            return false;
        };
        if input_section_offset >= patch.input_section_size || current_output != patch.baseline_value {
            return false;
        }
        let Some(output_value) = patch.output_section_address.checked_add(input_section_offset) else {
            return false;
        };
        let Some(destination) = output.get_mut(output_offset..output_end) else {
            return false;
        };
        destination.copy_from_slice(&output_value.to_le_bytes());
        true
    })
}

fn apply_output_path_patches(output: &mut [u8], patches: &[OutputPathPatch]) -> bool {
    if !output_path_patches_are_applicable(output, patches) {
        return false;
    }
    for patch in patches {
        let start = usize::try_from(patch.output_offset).unwrap();
        let end = start.checked_add(patch.expected.len()).unwrap();
        output[start..end].copy_from_slice(&patch.replacement);
    }
    true
}

fn signature_info(layout: &Layout<'_, MachO>, output: &[u8]) -> Option<SignatureInfo> {
    let code_signature = layout
        .section_layouts
        .get(output_section_id::CODE_SIGNATURE);
    let code_limit = u64::try_from(code_signature.file_offset).ok()?;
    let identifier_offset = code_limit.checked_add(macho::CS_HEADERS_SIZE)?;
    let identifier_capacity = macho::code_signature_padded_identifier_size(layout.args());
    let hashes_offset = identifier_offset.checked_add(identifier_capacity)?;
    let hash_count = u32::try_from(code_limit.div_ceil(macho::CS_BLOCK_SIZE as u64)).ok()?;
    let uuid_offset = find_uuid_offset(output)?;
    let hashes_len = u64::from(hash_count).checked_mul(u64::from(macho::CS_HASH_SIZE))?;
    (hashes_offset.checked_add(hashes_len)? <= output.len() as u64).then_some(SignatureInfo {
        code_limit,
        hashes_offset,
        hash_count,
        uuid_offset,
        identifier_offset,
        identifier_capacity,
    })
}

fn find_uuid_offset(output: &[u8]) -> Option<u64> {
    // mach_header_64 is 32 bytes; ncmds is its fifth 32-bit word.
    let ncmds = read_u32(output, 16)? as usize;
    let mut offset = 32usize;
    for _ in 0..ncmds {
        let command = read_u32(output, offset)?;
        let command_size = read_u32(output, offset.checked_add(4)?)? as usize;
        if command_size < 8 || offset.checked_add(command_size)? > output.len() {
            return None;
        }
        if command == LC_UUID.0 {
            return (command_size >= 24).then_some((offset + 8) as u64);
        }
        offset += command_size;
    }
    None
}

fn output_identity(output: &[u8], signature: &SignatureInfo) -> Option<OutputIdentity> {
    let (_, _, hashes_offset, hashes_end) = signature_identity_ranges(output, signature)?;
    Some(OutputIdentity {
        normalized_digest: normalized_output_digest(output, signature)?,
        signature_hashes_digest: *blake3::hash(&output[hashes_offset..hashes_end]).as_bytes(),
    })
}

#[cfg(test)]
fn output_matches_identity(
    output: &[u8],
    signature: &SignatureInfo,
    expected: &OutputIdentity,
) -> bool {
    let Some((uuid_offset, uuid_end, _, _)) = signature_identity_ranges(output, signature) else {
        return false;
    };
    output.get(uuid_offset..uuid_end) == Some(uuid_from_normalized_digest(&expected.normalized_digest).as_slice())
        && output_identity(output, signature).as_ref() == Some(expected)
}

/// BLAKE3 of the output with the bytes derived by Mach-O's ad-hoc signing scheme replaced by
/// zeroes. This is exactly the digest from which `refresh_uuid_and_signature` derives `LC_UUID`.
fn normalized_output_digest(output: &[u8], signature: &SignatureInfo) -> Option<[u8; HASH_SIZE]> {
    let (uuid_offset, uuid_end, hashes_offset, hashes_end) =
        signature_identity_ranges(output, signature)?;
    let mut hasher = blake3::Hasher::new();
    hasher.update(&output[..uuid_offset]);
    update_blake3_with_zeroes(&mut hasher, uuid_end - uuid_offset);
    hasher.update(&output[uuid_end..hashes_offset]);
    update_blake3_with_zeroes(&mut hasher, hashes_end - hashes_offset);
    hasher.update(&output[hashes_end..]);
    Some(*hasher.finalize().as_bytes())
}

fn uuid_from_normalized_digest(digest: &[u8; HASH_SIZE]) -> [u8; 16] {
    let mut uuid: [u8; 16] = digest[..16]
        .try_into()
        .expect("BLAKE3 output starts with a UUID-width prefix");
    uuid[6] = (uuid[6] & 0x0f) | 0x30;
    uuid[8] = (uuid[8] & 0x3f) | 0x80;
    uuid
}

/// Advances the cache-owned UUID chain using only the bounded changed-object snapshots. Unlike
/// a whole-image digest, this remains proportional to the incremental edit while ensuring that
/// successive cache publications receive distinct, deterministic UUIDs for distinct inputs.
fn cache_uuid_seed(
    previous: [u8; HASH_SIZE],
    changed_objects: &[ChangedObject<'_, '_>],
) -> [u8; HASH_SIZE] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(CACHE_UUID_SEED_DOMAIN);
    hasher.update(&previous);
    hasher.update(&(changed_objects.len() as u64).to_le_bytes());
    for changed in changed_objects {
        hasher.update(&changed.object.input_index.to_le_bytes());
        hasher.update(blake3::hash(changed.bytes).as_bytes());
    }
    *hasher.finalize().as_bytes()
}

fn signature_identity_ranges(
    output: &[u8],
    signature: &SignatureInfo,
) -> Option<(usize, usize, usize, usize)> {
    let code_limit = usize::try_from(signature.code_limit).ok()?;
    let hashes_offset = usize::try_from(signature.hashes_offset).ok()?;
    let hash_count = usize::try_from(signature.hash_count).ok()?;
    let hashes_len = usize::try_from(u64::from(signature.hash_count) * u64::from(macho::CS_HASH_SIZE)).ok()?;
    let hashes_end = hashes_offset.checked_add(hashes_len)?;
    let uuid_offset = usize::try_from(signature.uuid_offset).ok()?;
    let uuid_end = uuid_offset.checked_add(16)?;
    (hash_count == code_limit.div_ceil(macho::CS_BLOCK_SIZE)
        && uuid_end <= code_limit
        && code_limit <= hashes_offset
        && hashes_end <= output.len()
        && uuid_end <= hashes_offset)
        .then_some((uuid_offset, uuid_end, hashes_offset, hashes_end))
}

fn update_blake3_with_zeroes(hasher: &mut blake3::Hasher, len: usize) {
    const ZEROES: [u8; 4096] = [0; 4096];
    let mut remaining = len;
    while remaining != 0 {
        let chunk_len = remaining.min(ZEROES.len());
        hasher.update(&ZEROES[..chunk_len]);
        remaining -= chunk_len;
    }
}

fn refresh_uuid_and_signature(
    output: &mut [u8],
    signature: &SignatureInfo,
    args: &MachOArgs,
    uuid_seed: &[u8; HASH_SIZE],
    changed_patches: impl Iterator<Item = PatchRange>,
) -> bool {
    let Some(code_limit) = usize::try_from(signature.code_limit).ok() else {
        return false;
    };
    let Some(hashes_offset) = usize::try_from(signature.hashes_offset).ok() else {
        return false;
    };
    let Some(uuid_offset) = usize::try_from(signature.uuid_offset).ok() else {
        return false;
    };
    let Some(identifier_offset) = usize::try_from(signature.identifier_offset).ok() else {
        return false;
    };
    let Some(identifier_capacity) = usize::try_from(signature.identifier_capacity).ok() else {
        return false;
    };
    let Some(hashes_len) = usize::try_from(u64::from(signature.hash_count) * u64::from(macho::CS_HASH_SIZE)).ok() else {
        return false;
    };
    let Some(hashes_end) = hashes_offset.checked_add(hashes_len) else {
        return false;
    };
    let Some(uuid_end) = uuid_offset.checked_add(16) else {
        return false;
    };
    let Some(identifier_end) = identifier_offset.checked_add(identifier_capacity) else {
        return false;
    };
    if code_limit > output.len()
        || hashes_end > output.len()
        || uuid_end > output.len()
        || uuid_end > code_limit
        || identifier_end != hashes_offset
    {
        return false;
    }

    // `code_signature_identifier` is the output basename. A Rustc rebuild may change its
    // disambiguator, but the preallocated field is safe to reuse only when the new identifier
    // (including its terminator) still fits the original padded allocation.
    let identifier = macho::code_signature_identifier(args);
    let Some(identifier_len) = identifier.len().checked_add(1) else {
        return false;
    };
    if identifier_len > identifier_capacity {
        return false;
    }
    output[identifier_offset..identifier_end].fill(0);
    output[identifier_offset..identifier_offset + identifier.len()].copy_from_slice(identifier);

    // The cache image has a state-bound filesystem identity, so its unchanged code-signature
    // pages are already known-good. A UUID need not be a full-image digest: derive a fresh,
    // deterministic one from the bounded changed-input chain and rehash its one code page.
    output[uuid_offset..uuid_end].copy_from_slice(&uuid_from_normalized_digest(uuid_seed));

    if !refresh_changed_code_signature_hashes(
        output,
        code_limit,
        hashes_offset,
        usize::try_from(signature.hash_count).unwrap_or(usize::MAX),
        uuid_offset,
        changed_patches,
    ) {
        return false;
    }
    true
}

/// Rehashes the CodeDirectory pages changed by a cache patch and the page containing its fresh
/// UUID. All remaining slots were validated as part of the cache-owned baseline image and remain
/// valid because no cache patch is allowed to extend outside signed output bytes.
fn refresh_changed_code_signature_hashes(
    output: &mut [u8],
    code_limit: usize,
    hashes_offset: usize,
    hash_count: usize,
    uuid_offset: usize,
    changed_patches: impl Iterator<Item = PatchRange>,
) -> bool {
    if hash_count != code_limit.div_ceil(macho::CS_BLOCK_SIZE) || uuid_offset >= code_limit {
        return false;
    }
    let hash_size = usize::from(macho::CS_HASH_SIZE);
    let Some(hashes_len) = hash_count.checked_mul(hash_size) else {
        return false;
    };
    let Some(hashes_end) = hashes_offset.checked_add(hashes_len) else {
        return false;
    };
    if hashes_end > output.len() {
        return false;
    }

    let mut changed_pages = vec![false; hash_count];
    changed_pages[uuid_offset / macho::CS_BLOCK_SIZE] = true;
    for patch in changed_patches {
        let Some(start) = usize::try_from(patch.output_offset).ok() else {
            return false;
        };
        let Some(len) = usize::try_from(patch.len).ok() else {
            return false;
        };
        let Some(end) = start.checked_add(len) else {
            return false;
        };
        if len == 0 || end > code_limit {
            return false;
        }
        let first_page = start / macho::CS_BLOCK_SIZE;
        let last_page = (end - 1) / macho::CS_BLOCK_SIZE;
        for page in first_page..=last_page {
            changed_pages[page] = true;
        }
    }

    for (page, changed) in changed_pages.into_iter().enumerate() {
        if !changed {
            continue;
        }
        let Some(page_start) = page.checked_mul(macho::CS_BLOCK_SIZE) else {
            return false;
        };
        let page_end = page_start.saturating_add(macho::CS_BLOCK_SIZE).min(code_limit);
        let digest = <sha2::Sha256 as sha2::Digest>::digest(&output[page_start..page_end]);
        let Some(slot_start) = page
            .checked_mul(hash_size)
            .and_then(|offset| hashes_offset.checked_add(offset))
        else {
            return false;
        };
        let Some(slot_end) = slot_start.checked_add(hash_size) else {
            return false;
        };
        let Some(slot) = output.get_mut(slot_start..slot_end) else {
            return false;
        };
        slot.copy_from_slice(&digest);
    }
    true
}

fn write_output_atomic(path: &Path, output: &[u8]) -> std::io::Result<()> {
    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    let name = path.file_name().and_then(|name| name.to_str()).unwrap_or("output");
    let unique = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    let temporary = parent.join(format!(".{name}.wild-incremental.{}.{}.tmp", std::process::id(), unique));
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&temporary)?;
    file.write_all(output)?;
    crate::make_executable(&file).map_err(|error| std::io::Error::other(error.to_string()))?;
    // The ordinary Mach-O writer flushes and closes its output without requesting durable media
    // storage. Closing this replacement before its rename gives the same successful-link
    // contract while avoiding an unnecessary APFS durability barrier on every cache hit.
    drop(file);
    replace_output_after_detaching_previous(&temporary, path)
}

/// Publishes a cache-hit output through a fresh pathname rather than replacing an already
/// executable file in place. macOS caches code-signature state by vnode, and a direct `rename`
/// over an executed Cargo artifact can still leave that path unable to execute even when the
/// replacement's bytes and embedded signature are valid. This is the same detach-before-create
/// contract as the ordinary Mach-O writer's `UnlinkAndReplace` mode.
fn replace_output_after_detaching_previous(staged: &Path, output: &Path) -> std::io::Result<()> {
    let parent = output.parent().unwrap_or_else(|| Path::new("."));
    let name = output
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("output");
    let unique = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    let previous = parent.join(format!(
        ".{name}.wild-incremental-previous.{}.{}",
        std::process::id(),
        unique
    ));
    let detached_previous = match fs::rename(output, &previous) {
        Ok(()) => Some(previous),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => None,
        Err(error) => return Err(error),
    };
    if let Err(error) = fs::rename(staged, output) {
        if let Some(previous) = detached_previous {
            let _ = fs::rename(previous, output);
        }
        return Err(error);
    }
    if let Some(previous) = detached_previous {
        let _ = fs::remove_file(previous);
    }
    Ok(())
}

#[cfg(target_os = "macos")]
fn clone_baseline_image(cache_dir: &Path, args: &MachOArgs) -> Option<MutableOutput> {
    let source = cache_image_path(cache_dir, args);
    let staged_path = clone_temporary_path(args.output());
    clone_file(&source, &staged_path).ok()?;
    let file = match fs::OpenOptions::new().read(true).write(true).open(&staged_path) {
        Ok(file) => file,
        Err(_) => {
            let _ = fs::remove_file(&staged_path);
            return None;
        }
    };
    if crate::make_executable(&file).is_err() {
        let _ = fs::remove_file(&staged_path);
        return None;
    }
    let mapping = match unsafe { memmap2::MmapOptions::new().map_mut(&file) } {
        Ok(mapping) => mapping,
        Err(_) => {
            let _ = fs::remove_file(&staged_path);
            return None;
        }
    };
    Some(MutableOutput::Cloned {
        staged_path,
        mapping,
    })
}

#[cfg(target_os = "macos")]
fn clone_cache_image_atomic(cache_dir: &Path, args: &MachOArgs) -> std::io::Result<()> {
    fs::create_dir_all(cache_dir)?;
    let target = cache_image_path(cache_dir, args);
    let temporary = clone_temporary_path(&target);
    clone_file(args.output(), &temporary)?;
    if let Err(error) = fs::rename(&temporary, target) {
        let _ = fs::remove_file(temporary);
        return Err(error);
    }
    Ok(())
}

#[cfg(target_os = "macos")]
fn clone_file(source: &Path, destination: &Path) -> std::io::Result<()> {
    let source = CString::new(source.as_os_str().as_bytes())
        .map_err(|_| std::io::Error::new(std::io::ErrorKind::InvalidInput, "NUL in cache path"))?;
    let destination = CString::new(destination.as_os_str().as_bytes())
        .map_err(|_| std::io::Error::new(std::io::ErrorKind::InvalidInput, "NUL in cache path"))?;
    // `clonefile` is APFS copy-on-write. A cross-volume or unsupported-filesystem error is
    // intentionally handled by the caller as an in-memory cache hit, never as an unsafe copy.
    if unsafe { libc::clonefile(source.as_ptr(), destination.as_ptr(), 0) } != 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(())
}

fn cache_image_token_for_manifest(manifest: &Manifest) -> [u8; 16] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(CACHE_IMAGE_TOKEN_DOMAIN);
    hasher.update(&manifest.arguments_digest);
    hasher.update(&manifest.output_identity.normalized_digest);
    hasher.update(&manifest.output_len.to_le_bytes());
    hasher.finalize().as_bytes()[..16]
        .try_into()
        .expect("BLAKE3 output contains an image token")
}

#[cfg(target_os = "macos")]
fn cache_image_token(path: &Path) -> Option<[u8; 16]> {
    let path = CString::new(path.as_os_str().as_bytes()).ok()?;
    let name = CString::new(CACHE_IMAGE_TOKEN_XATTR).ok()?;
    let mut token = [0_u8; 16];
    let read = unsafe {
        libc::getxattr(
            path.as_ptr(),
            name.as_ptr(),
            token.as_mut_ptr().cast(),
            token.len(),
            0,
            0,
        )
    };
    (usize::try_from(read).ok() == Some(token.len())).then_some(token)
}

#[cfg(not(target_os = "macos"))]
fn cache_image_token(_path: &Path) -> Option<[u8; 16]> {
    None
}

#[cfg(target_os = "macos")]
fn set_cache_image_token(path: &Path, token: [u8; 16]) -> bool {
    let Ok(path) = CString::new(path.as_os_str().as_bytes()) else {
        return false;
    };
    let Ok(name) = CString::new(CACHE_IMAGE_TOKEN_XATTR) else {
        return false;
    };
    unsafe {
        libc::setxattr(
            path.as_ptr(),
            name.as_ptr(),
            token.as_ptr().cast(),
            token.len(),
            0,
            0,
        ) == 0
    }
}

#[cfg(not(target_os = "macos"))]
fn set_cache_image_token(_path: &Path, _token: [u8; 16]) -> bool {
    false
}

#[cfg(target_os = "macos")]
fn clone_temporary_path(target: &Path) -> PathBuf {
    let parent = target.parent().unwrap_or_else(|| Path::new("."));
    let name = target.file_name().and_then(|name| name.to_str()).unwrap_or("cache");
    let unique = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    parent.join(format!(
        ".{name}.wild-incremental-clone.{}.{}.tmp",
        std::process::id(),
        unique
    ))
}

fn read_u32(bytes: &[u8], offset: usize) -> Option<u32> {
    bytes
        .get(offset..offset.checked_add(4)?)?
        .try_into()
        .ok()
        .map(u32::from_le_bytes)
}

fn read_u16(bytes: &[u8], offset: usize) -> Option<u16> {
    bytes
        .get(offset..offset.checked_add(2)?)?
        .try_into()
        .ok()
        .map(u16::from_le_bytes)
}

fn read_u64(bytes: &[u8], offset: usize) -> Option<u64> {
    bytes
        .get(offset..offset.checked_add(8)?)?
        .try_into()
        .ok()
        .map(u64::from_le_bytes)
}

fn write_staged_manifest_atomic(
    cache_dir: &Path,
    args: &MachOArgs,
    manifest: &Manifest,
) -> std::io::Result<()> {
    fs::create_dir_all(cache_dir)?;
    let target = staged_cache_path(cache_dir, args);
    write_bytes_atomic(cache_dir, &target, &manifest.encode())
}

fn write_image_state_atomic(
    cache_dir: &Path,
    args: &MachOArgs,
    state: &ImageState,
) -> std::io::Result<()> {
    fs::create_dir_all(cache_dir)?;
    write_bytes_atomic(cache_dir, &cache_state_path(cache_dir, args), &state.encode())
}

fn write_staged_image_state_atomic(
    cache_dir: &Path,
    args: &MachOArgs,
    state: &ImageState,
) -> std::io::Result<()> {
    fs::create_dir_all(cache_dir)?;
    write_bytes_atomic(
        cache_dir,
        &staged_cache_state_path(cache_dir, args),
        &state.encode(),
    )
}

fn write_cache_image_atomic(
    cache_dir: &Path,
    args: &MachOArgs,
    output: &[u8],
) -> std::io::Result<()> {
    fs::create_dir_all(cache_dir)?;
    write_bytes_atomic(cache_dir, &cache_image_path(cache_dir, args), output)
}

fn write_staged_image_atomic(
    cache_dir: &Path,
    args: &MachOArgs,
    output: &[u8],
) -> std::io::Result<()> {
    fs::create_dir_all(cache_dir)?;
    write_bytes_atomic(cache_dir, &staged_cache_image_path(cache_dir, args), output)
}

fn write_bytes_atomic(cache_dir: &Path, target: &Path, bytes: &[u8]) -> std::io::Result<()> {
    let unique = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    let temporary = cache_dir.join(format!(
        ".{}.{}.{}.tmp",
        target.file_name().and_then(|name| name.to_str()).unwrap_or("cache"),
        std::process::id(),
        unique
    ));
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&temporary)?;
    file.write_all(bytes)?;
    // A sidecar is always verified before use, so it deliberately does not impose a durable
    // media flush on the foreground link path.
    drop(file);
    fs::rename(temporary, target)
}

impl Manifest {
    fn encode(&self) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(MAGIC);
        put_u32(&mut out, VERSION);
        out.extend_from_slice(&self.arguments_digest);
        put_bytes(&mut out, self.baseline_output_path.as_bytes());
        out.extend_from_slice(&self.output_identity.normalized_digest);
        out.extend_from_slice(&self.output_identity.signature_hashes_digest);
        put_u64(&mut out, self.output_len);
        put_u64(&mut out, self.signature.code_limit);
        put_u64(&mut out, self.signature.hashes_offset);
        put_u32(&mut out, self.signature.hash_count);
        put_u64(&mut out, self.signature.uuid_offset);
        put_u64(&mut out, self.signature.identifier_offset);
        put_u64(&mut out, self.signature.identifier_capacity);
        put_u32(&mut out, self.inputs.len() as u32);
        for input in &self.inputs {
            put_bytes(&mut out, input.path.as_bytes());
            out.extend_from_slice(&input.digest);
            put_input_metadata(&mut out, &input.metadata);
        }
        put_u32(
            &mut out,
            self.cache_approved_rustc_temporary_archives.len() as u32,
        );
        for index in &self.cache_approved_rustc_temporary_archives {
            put_u32(&mut out, *index);
        }
        put_u32(
            &mut out,
            self.cache_approved_moved_direct_objects.len() as u32,
        );
        for index in &self.cache_approved_moved_direct_objects {
            put_u32(&mut out, *index);
        }
        put_u32(&mut out, self.objects.len() as u32);
        for object in &self.objects {
            put_u32(&mut out, object.input_index);
            out.extend_from_slice(&object.structure_digest);
            put_u32(&mut out, object.patches.len() as u32);
            for patch in &object.patches {
                put_u64(&mut out, patch.input_offset);
                put_u64(&mut out, patch.output_offset);
                put_u64(&mut out, patch.len);
            }
            put_u32(&mut out, object.structure_masks.len() as u32);
            for mask in &object.structure_masks {
                put_u64(&mut out, mask.input_offset);
                put_u64(&mut out, mask.len);
            }
            put_u32(&mut out, object.symbol_values.len() as u32);
            for symbol in &object.symbol_values {
                put_u64(&mut out, symbol.input_value_offset);
                put_u64(&mut out, symbol.input_section_address);
                put_u64(&mut out, symbol.input_section_size);
                put_u64(&mut out, symbol.output_value_offset);
                put_u64(&mut out, symbol.output_section_address);
                put_u64(&mut out, symbol.baseline_value);
            }
            put_u32(&mut out, object.protected.len() as u32);
            for protected in &object.protected {
                put_u64(&mut out, protected.input_offset);
                put_bytes(&mut out, &protected.bytes);
            }
            match &object.rustc_private {
                Some(private) => {
                    put_u32(&mut out, 1);
                    out.extend_from_slice(&private.metadata_digest);
                    put_u32(&mut out, private.symbols.len() as u32);
                    for symbol in &private.symbols {
                        put_u32(&mut out, symbol.input_symbol_index);
                        put_u64(&mut out, symbol.output_offset);
                        put_bytes(&mut out, &symbol.canonical_name);
                        put_bytes(&mut out, &symbol.expected);
                    }
                }
                None => put_u32(&mut out, 0),
            }
        }
        out.extend_from_slice(&manifest_checksum(&out));
        out
    }

    fn decode(bytes: &[u8]) -> anyhow::Result<Self> {
        let Some(checksum_offset) = bytes.len().checked_sub(HASH_SIZE) else {
            anyhow::bail!("truncated cache checksum");
        };
        let (body, checksum_bytes) = bytes.split_at(checksum_offset);
        let checksum: [u8; HASH_SIZE] = checksum_bytes
            .try_into()
            .map_err(|_| anyhow::anyhow!("invalid cache checksum length"))?;
        anyhow::ensure!(manifest_checksum(body) == checksum, "cache checksum differs");
        let mut reader = Reader {
            bytes: body,
            offset: 0,
        };
        anyhow::ensure!(reader.take(MAGIC.len())? == MAGIC, "wrong cache magic");
        anyhow::ensure!(reader.u32()? == VERSION, "unsupported cache version");
        let arguments_digest = reader.hash()?;
        let baseline_output_path = reader.string()?;
        let output_identity = OutputIdentity {
            normalized_digest: reader.hash()?,
            signature_hashes_digest: reader.hash()?,
        };
        let output_len = reader.u64()?;
        let signature = SignatureInfo {
            code_limit: reader.u64()?,
            hashes_offset: reader.u64()?,
            hash_count: reader.u32()?,
            uuid_offset: reader.u64()?,
            identifier_offset: reader.u64()?,
            identifier_capacity: reader.u64()?,
        };
        let input_count = reader.count()?;
        let mut inputs = Vec::with_capacity(input_count);
        for _ in 0..input_count {
            inputs.push(InputDigest {
                path: reader.string()?,
                digest: reader.hash()?,
                direct_object_bytes: None,
                metadata: read_input_metadata(&mut reader)?,
            });
        }
        let cache_approved_rustc_temporary_archives =
            read_cache_approved_rustc_temporary_archives(&mut reader, input_count)?;
        let cache_approved_moved_direct_objects =
            read_cache_approved_rustc_temporary_archives(&mut reader, input_count)?;
        let object_count = reader.count()?;
        let mut objects = Vec::with_capacity(object_count);
        for _ in 0..object_count {
            let input_index = reader.u32()?;
            let structure_digest = reader.hash()?;
            let patch_count = reader.count()?;
            let mut patches = Vec::with_capacity(patch_count);
            for _ in 0..patch_count {
                patches.push(PatchRange {
                    input_offset: reader.u64()?,
                    output_offset: reader.u64()?,
                    len: reader.u64()?,
                });
            }
            let structure_mask_count = reader.count()?;
            let mut structure_masks = Vec::with_capacity(structure_mask_count);
            for _ in 0..structure_mask_count {
                structure_masks.push(InputRange {
                    input_offset: reader.u64()?,
                    len: reader.u64()?,
                });
            }
            let symbol_value_count = reader.count()?;
            let mut symbol_values = Vec::with_capacity(symbol_value_count);
            for _ in 0..symbol_value_count {
                symbol_values.push(SymbolValuePatch {
                    input_value_offset: reader.u64()?,
                    input_section_address: reader.u64()?,
                    input_section_size: reader.u64()?,
                    output_value_offset: reader.u64()?,
                    output_section_address: reader.u64()?,
                    baseline_value: reader.u64()?,
                });
            }
            let protected_count = reader.count()?;
            let mut protected = Vec::with_capacity(protected_count);
            for _ in 0..protected_count {
                protected.push(ProtectedRange {
                    input_offset: reader.u64()?,
                    bytes: reader.bytes()?,
                });
            }
            let rustc_private = match reader.u32()? {
                0 => None,
                1 => {
                    let metadata_digest = reader.hash()?;
                    let symbol_count = reader.count()?;
                    let mut symbols = Vec::with_capacity(symbol_count);
                    let mut previous_index = None;
                    for _ in 0..symbol_count {
                        let input_symbol_index = reader.u32()?;
                        anyhow::ensure!(
                            previous_index.is_none_or(|previous| previous < input_symbol_index),
                            "Rustc private-symbol indices are not strictly ordered"
                        );
                        previous_index = Some(input_symbol_index);
                        let output_offset = reader.u64()?;
                        let canonical_name = reader.bytes()?;
                        let expected = reader.bytes()?;
                        anyhow::ensure!(
                            !canonical_name.is_empty() && !expected.is_empty(),
                            "Rustc private-symbol record is empty"
                        );
                        symbols.push(RustcPrivateSymbolPatch {
                            input_symbol_index,
                            canonical_name,
                            expected,
                            output_offset,
                        });
                    }
                    Some(RustcPrivateObject {
                        metadata_digest,
                        symbols,
                    })
                }
                _ => anyhow::bail!("invalid Rustc private-metadata flag"),
            };
            anyhow::ensure!(normalise_ranges(&mut patches).is_some(), "invalid cache patch ranges");
            anyhow::ensure!(normalise_input_ranges(&mut structure_masks).is_some(), "invalid cache structure masks");
            anyhow::ensure!(symbol_value_patches_are_normalized(&symbol_values), "invalid cache symbol value patches");
            anyhow::ensure!(normalise_protected_ranges(&mut protected).is_some(), "invalid protected ranges");
            objects.push(ObjectRecord {
                input_index,
                structure_digest,
                patches,
                structure_masks,
                symbol_values,
                protected,
                rustc_private,
            });
        }
        anyhow::ensure!(reader.offset == body.len(), "trailing cache data");
        Ok(Self {
            arguments_digest,
            baseline_output_path,
            output_identity,
            output_len,
            signature,
            inputs,
            cache_approved_rustc_temporary_archives,
            cache_approved_moved_direct_objects,
            objects,
        })
    }
}

impl<'a> ManifestView<'a> {
    fn decode(bytes: &'a [u8]) -> anyhow::Result<Self> {
        let Some(checksum_offset) = bytes.len().checked_sub(HASH_SIZE) else {
            anyhow::bail!("truncated cache checksum");
        };
        let (body, checksum_bytes) = bytes.split_at(checksum_offset);
        let checksum: [u8; HASH_SIZE] = checksum_bytes
            .try_into()
            .map_err(|_| anyhow::anyhow!("invalid cache checksum length"))?;
        anyhow::ensure!(manifest_checksum(body) == checksum, "cache checksum differs");
        let mut reader = Reader { bytes: body, offset: 0 };
        anyhow::ensure!(reader.take(MAGIC.len())? == MAGIC, "wrong cache magic");
        anyhow::ensure!(reader.u32()? == VERSION, "unsupported cache version");
        let arguments_digest = reader.hash()?;
        // Baseline output provenance and its content identity are needed when publishing a normal
        // link, but the hit path owns and validates the current image through `ImageState`.
        reader.skip_bytes()?;
        let _ = reader.hash()?;
        let _ = reader.hash()?;
        let _ = reader.u64()?;
        let signature = SignatureInfo {
            code_limit: reader.u64()?,
            hashes_offset: reader.u64()?,
            hash_count: reader.u32()?,
            uuid_offset: reader.u64()?,
            identifier_offset: reader.u64()?,
            identifier_capacity: reader.u64()?,
        };
        let input_count = reader.count()?;
        for _ in 0..input_count {
            reader.skip_bytes()?;
            let _ = reader.hash()?;
            reader.skip_input_metadata()?;
        }
        let cache_approved_rustc_temporary_archives =
            read_cache_approved_rustc_temporary_archives(&mut reader, input_count)?;
        let cache_approved_moved_direct_objects =
            read_cache_approved_rustc_temporary_archives(&mut reader, input_count)?;
        let object_count = reader.count()?;
        let object_records_start = reader.offset;
        // The checksum above covers every record. On a hit, only the selected objects from
        // `ImageState::inputs` can affect the patch, so decode and validate their records on
        // demand rather than rebuilding owned records for every unrelated object.
        Ok(Self {
            arguments_digest,
            checksum,
            signature,
            input_count,
            cache_approved_rustc_temporary_archives,
            cache_approved_moved_direct_objects,
            object_records: &body[object_records_start..],
            object_count,
        })
    }

    fn object_for_input(&self, input_index: u32) -> anyhow::Result<Option<ObjectRecordView<'a>>> {
        let mut reader = Reader {
            bytes: self.object_records,
            offset: 0,
        };
        for _ in 0..self.object_count {
            let object = ObjectRecordView::decode(&mut reader)?;
            if object.input_index == input_index {
                return Ok(Some(object));
            }
        }
        anyhow::ensure!(reader.offset == self.object_records.len(), "truncated object record list");
        Ok(None)
    }

    /// Decodes every selected record in one linear scan. The usual one-object hit keeps the
    /// historical early-exit lookup above; composing several objects must also reject duplicate
    /// input records and requires the records in input order for deterministic patching.
    fn objects_for_inputs(
        &self,
        input_indices: &[u32],
    ) -> anyhow::Result<Vec<ObjectRecordView<'a>>> {
        anyhow::ensure!(
            !input_indices.is_empty() && input_indices.windows(2).all(|pair| pair[0] < pair[1]),
            "changed input indices are not strictly ordered"
        );
        let mut reader = Reader {
            bytes: self.object_records,
            offset: 0,
        };
        let mut objects = Vec::with_capacity(input_indices.len());
        for _ in 0..self.object_count {
            let object = ObjectRecordView::decode(&mut reader)?;
            if input_indices.binary_search(&object.input_index).is_ok() {
                anyhow::ensure!(
                    !objects.iter().any(|previous: &ObjectRecordView<'_>| {
                        previous.input_index == object.input_index
                    }),
                    "cache contains duplicate direct-object records"
                );
                objects.push(object);
            }
        }
        anyhow::ensure!(reader.offset == self.object_records.len(), "truncated object record list");
        objects.sort_unstable_by_key(|object| object.input_index);
        anyhow::ensure!(
            objects.len() == input_indices.len()
                && objects
                    .iter()
                    .map(|object| object.input_index)
                    .eq(input_indices.iter().copied()),
            "changed object has no cached positional record"
        );
        Ok(objects)
    }
}

fn read_cache_approved_rustc_temporary_archives(
    reader: &mut Reader<'_>,
    input_count: usize,
) -> anyhow::Result<Vec<u32>> {
    let count = reader.count()?;
    let mut indices = Vec::with_capacity(count);
    let mut previous = None;
    for _ in 0..count {
        let index = reader.u32()?;
        anyhow::ensure!(usize::try_from(index).is_ok_and(|index| index < input_count), "cache-approved input index is out of bounds");
        anyhow::ensure!(previous.is_none_or(|previous| previous < index), "cache-approved input indices are not strictly ordered");
        indices.push(index);
        previous = Some(index);
    }
    Ok(indices)
}

impl<'a> ObjectRecordView<'a> {
    fn decode(reader: &mut Reader<'a>) -> anyhow::Result<Self> {
        let input_index = reader.u32()?;
        let structure_digest = reader.hash()?;
        let patch_count = reader.count()?;
        let patch_bytes_len = patch_count
            .checked_mul(3 * size_of::<u64>())
            .ok_or_else(|| anyhow::anyhow!("cache patch length overflow"))?;
        let patch_bytes = reader.take(patch_bytes_len)?;
        let structure_mask_count = reader.count()?;
        let structure_mask_bytes_len = structure_mask_count
            .checked_mul(2 * size_of::<u64>())
            .ok_or_else(|| anyhow::anyhow!("cache structure-mask length overflow"))?;
        let structure_mask_bytes = reader.take(structure_mask_bytes_len)?;
        let symbol_value_count = reader.count()?;
        let symbol_value_bytes_len = symbol_value_count
            .checked_mul(6 * size_of::<u64>())
            .ok_or_else(|| anyhow::anyhow!("cache symbol-value length overflow"))?;
        let symbol_value_bytes = reader.take(symbol_value_bytes_len)?;
        let protected_count = reader.count()?;
        let protected_start = reader.offset;
        let mut previous_protected_end = 0_u64;
        for _ in 0..protected_count {
            let input_offset = reader.u64()?;
            let bytes = reader.bytes_ref()?;
            let end = input_offset
                .checked_add(bytes.len() as u64)
                .ok_or_else(|| anyhow::anyhow!("protected range overflow"))?;
            anyhow::ensure!(
                input_offset >= previous_protected_end,
                "invalid protected ranges"
            );
            previous_protected_end = end;
        }
        let protected_bytes = &reader.bytes[protected_start..reader.offset];
        let rustc_private = match reader.u32()? {
            0 => None,
            1 => Some(RustcPrivateObjectView::decode(reader)?),
            _ => anyhow::bail!("invalid Rustc private-metadata flag"),
        };
        let object = Self {
            input_index,
            structure_digest,
            patch_bytes,
            structure_mask_bytes,
            symbol_value_bytes,
            protected_bytes,
            protected_count,
            rustc_private,
        };
        anyhow::ensure!(object.patches_are_normalized(), "invalid cache patch ranges");
        anyhow::ensure!(object.structure_masks_are_normalized(), "invalid cache structure masks");
        anyhow::ensure!(object.symbol_value_patches_are_normalized(), "invalid cache symbol value patches");
        Ok(object)
    }

    fn patches(&self) -> PatchRangeIter<'a> {
        PatchRangeIter {
            bytes: self.patch_bytes.chunks_exact(3 * size_of::<u64>()),
        }
    }

    fn protected(&self) -> ProtectedRangeIter<'a> {
        ProtectedRangeIter {
            bytes: self.protected_bytes,
            offset: 0,
            remaining: self.protected_count,
        }
    }

    fn structure_masks(&self) -> InputRangeIter<'a> {
        InputRangeIter {
            bytes: self.structure_mask_bytes.chunks_exact(2 * size_of::<u64>()),
        }
    }

    fn symbol_values(&self) -> SymbolValuePatchIter<'a> {
        SymbolValuePatchIter {
            bytes: self.symbol_value_bytes.chunks_exact(6 * size_of::<u64>()),
        }
    }

    fn rustc_private_output_patches(&self, bytes: &[u8]) -> Option<Vec<OutputPathPatch>> {
        let private = self.rustc_private?;
        let patch_ranges = self
            .patches()
            .map(|patch| PatchRange {
                input_offset: patch.input_offset,
                output_offset: patch.output_offset,
                len: patch.len,
            })
            .collect::<Vec<_>>();
        let metadata = rustc_private_metadata(bytes, &patch_ranges)?;
        (metadata.digest == private.metadata_digest)
            .then(|| private.output_patches(&metadata.symbols))?
    }

    fn patches_are_normalized(&self) -> bool {
        let mut previous_input_end = 0_u64;
        for patch in self.patches() {
            let Some(input_end) = patch.input_offset.checked_add(patch.len) else {
                return false;
            };
            if patch.output_offset.checked_add(patch.len).is_none() {
                return false;
            }
            // Input ranges are serialized in increasing order. Output ranges are separately
            // non-overlapping, but string merging can legitimately make their order differ; the
            // normal-link publisher verifies that invariant before checksumming this manifest.
            if patch.len == 0 || patch.input_offset < previous_input_end {
                return false;
            }
            previous_input_end = input_end;
        }
        true
    }

    fn structure_masks_are_normalized(&self) -> bool {
        input_ranges_are_normalized(self.structure_masks())
    }

    fn symbol_value_patches_are_normalized(&self) -> bool {
        symbol_value_patches_are_normalized_from_iter(self.symbol_values())
    }
}

impl<'a> RustcPrivateObjectView<'a> {
    fn decode(reader: &mut Reader<'a>) -> anyhow::Result<Self> {
        let metadata_digest = reader.hash()?;
        let symbol_count = reader.count()?;
        let symbol_start = reader.offset;
        let mut previous_index = None;
        for _ in 0..symbol_count {
            let input_symbol_index = reader.u32()?;
            anyhow::ensure!(
                previous_index.is_none_or(|previous| previous < input_symbol_index),
                "Rustc private-symbol indices are not strictly ordered"
            );
            previous_index = Some(input_symbol_index);
            let _ = reader.u64()?;
            let canonical_name = reader.bytes_ref()?;
            let expected = reader.bytes_ref()?;
            anyhow::ensure!(
                !canonical_name.is_empty() && !expected.is_empty(),
                "Rustc private-symbol record is empty"
            );
        }
        Ok(Self {
            metadata_digest,
            symbol_bytes: &reader.bytes[symbol_start..reader.offset],
            symbol_count,
        })
    }

    fn output_patches(self, symbols: &[InputSymbol]) -> Option<Vec<OutputPathPatch>> {
        let mut reader = Reader {
            bytes: self.symbol_bytes,
            offset: 0,
        };
        let mut patches = Vec::with_capacity(self.symbol_count);
        for _ in 0..self.symbol_count {
            let input_symbol_index = usize::try_from(reader.u32().ok()?).ok()?;
            let output_offset = reader.u64().ok()?;
            let canonical_name = reader.bytes_ref().ok()?;
            let expected = reader.bytes_ref().ok()?;
            let current = symbols.get(input_symbol_index)?;
            if rustc_private_symbol_base(&current.name) != Some(canonical_name)
                || current.name.len() > expected.len()
            {
                return None;
            }
            let mut replacement = current.name.clone();
            replacement.resize(expected.len(), 0);
            patches.push(OutputPathPatch {
                output_offset,
                expected: expected.to_vec(),
                replacement,
            });
        }
        (reader.offset == reader.bytes.len()).then_some(patches)
    }
}

impl<'a> Iterator for PatchRangeIter<'a> {
    type Item = PatchRange;

    fn next(&mut self) -> Option<Self::Item> {
        let bytes = self.bytes.next()?;
        Some(PatchRange {
            input_offset: u64::from_le_bytes(bytes[0..8].try_into().unwrap()),
            output_offset: u64::from_le_bytes(bytes[8..16].try_into().unwrap()),
            len: u64::from_le_bytes(bytes[16..24].try_into().unwrap()),
        })
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        self.bytes.size_hint()
    }
}

impl ExactSizeIterator for PatchRangeIter<'_> {
}

impl<'a> Iterator for InputRangeIter<'a> {
    type Item = InputRange;

    fn next(&mut self) -> Option<Self::Item> {
        let bytes = self.bytes.next()?;
        Some(InputRange {
            input_offset: u64::from_le_bytes(bytes[0..8].try_into().unwrap()),
            len: u64::from_le_bytes(bytes[8..16].try_into().unwrap()),
        })
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        self.bytes.size_hint()
    }
}

impl ExactSizeIterator for InputRangeIter<'_> {
}

#[derive(Clone)]
struct SymbolValuePatchIter<'a> {
    bytes: std::slice::ChunksExact<'a, u8>,
}

impl<'a> Iterator for SymbolValuePatchIter<'a> {
    type Item = SymbolValuePatch;

    fn next(&mut self) -> Option<Self::Item> {
        let bytes = self.bytes.next()?;
        Some(SymbolValuePatch {
            input_value_offset: u64::from_le_bytes(bytes[0..8].try_into().unwrap()),
            input_section_address: u64::from_le_bytes(bytes[8..16].try_into().unwrap()),
            input_section_size: u64::from_le_bytes(bytes[16..24].try_into().unwrap()),
            output_value_offset: u64::from_le_bytes(bytes[24..32].try_into().unwrap()),
            output_section_address: u64::from_le_bytes(bytes[32..40].try_into().unwrap()),
            baseline_value: u64::from_le_bytes(bytes[40..48].try_into().unwrap()),
        })
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        self.bytes.size_hint()
    }
}

impl ExactSizeIterator for SymbolValuePatchIter<'_> {
}

impl<'a> Iterator for ProtectedRangeIter<'a> {
    type Item = ProtectedRangeRef<'a>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.remaining == 0 {
            return None;
        }
        let offset_end = self.offset.checked_add(8)?;
        let input_offset = u64::from_le_bytes(self.bytes.get(self.offset..offset_end)?.try_into().ok()?);
        let len_start = offset_end;
        let len_end = len_start.checked_add(4)?;
        let len = u32::from_le_bytes(self.bytes.get(len_start..len_end)?.try_into().ok()?) as usize;
        let bytes_end = len_end.checked_add(len)?;
        let bytes = self.bytes.get(len_end..bytes_end)?;
        self.offset = bytes_end;
        self.remaining -= 1;
        Some(ProtectedRangeRef { input_offset, bytes })
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        (self.remaining, Some(self.remaining))
    }
}

impl ExactSizeIterator for ProtectedRangeIter<'_> {
}

impl ImageState {
    fn encode(&self) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(STATE_MAGIC);
        put_u32(&mut out, STATE_VERSION);
        out.extend_from_slice(&self.arguments_digest);
        out.extend_from_slice(&self.manifest_checksum);
        out.extend_from_slice(&self.cache_image_token);
        out.extend_from_slice(&self.uuid_seed);
        put_u64(&mut out, self.output_len);
        put_u32(&mut out, self.inputs.len() as u32);
        for input in &self.inputs {
            put_bytes(&mut out, input.path.as_bytes());
            out.extend_from_slice(&input.digest);
            put_input_metadata(&mut out, &input.metadata);
        }
        out.extend_from_slice(&state_checksum(&out));
        out
    }

    fn decode(bytes: &[u8]) -> anyhow::Result<Self> {
        let Some(checksum_offset) = bytes.len().checked_sub(HASH_SIZE) else {
            anyhow::bail!("truncated image-state checksum");
        };
        let (body, checksum) = bytes.split_at(checksum_offset);
        anyhow::ensure!(state_checksum(body).as_slice() == checksum, "image-state checksum differs");
        let mut reader = Reader {
            bytes: body,
            offset: 0,
        };
        anyhow::ensure!(reader.take(STATE_MAGIC.len())? == STATE_MAGIC, "wrong image-state magic");
        anyhow::ensure!(reader.u32()? == STATE_VERSION, "unsupported image-state version");
        let arguments_digest = reader.hash()?;
        let manifest_checksum = reader.hash()?;
        let cache_image_token = reader.take(16)?.try_into().expect("fixed-width image token");
        let uuid_seed = reader.hash()?;
        let output_len = reader.u64()?;
        let input_count = reader.count()?;
        let mut inputs = Vec::with_capacity(input_count);
        for _ in 0..input_count {
            inputs.push(InputDigest {
                path: reader.string()?,
                digest: reader.hash()?,
                direct_object_bytes: None,
                metadata: read_input_metadata(&mut reader)?,
            });
        }
        anyhow::ensure!(reader.offset == body.len(), "trailing image-state data");
        Ok(Self {
            arguments_digest,
            manifest_checksum,
            cache_image_token,
            uuid_seed,
            output_len,
            inputs,
        })
    }
}

fn manifest_checksum(body: &[u8]) -> [u8; HASH_SIZE] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(MANIFEST_CHECKSUM_DOMAIN);
    hasher.update(body);
    *hasher.finalize().as_bytes()
}

fn state_checksum(body: &[u8]) -> [u8; HASH_SIZE] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(STATE_CHECKSUM_DOMAIN);
    hasher.update(body);
    *hasher.finalize().as_bytes()
}

struct Reader<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl<'a> Reader<'a> {
    fn take(&mut self, len: usize) -> anyhow::Result<&'a [u8]> {
        let end = self
            .offset
            .checked_add(len)
            .ok_or_else(|| anyhow::anyhow!("cache length overflow"))?;
        let value = self
            .bytes
            .get(self.offset..end)
            .ok_or_else(|| anyhow::anyhow!("truncated cache"))?;
        self.offset = end;
        Ok(value)
    }

    fn u32(&mut self) -> anyhow::Result<u32> {
        Ok(u32::from_le_bytes(self.take(4)?.try_into().unwrap()))
    }

    fn u64(&mut self) -> anyhow::Result<u64> {
        Ok(u64::from_le_bytes(self.take(8)?.try_into().unwrap()))
    }

    fn hash(&mut self) -> anyhow::Result<[u8; HASH_SIZE]> {
        Ok(self.take(HASH_SIZE)?.try_into().unwrap())
    }

    fn count(&mut self) -> anyhow::Result<usize> {
        let count = self.u32()? as usize;
        anyhow::ensure!(count <= MAX_RECORDS, "cache record count is too large");
        Ok(count)
    }

    fn bytes(&mut self) -> anyhow::Result<Vec<u8>> {
        let len = self.count()?;
        Ok(self.take(len)?.to_vec())
    }

    fn bytes_ref(&mut self) -> anyhow::Result<&'a [u8]> {
        let len = self.count()?;
        self.take(len)
    }

    fn skip_bytes(&mut self) -> anyhow::Result<()> {
        let len = self.count()?;
        let _ = self.take(len)?;
        Ok(())
    }

    fn skip_input_metadata(&mut self) -> anyhow::Result<()> {
        // The fixed-width encoding is kept alongside `put_input_metadata` below. Skipping it on
        // a hit avoids materialising immutable-manifest metadata that the image state already
        // owns and compares.
        let _ = self.take(6 * size_of::<u64>() + size_of::<u32>())?;
        Ok(())
    }

    fn string(&mut self) -> anyhow::Result<String> {
        String::from_utf8(self.bytes()?).map_err(|_| anyhow::anyhow!("cache path is not UTF-8"))
    }
}

fn put_u32(out: &mut Vec<u8>, value: u32) {
    out.extend_from_slice(&value.to_le_bytes());
}

fn put_u64(out: &mut Vec<u8>, value: u64) {
    out.extend_from_slice(&value.to_le_bytes());
}

fn put_input_metadata(out: &mut Vec<u8>, metadata: &InputFileMetadata) {
    put_u64(out, metadata.len);
    put_u64(out, metadata.modified_seconds);
    put_u32(out, metadata.modified_nanoseconds);
    put_u64(out, metadata.device);
    put_u64(out, metadata.inode);
    put_u64(out, metadata.changed_seconds as u64);
    put_u64(out, metadata.changed_nanoseconds as u64);
}

fn read_input_metadata(reader: &mut Reader<'_>) -> anyhow::Result<InputFileMetadata> {
    Ok(InputFileMetadata {
        len: reader.u64()?,
        modified_seconds: reader.u64()?,
        modified_nanoseconds: reader.u32()?,
        device: reader.u64()?,
        inode: reader.u64()?,
        changed_seconds: reader.u64()? as i64,
        changed_nanoseconds: reader.u64()? as i64,
    })
}

fn put_bytes(out: &mut Vec<u8>, bytes: &[u8]) {
    put_u32(out, bytes.len() as u32);
    out.extend_from_slice(bytes);
}

#[cfg(test)]
mod tests {
    use super::Manifest;
    use super::ManifestView;
    use super::Candidate;
    use super::HASH_SIZE;
    use super::MAGIC;
    use super::STATE_MAGIC;
    use super::DirectObjectSnapshot;
    use super::ExistingOutputBaseline;
    use super::InputDigest;
    use super::InputFileMetadata;
    use super::InputRange;
    use super::ImageState;
    use super::ObjectRecord;
    use super::OutputIdentity;
    use super::PatchRange;
    use super::ProtectedRange;
    use super::SignatureInfo;
    use super::SymbolValuePatch;
    use super::add_patch_ranges_excluding_protected;
    use super::apply_patches;
    use super::apply_symbol_value_patches;
    use super::cache_is_eligible;
    use super::cache_approved_rustc_temporary_archives;
    use super::cache_hit_input_path;
    use super::read_existing_output_baseline;
    use super::resident_state_after_hit;
    #[cfg(target_os = "macos")]
    use super::clone_file;
    #[cfg(target_os = "macos")]
    use super::replace_output_after_detaching_previous;
    use super::input_digests;
    use super::input_digests_for_cache_hit;
    use super::input_identity_changed;
    use super::input_metadata_snapshots_match;
    use super::masked_digest;
    use super::masked_digest_for_input_ranges;
    use super::macho_symtab;
    use super::protected_ranges_match;
    use super::refresh_changed_code_signature_hashes;
    use super::rustc_private_metadata;
    use super::rustc_private_symbol_base;
    use super::n_oso_archive_path_patches;
    use super::normalized_output_digest;
    use super::output_identity;
    use super::output_matches_identity;
    use super::stable_output_basename;
    use super::uuid_from_normalized_digest;
    use super::arguments_digest;
    use crate::args::Input;
    use crate::args::InputSpec;
    use crate::args::Modifiers;
    use crate::args::macho::MachOArgs;
    use crate::macho;
    use std::sync::Arc;
    use std::time::SystemTime;
    use std::mem::size_of;

    #[test]
    fn manifest_round_trip_is_versioned_and_rejects_trailing_bytes() {
        let manifest = Manifest {
            arguments_digest: [1; 32],
            baseline_output_path: "/tmp/e-old-hash".to_owned(),
            output_identity: OutputIdentity {
                normalized_digest: [2; 32],
                signature_hashes_digest: [3; 32],
            },
            output_len: 123,
            signature: SignatureInfo {
                code_limit: 64,
                hashes_offset: 80,
                hash_count: 2,
                uuid_offset: 40,
                identifier_offset: 72,
                identifier_capacity: 8,
            },
            inputs: vec![InputDigest {
                path: "/tmp/main.o".to_owned(),
                digest: [8; 32],
                direct_object_bytes: None,
                metadata: test_input_metadata(),
            }],
            cache_approved_rustc_temporary_archives: vec![0],
            cache_approved_moved_direct_objects: vec![0],
            objects: vec![ObjectRecord {
                input_index: 0,
                structure_digest: [3; 32],
                patches: vec![PatchRange {
                    input_offset: 4,
                    output_offset: 8,
                    len: 2,
                }],
                structure_masks: vec![InputRange {
                    input_offset: 4,
                    len: 2,
                }],
                symbol_values: vec![SymbolValuePatch {
                    input_value_offset: 16,
                    input_section_address: 0,
                    input_section_size: 32,
                    output_value_offset: 48,
                    output_section_address: 0x1_0000_0000,
                    baseline_value: 0x1_0000_0004,
                }],
                protected: vec![ProtectedRange {
                    input_offset: 4,
                    bytes: vec![9, 10],
                }],
                rustc_private: None,
            }],
        };
        let encoded = manifest.encode();
        assert_eq!(Manifest::decode(&encoded).unwrap(), manifest);
        let view = ManifestView::decode(&encoded).unwrap();
        assert_eq!(view.arguments_digest, manifest.arguments_digest);
        assert_eq!(
            view.checksum,
            <[u8; HASH_SIZE]>::try_from(&encoded[encoded.len() - HASH_SIZE..]).unwrap(),
        );
        assert_eq!(view.input_count, manifest.inputs.len());
        assert_eq!(
            view.cache_approved_rustc_temporary_archives,
            manifest.cache_approved_rustc_temporary_archives
        );
        assert_eq!(
            view.cache_approved_moved_direct_objects,
            manifest.cache_approved_moved_direct_objects
        );
        let object = view.object_for_input(0).unwrap().unwrap();
        assert_eq!(object.structure_digest, [3; 32]);
        assert_eq!(object.patches().collect::<Vec<_>>(), manifest.objects[0].patches);
        assert_eq!(
            object.structure_masks().collect::<Vec<_>>(),
            manifest.objects[0].structure_masks
        );
        assert_eq!(
            object.symbol_values().collect::<Vec<_>>(),
            manifest.objects[0].symbol_values
        );
        assert!(super::protected_ranges_match_from_iter(
            &[0, 0, 0, 0, 9, 10],
            object.protected()
        ));
        assert!(view.object_for_input(1).unwrap().is_none());
        let mut reordered_output = manifest.clone();
        reordered_output.objects[0].patches = vec![
            PatchRange {
                input_offset: 4,
                output_offset: 8,
                len: 2,
            },
            PatchRange {
                input_offset: 8,
                output_offset: 2,
                len: 2,
            },
        ];
        let reordered_bytes = reordered_output.encode();
        let reordered_view = ManifestView::decode(&reordered_bytes).unwrap();
        assert_eq!(
            reordered_view
                .object_for_input(0)
                .unwrap()
                .unwrap()
                .patches()
                .collect::<Vec<_>>(),
            reordered_output.objects[0].patches
        );
        let state = ImageState {
            arguments_digest: manifest.arguments_digest,
            manifest_checksum: view.checksum,
            cache_image_token: [4; 16],
            uuid_seed: manifest.output_identity.normalized_digest,
            output_len: manifest.output_len,
            inputs: manifest.inputs.clone(),
        };
        let state_encoded = state.encode();
        assert_eq!(ImageState::decode(&state_encoded).unwrap(), state);
        let mut corrupt_state = state_encoded;
        corrupt_state[STATE_MAGIC.len() + size_of::<u32>()] ^= 1;
        assert!(ImageState::decode(&corrupt_state).is_err());
        let mut trailing = encoded;
        trailing.push(0);
        assert!(Manifest::decode(&trailing).is_err());
        let mut corrupt = manifest.encode();
        corrupt[MAGIC.len() + size_of::<u32>()] ^= 1;
        assert!(Manifest::decode(&corrupt).is_err());
    }

    #[test]
    fn unrecordable_direct_object_does_not_suppress_a_cacheable_object_record() {
        let records = super::cacheable_records_from_candidates([
            (
                3,
                Some(Candidate {
                    bytes: vec![1, 2, 3, 4],
                    patches: vec![PatchRange {
                        input_offset: 1,
                        output_offset: 9,
                        len: 2,
                    }],
                    structure_masks: Vec::new(),
                    symbol_values: Vec::new(),
                    protected: Vec::new(),
                    rustc_private_symbols: None,
                }),
            ),
            (7, None),
        ]);

        assert_eq!(records.len(), 1);
        assert_eq!(records[0].input_index, 3);
        assert_eq!(records[0].patches.len(), 1);
        assert_eq!(records[0].structure_masks, vec![InputRange { input_offset: 1, len: 2 }]);
    }

    #[test]
    fn cache_approved_moved_direct_object_with_equal_bytes_is_unchanged() {
        let cached = InputDigest {
            path: "/tmp/old-codegen.o".to_owned(),
            digest: [7; HASH_SIZE],
            direct_object_bytes: None,
            metadata: test_input_metadata(),
        };
        let current = InputDigest {
            path: "/tmp/new-codegen.o".to_owned(),
            digest: cached.digest,
            direct_object_bytes: None,
            metadata: InputFileMetadata {
                inode: cached.metadata.inode + 1,
                ..cached.metadata
            },
        };

        assert!(!input_identity_changed(&current, &cached, false, true));
        assert!(input_identity_changed(&current, &cached, false, false));
    }

    #[test]
    fn rustc_output_hash_is_the_only_normalized_basename_suffix() {
        assert_eq!(stable_output_basename(b"e-4903cf8e124ea782"), b"e");
        assert_eq!(stable_output_basename(b"my-tool"), b"my-tool");
        assert_eq!(stable_output_basename(b"tool-2026"), b"tool-2026");
    }

    #[test]
    fn rustc_temporary_archive_paths_can_only_move_at_verified_n_oso_entries() {
        let old_path = "/tmp/rustcAb12Cd/libexample.rlib";
        let new_path = "/tmp/rustcEf34Gh/libexample.rlib";
        assert_eq!(old_path.len(), new_path.len());

        let mut output = macho_with_symbol_strings(&[
            (format!("{old_path}(one.o)"), object::macho::N_OSO.0),
            (format!("{old_path}(two.o)"), object::macho::N_OSO.0),
            ("_ordinary_symbol".to_owned(), object::macho::N_SECT.0),
        ]);
        let patches = n_oso_archive_path_patches(&output, old_path, new_path).unwrap();
        assert_eq!(patches.len(), 2);
        assert!(super::apply_output_path_patches(&mut output, &patches));
        assert!(!output.windows(old_path.len()).any(|bytes| bytes == old_path.as_bytes()));
        assert_eq!(
            output.windows(new_path.len()).filter(|bytes| *bytes == new_path.as_bytes()).count(),
            2
        );

        let non_debug_map_occurrence = macho_with_symbol_strings(&[
            (format!("{old_path}(one.o)"), object::macho::N_OSO.0),
            (old_path.to_owned(), object::macho::N_SO.0),
        ]);
        assert!(n_oso_archive_path_patches(&non_debug_map_occurrence, old_path, new_path).is_none());
        assert!(n_oso_archive_path_patches(&output, new_path, "/tmp/rustcTooLong/libexample.rlib").is_none());
    }

    #[test]
    fn rustc_private_metadata_accepts_only_terminal_llvm_discriminator_churn() {
        let old = macho_with_symbol_strings(&[(
            "_private.llvm.16817195673798115762".to_owned(),
            object::macho::N_SECT.0 | object::macho::N_PEXT.0,
        )]);
        let changed = macho_with_symbol_strings(&[(
            "_private.llvm.8538991645495547684".to_owned(),
            object::macho::N_SECT.0 | object::macho::N_PEXT.0,
        )]);
        let ordinary_change = macho_with_symbol_strings(&[(
            "_different_private.llvm.8538991645495547684".to_owned(),
            object::macho::N_SECT.0 | object::macho::N_PEXT.0,
        )]);

        let old_metadata = rustc_private_metadata(&old, &[]).unwrap();
        let changed_metadata = rustc_private_metadata(&changed, &[]).unwrap();
        let ordinary_metadata = rustc_private_metadata(&ordinary_change, &[]).unwrap();

        assert_eq!(old_metadata.digest, changed_metadata.digest);
        assert_ne!(old_metadata.digest, ordinary_metadata.digest);
        assert_eq!(
            rustc_private_symbol_base(b"_private.llvm.123"),
            Some(&b"_private.llvm."[..])
        );
        assert!(rustc_private_symbol_base(b"_private.llvm.not-a-number").is_none());
        assert!(rustc_private_symbol_base(b"llvm.123").is_none());
    }

    #[test]
    fn rustc_private_output_string_is_identified_without_a_linear_section_mapping() {
        let name = "_private.llvm.16817195673798115762";
        let mut output = macho_with_symbol_strings(&[(
            name.to_owned(),
            object::macho::N_SECT.0 | object::macho::N_PEXT.0,
        )]);
        // A string-merged input symbol has no source-to-output offset, and therefore may have a
        // different final address. The nlist spelling/type/descriptor still identifies one
        // exact string-table slot.
        output[64..72].copy_from_slice(&0x1234_5678_u64.to_le_bytes());

        let symtab = macho_symtab(&output).unwrap();
        assert_eq!(
            symtab.unique_symbol_string_offset(
                &output,
                name.as_bytes(),
                object::macho::N_SECT.0 | object::macho::N_PEXT.0,
                0,
            ),
            Some(symtab.string_offset + 1)
        );
    }

    fn macho_with_symbol_strings(symbols: &[(String, u8)]) -> Vec<u8> {
        const MACH_HEADER_64_SIZE: usize = 32;
        const SYMTAB_COMMAND_SIZE: usize = 24;
        const NLIST_64_SIZE: usize = 16;

        let symoff = MACH_HEADER_64_SIZE + SYMTAB_COMMAND_SIZE;
        let stroff = symoff + symbols.len() * NLIST_64_SIZE;
        let mut output = vec![0; stroff + 1];
        output[..4].copy_from_slice(&object::macho::MH_MAGIC_64.to_le_bytes());
        output[16..20].copy_from_slice(&1_u32.to_le_bytes());
        output[MACH_HEADER_64_SIZE..MACH_HEADER_64_SIZE + 4]
            .copy_from_slice(&object::macho::LC_SYMTAB.0.to_le_bytes());
        output[MACH_HEADER_64_SIZE + 4..MACH_HEADER_64_SIZE + 8]
            .copy_from_slice(&(SYMTAB_COMMAND_SIZE as u32).to_le_bytes());
        output[MACH_HEADER_64_SIZE + 8..MACH_HEADER_64_SIZE + 12]
            .copy_from_slice(&(symoff as u32).to_le_bytes());
        output[MACH_HEADER_64_SIZE + 12..MACH_HEADER_64_SIZE + 16]
            .copy_from_slice(&(symbols.len() as u32).to_le_bytes());
        output[MACH_HEADER_64_SIZE + 16..MACH_HEADER_64_SIZE + 20]
            .copy_from_slice(&(stroff as u32).to_le_bytes());

        for (index, (name, n_type)) in symbols.iter().enumerate() {
            let string_index = output.len() - stroff;
            let entry = symoff + index * NLIST_64_SIZE;
            output[entry..entry + 4].copy_from_slice(&(string_index as u32).to_le_bytes());
            output[entry + 4] = *n_type;
            output[entry + 5] = ((*n_type & object::macho::N_TYPE)
                == object::macho::N_SECT.0) as u8;
            output.extend_from_slice(name.as_bytes());
            output.push(0);
        }
        let string_size = output.len() - stroff;
        output[MACH_HEADER_64_SIZE + 20..MACH_HEADER_64_SIZE + SYMTAB_COMMAND_SIZE]
            .copy_from_slice(&(string_size as u32).to_le_bytes());
        output
    }

    #[test]
    fn semantic_arguments_ignore_runtime_thread_availability() {
        let mut cargo_link = MachOArgs::default();
        cargo_link.common.available_threads = std::num::NonZeroUsize::new(1).unwrap();

        let mut direct_replay = MachOArgs::default();
        direct_replay.common.available_threads = std::num::NonZeroUsize::new(12).unwrap();

        assert_eq!(arguments_digest(&cargo_link), arguments_digest(&direct_replay));

        direct_replay.entry = "_different_entry".to_owned();
        assert_ne!(arguments_digest(&cargo_link), arguments_digest(&direct_replay));
    }

    #[test]
    fn cache_rejects_an_export_list_whose_contents_are_not_input_fingerprinted() {
        let mut args = MachOArgs::default();
        assert!(cache_is_eligible(&args));

        args.export_list_path = Some("/tmp/wild-stable-layout-cache-exports".into());
        assert!(!cache_is_eligible(&args));
    }

    #[test]
    fn existing_output_baseline_retains_verified_bytes_and_rejects_mismatches() {
        let unique = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let path = std::env::temp_dir().join(format!(
            "wild-stable-layout-cache-output-{unique}-{}",
            std::process::id()
        ));
        let signature = SignatureInfo {
            code_limit: 64,
            hashes_offset: 128,
            hash_count: 1,
            uuid_offset: 32,
            identifier_offset: 96,
            identifier_capacity: 32,
        };
        let mut baseline = (0..160).map(|byte| byte as u8).collect::<Vec<_>>();
        let normalized = normalized_output_digest(&baseline, &signature).unwrap();
        baseline[32..48].copy_from_slice(&uuid_from_normalized_digest(&normalized));
        let identity = output_identity(&baseline, &signature).unwrap();
        std::fs::write(&path, &baseline).unwrap();
        let wrong_identity = OutputIdentity {
            normalized_digest: [0; HASH_SIZE],
            signature_hashes_digest: identity.signature_hashes_digest,
        };

        let matched = read_existing_output_baseline(
            &path,
            baseline.len() as u64,
            &identity,
            &signature,
        );
        assert_eq!(matched, ExistingOutputBaseline::Matched(baseline.clone()));
        // The retained, authenticated bytes remain a valid patch source even if Cargo removes
        // the old output before the cache publishes its replacement.
        std::fs::remove_file(&path).unwrap();
        assert_eq!(matched, ExistingOutputBaseline::Matched(baseline.clone()));

        std::fs::write(&path, &baseline).unwrap();
        assert_eq!(
            read_existing_output_baseline(
                &path,
                baseline.len() as u64 - 1,
                &identity,
                &signature,
            ),
            ExistingOutputBaseline::Mismatch,
        );
        assert_eq!(
            read_existing_output_baseline(&path, baseline.len() as u64, &wrong_identity, &signature),
            ExistingOutputBaseline::Mismatch,
        );

        std::fs::remove_file(&path).unwrap();
        assert_eq!(
            read_existing_output_baseline(&path, baseline.len() as u64, &identity, &signature),
            ExistingOutputBaseline::Absent,
        );

        // Cargo may retire the old output before a relink, but an existing path that cannot be
        // read is not equivalent to that allowed absence: it cannot prove this cache lineage.
        std::fs::create_dir(&path).unwrap();
        assert_eq!(
            read_existing_output_baseline(&path, baseline.len() as u64, &identity, &signature),
            ExistingOutputBaseline::Mismatch,
        );
        std::fs::remove_dir(&path).unwrap();
    }

    #[test]
    fn output_identity_binds_code_bytes_uuid_and_signature_hashes() {
        let signature = SignatureInfo {
            code_limit: 128,
            hashes_offset: 192,
            hash_count: 1,
            uuid_offset: 32,
            identifier_offset: 160,
            identifier_capacity: 32,
        };
        let mut output = (0..300).map(|byte| byte as u8).collect::<Vec<_>>();
        let normalized = normalized_output_digest(&output, &signature).unwrap();
        let mut writer_preimage = output.clone();
        writer_preimage[32..48].fill(0);
        writer_preimage[192..224].fill(0);
        assert_eq!(normalized, *blake3::hash(&writer_preimage).as_bytes());
        output[32..48].copy_from_slice(&uuid_from_normalized_digest(&normalized));
        let identity = output_identity(&output, &signature).unwrap();
        assert!(output_matches_identity(&output, &signature, &identity));

        output[80] ^= 1;
        assert!(!output_matches_identity(&output, &signature, &identity));
        output[80] ^= 1;

        output[160] ^= 1;
        assert!(!output_matches_identity(&output, &signature, &identity));
        output[160] ^= 1;

        output[32] ^= 1;
        assert!(!output_matches_identity(&output, &signature, &identity));
        output[32] ^= 1;

        output[192] ^= 1;
        assert!(!output_matches_identity(&output, &signature, &identity));
        output[192] ^= 1;

        output[250] ^= 1;
        assert!(!output_matches_identity(&output, &signature, &identity));

        let invalid_signature = SignatureInfo {
            hash_count: 2,
            ..signature
        };
        assert!(output_identity(&output, &invalid_signature).is_none());
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn clone_file_keeps_the_staged_output_independent() {
        let unique = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let directory = std::env::temp_dir().join(format!(
            "wild-stable-layout-cache-clone-{unique}-{}",
            std::process::id()
        ));
        std::fs::create_dir(&directory).unwrap();
        let source = directory.join("source");
        let destination = directory.join("destination");
        std::fs::write(&source, b"baseline").unwrap();
        clone_file(&source, &destination).unwrap();
        std::fs::write(&source, b"changed").unwrap();
        assert_eq!(std::fs::read(&destination).unwrap(), b"baseline");
        std::fs::remove_file(source).unwrap();
        std::fs::remove_file(destination).unwrap();
        std::fs::remove_dir(directory).unwrap();
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn cache_publication_detaches_a_previous_output_inode() {
        use std::os::unix::fs::MetadataExt as _;

        let unique = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let directory = std::env::temp_dir().join(format!(
            "wild-stable-layout-cache-publication-{unique}-{}",
            std::process::id()
        ));
        std::fs::create_dir(&directory).unwrap();
        let output = directory.join("output");
        let staged = directory.join("staged");
        std::fs::write(&output, b"previous executable").unwrap();
        std::fs::write(&staged, b"new executable").unwrap();
        let previous_inode = std::fs::metadata(&output).unwrap().ino();

        replace_output_after_detaching_previous(&staged, &output).unwrap();

        assert_eq!(std::fs::read(&output).unwrap(), b"new executable");
        assert_ne!(std::fs::metadata(&output).unwrap().ino(), previous_inode);
        assert!(!staged.exists());
        std::fs::remove_file(output).unwrap();
        std::fs::remove_dir(directory).unwrap();
    }

    #[test]
    fn input_identity_excludes_process_local_object_snapshot() {
        let cached = InputDigest {
            path: "/tmp/main.o".to_owned(),
            digest: [9; 32],
            direct_object_bytes: None,
            metadata: test_input_metadata(),
        };
        let current = InputDigest {
            direct_object_bytes: Some(DirectObjectSnapshot::InMemory(Arc::from([1, 2, 3]))),
            ..cached.clone()
        };
        assert_eq!(cached, current);
    }

    #[test]
    fn resident_state_hashes_changed_direct_object_bytes() {
        let state = ImageState {
            arguments_digest: [1; HASH_SIZE],
            manifest_checksum: [2; HASH_SIZE],
            cache_image_token: [3; 16],
            uuid_seed: [4; HASH_SIZE],
            output_len: 5,
            inputs: vec![InputDigest {
                path: "/tmp/main.o".to_owned(),
                digest: [6; HASH_SIZE],
                direct_object_bytes: None,
                metadata: test_input_metadata(),
            }],
        };
        let changed_bytes = Arc::<[u8]>::from([7, 8, 9]);
        let resident = resident_state_after_hit(
            &state,
            vec![InputDigest {
                path: "/tmp/main.o".to_owned(),
                digest: [6; HASH_SIZE],
                direct_object_bytes: Some(DirectObjectSnapshot::InMemory(changed_bytes.clone())),
                metadata: test_input_metadata(),
            }],
        );

        assert_eq!(resident.inputs[0].digest, *blake3::hash(&changed_bytes).as_bytes());
        assert!(resident.inputs[0].direct_object_bytes.is_none());
    }

    #[test]
    fn input_metadata_recheck_rejects_a_changed_file() {
        let unique = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let path = std::env::temp_dir().join(format!(
            "wild-stable-layout-cache-input-{unique}-{}.o",
            std::process::id()
        ));
        std::fs::write(&path, b"before").unwrap();

        let mut args = MachOArgs::default();
        args.common.inputs.push(Input {
            spec: InputSpec::File(Box::from(path.as_path())),
            search_first: None,
            modifiers: Modifiers::default(),
        });
        let inputs = input_digests(&args).unwrap();
        assert!(input_metadata_snapshots_match(&args, &inputs));
        // A canonical direct spelling skips all resolution on cache hits. The equality is
        // intentionally exact: relative/symlink spellings retain the conservative fallback.
        args.common.inputs[0].spec = InputSpec::File(Box::from(std::path::Path::new(
            &inputs[0].path,
        )));
        assert_eq!(
            cache_hit_input_path(&args, &args.common.inputs[0], &inputs[0]),
            Some(inputs[0].path.clone())
        );
        let unchanged = input_digests_for_cache_hit(&args, &inputs, &[], &[]).unwrap();
        assert_eq!(unchanged, inputs);
        assert!(unchanged[0].direct_object_bytes.is_none());

        std::fs::write(&path, b"after-with-a-different-length").unwrap();
        assert!(!input_metadata_snapshots_match(&args, &inputs));
        let changed = input_digests_for_cache_hit(&args, &inputs, &[], &[]).unwrap();
        assert_ne!(changed[0].metadata, inputs[0].metadata);
        // A direct cache candidate detects this by metadata rather than a second full digest.
        assert_eq!(changed[0].digest, inputs[0].digest);
        assert!(changed[0].direct_object_bytes.is_some());
        std::fs::remove_file(path).unwrap();
    }

    #[test]
    fn cache_approved_rustc_temporary_archives_reuse_identical_contents() {
        let unique = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let directory = std::env::temp_dir().join(format!(
            "wild-stable-layout-cache-rustc-temporary-{unique}-{}",
            std::process::id()
        ));
        let previous_directory = directory.join("rustcAb12Cd");
        let current_directory = directory.join("rustcEf34Gh");
        std::fs::create_dir_all(&previous_directory).unwrap();
        std::fs::create_dir(&current_directory).unwrap();
        let previous_archive = previous_directory.join("libexample.rlib");
        let current_archive = current_directory.join("libexample.rlib");
        std::fs::write(&previous_archive, b"the cached archive bytes").unwrap();
        std::fs::write(&current_archive, b"the cached archive bytes").unwrap();

        let mut previous_args = MachOArgs::default();
        previous_args.common.inputs.push(Input {
            spec: InputSpec::File(Box::from(previous_archive.as_path())),
            search_first: None,
            modifiers: Modifiers::default(),
        });
        let cached = input_digests(&previous_args).unwrap();
        previous_args.common.inputs[0].spec =
            InputSpec::File(Box::from(std::path::Path::new(&cached[0].path)));

        let mut current_args = MachOArgs::default();
        current_args.common.inputs.push(Input {
            spec: InputSpec::File(Box::from(current_archive.as_path())),
            search_first: None,
            modifiers: Modifiers::default(),
        });
        let current_input_path = input_digests(&current_args).unwrap()[0].path.clone();
        current_args.common.inputs[0].spec = InputSpec::File(Box::from(std::path::Path::new(&current_input_path)));

        assert_eq!(arguments_digest(&previous_args), arguments_digest(&current_args));
        assert_eq!(
            cache_approved_rustc_temporary_archives(
                &previous_args,
                &cached,
                b"an executable without input paths"
            ),
            vec![0]
        );
        assert!(cache_approved_rustc_temporary_archives(
            &previous_args,
            &cached,
            cached[0].path.as_bytes()
        )
        .is_empty());
        let current = input_digests_for_cache_hit(&current_args, &cached, &[0], &[]).unwrap();
        assert_eq!(current[0].digest, cached[0].digest);
        assert_ne!(current[0].path, cached[0].path);
        assert!(input_metadata_snapshots_match(&current_args, &current));

        std::fs::write(&current_archive, b"a different archive payload").unwrap();
        assert!(input_digests_for_cache_hit(&current_args, &cached, &[0], &[]).is_none());
        std::fs::remove_dir_all(directory).unwrap();
    }

    fn test_input_metadata() -> InputFileMetadata {
        InputFileMetadata {
            len: 12,
            modified_seconds: 34,
            modified_nanoseconds: 56,
            device: 78,
            inode: 90,
            changed_seconds: 12,
            changed_nanoseconds: 34,
        }
    }

    #[test]
    fn only_mapped_non_relocation_bytes_are_patchable() {
        let patches = vec![PatchRange {
            input_offset: 2,
            output_offset: 5,
            len: 3,
        }];
        let old_object = b"abcdefgh";
        let mut changed_object = *old_object;
        changed_object[3] = b'X';
        assert_eq!(masked_digest(old_object, &patches), masked_digest(&changed_object, &patches));

        let protected = vec![ProtectedRange {
            input_offset: 3,
            bytes: vec![b'd'],
        }];
        assert!(!protected_ranges_match(&changed_object, &protected));
        changed_object[3] = b'd';
        assert!(protected_ranges_match(&changed_object, &protected));

        let mut output = *b"0123456789";
        assert!(apply_patches(&mut output, &changed_object, &patches));
        assert_eq!(&output[5..8], b"cde");
    }

    #[test]
    fn output_patch_ranges_reject_cross_record_overlap_before_patching() {
        // Cargo's fixed-width `linker-stress` edit is a real 18-object Rustc transition. Keep
        // the cache batch large enough for that qualified topology while retaining a hard cap.
        assert_eq!(super::MAX_CHANGED_DIRECT_OBJECTS, 32);
        assert!(!super::changed_object_count_is_supported(0));
        assert!(super::changed_object_count_is_supported(1));
        assert!(super::changed_object_count_is_supported(
            super::MAX_CHANGED_DIRECT_OBJECTS
        ));
        assert!(!super::changed_object_count_is_supported(
            super::MAX_CHANGED_DIRECT_OBJECTS + 1
        ));

        let raw_object_patch = PatchRange {
            input_offset: 4,
            output_offset: 8,
            len: 4,
        };
        let linker_private_symbol_patch = SymbolValuePatch {
            input_value_offset: 0,
            input_section_address: 0,
            input_section_size: 8,
            output_value_offset: 24,
            output_section_address: 0x1_0000_0000,
            baseline_value: 0x1_0000_0000,
        }
        .signature_range();
        let rewritten_debug_path = PatchRange {
            input_offset: 0,
            output_offset: 40,
            len: 6,
        };
        assert!(super::output_patch_ranges_are_disjoint(
            64,
            [raw_object_patch, linker_private_symbol_patch, rewritten_debug_path]
        ));

        let overlapping_second_object = PatchRange {
            input_offset: 12,
            output_offset: 10,
            len: 4,
        };
        assert!(!super::output_patch_ranges_are_disjoint(
            64,
            [raw_object_patch, overlapping_second_object]
        ));
        assert!(!super::output_patch_ranges_are_disjoint(
            64,
            [PatchRange {
                input_offset: 0,
                output_offset: 63,
                len: 2,
            }]
        ));
    }

    #[test]
    fn structural_digest_ignores_patch_bytes_and_binds_their_layout() {
        let patches = vec![PatchRange {
            input_offset: 2,
            output_offset: 100,
            len: 3,
        }];
        assert_eq!(masked_digest(b"abcdef", &patches), masked_digest(b"abXYZf", &patches));
        assert_ne!(masked_digest(b"abcdef", &patches), masked_digest(b"aZcdef", &patches));

        let different_layout = vec![PatchRange {
            input_offset: 1,
            output_offset: 100,
            len: 3,
        }];
        assert_ne!(
            masked_digest(b"abcdef", &patches),
            masked_digest(b"abcdef", &different_layout)
        );

        let different_output_layout = vec![PatchRange {
            input_offset: 2,
            output_offset: 101,
            len: 3,
        }];
        assert_eq!(
            masked_digest(b"abcdef", &patches),
            masked_digest(b"abcdef", &different_output_layout)
        );
    }

    #[test]
    fn structural_digest_can_mask_a_linker_private_symbol_value_without_masking_its_nlist_identity() {
        let masks = [InputRange {
            input_offset: 8,
            len: 8,
        }];
        let baseline = b"symbol!!\x10\x00\x00\x00\x00\x00\x00\x00type";
        let changed_value = b"symbol!!\x18\x00\x00\x00\x00\x00\x00\x00type";
        let changed_identity = b"symbol?!\x18\x00\x00\x00\x00\x00\x00\x00type";
        assert_eq!(
            masked_digest_for_input_ranges(baseline, &masks),
            masked_digest_for_input_ranges(changed_value, &masks)
        );
        assert_ne!(
            masked_digest_for_input_ranges(baseline, &masks),
            masked_digest_for_input_ranges(changed_identity, &masks)
        );
    }

    #[test]
    fn linker_private_symbol_value_patch_updates_only_a_verified_fixed_width_output_value() {
        let mut input = [0_u8; 16];
        input[8..16].copy_from_slice(&0x1018_u64.to_le_bytes());
        let patch = SymbolValuePatch {
            input_value_offset: 8,
            input_section_address: 0x1000,
            input_section_size: 0x20,
            output_value_offset: 8,
            output_section_address: 0x1_0000_0000,
            baseline_value: 0x1_0000_0010,
        };

        let mut output = [0_u8; 16];
        output[8..16].copy_from_slice(&patch.baseline_value.to_le_bytes());
        assert!(apply_symbol_value_patches(&mut output, &input, &[patch]));
        assert_eq!(
            u64::from_le_bytes(output[8..16].try_into().unwrap()),
            0x1_0000_0018
        );

        output[8..16].copy_from_slice(&patch.baseline_value.to_le_bytes());
        input[8..16].copy_from_slice(&0x1020_u64.to_le_bytes());
        assert!(!apply_symbol_value_patches(&mut output, &input, &[patch]));
        assert_eq!(
            u64::from_le_bytes(output[8..16].try_into().unwrap()),
            patch.baseline_value
        );
    }

    #[test]
    fn cache_signature_rehashes_changed_pages_and_the_uuid_page() {
        let code_limit = 3 * macho::CS_BLOCK_SIZE + 17;
        let hash_count = code_limit.div_ceil(macho::CS_BLOCK_SIZE);
        let hash_size = usize::from(macho::CS_HASH_SIZE);
        let hashes_offset = code_limit + 64;
        let uuid_offset = 12;
        let mut output = (0..hashes_offset + hash_count * hash_size)
            .map(|index| (index % 251) as u8)
            .collect::<Vec<_>>();
        let baseline_hashes = output[..code_limit]
            .chunks(macho::CS_BLOCK_SIZE)
            .map(<sha2::Sha256 as sha2::Digest>::digest)
            .collect::<Vec<_>>();
        for (index, digest) in baseline_hashes.into_iter().enumerate() {
            let start = hashes_offset + index * hash_size;
            output[start..start + hash_size].copy_from_slice(&digest);
        }

        // Page zero changes whenever a cache hit writes its new UUID. The two patch ranges cover
        // the remaining changed pages; untouched hash slots must stay valid from the baseline.
        output[uuid_offset] ^= 1;
        output[macho::CS_BLOCK_SIZE + 3] ^= 1;
        output[3 * macho::CS_BLOCK_SIZE + 7] ^= 1;
        let patches = [
            PatchRange {
                input_offset: 0,
                output_offset: (macho::CS_BLOCK_SIZE + 3) as u64,
                len: 1,
            },
            PatchRange {
                input_offset: 1,
                output_offset: (3 * macho::CS_BLOCK_SIZE + 7) as u64,
                len: 1,
            },
        ];

        assert!(refresh_changed_code_signature_hashes(
            &mut output,
            code_limit,
            hashes_offset,
            hash_count,
            uuid_offset,
            patches.into_iter(),
        ));

        let expected = output[..code_limit]
            .chunks(macho::CS_BLOCK_SIZE)
            .flat_map(<sha2::Sha256 as sha2::Digest>::digest)
            .collect::<Vec<_>>();
        assert_eq!(
            &output[hashes_offset..hashes_offset + hash_count * hash_size],
            expected
        );
    }

    #[test]
    fn relocation_words_remain_from_the_resolved_baseline() {
        let protected = vec![ProtectedRange {
            input_offset: 3,
            bytes: vec![b'd', b'e'],
        }];
        let mut patches = Vec::new();
        add_patch_ranges_excluding_protected(&mut patches, 2, 8, 5, &protected).unwrap();
        assert_eq!(
            patches,
            vec![
                PatchRange {
                    input_offset: 2,
                    output_offset: 8,
                    len: 1,
                },
                PatchRange {
                    input_offset: 5,
                    output_offset: 11,
                    len: 2,
                },
            ]
        );

        let input = b"abcdeFG";
        let mut output = *b"01234567rRrRrRrR";
        assert!(apply_patches(&mut output, input, &patches));
        assert_eq!(&output[8..13], b"cRrFG");
    }
}
