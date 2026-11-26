//! Shared configuration for the bcur fuzz targets.

/// Defines `__asan_default_options` with `malloc_context_size=8` for targets
/// that decode dCBOR.
///
/// `dcbor` decodes and drops nested values recursively, one stack frame per
/// nesting level, so each allocation's stack trace spells out the input's
/// nesting path. ASan interns every distinct alloc/free trace (30 frames by
/// default) in its append-only StackDepot, which then grows with every new
/// nesting libFuzzer generates until `-rss_limit_mb` trips. Eight frames keep
/// the allocation site and its nearest callers and bound the depot. An
/// explicit `ASAN_OPTIONS=malloc_context_size=<n>` still takes precedence.
#[macro_export]
macro_rules! dcbor_asan_options {
    () => {
        #[unsafe(no_mangle)]
        pub extern "C" fn __asan_default_options() -> *const ::core::ffi::c_char {
            c"malloc_context_size=8".as_ptr()
        }
    };
}
