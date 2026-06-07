use backend::*;

pub use backend::ProofError;
pub use rec_aggregation::{
    MAX_RECURSIONS, MAX_XMSS_AGGREGATED, MAX_XMSS_DUPLICATES, TypeOneInfo, TypeOneMultiSignature,
    TypeTwoMultiSignature, aggregate_type_1, merge_many_type_1, split_type_2, verify_type_1, verify_type_2,
};
pub use xmss::{MESSAGE_LEN_FE, XmssPublicKey, XmssSecretKey, XmssSignature, xmss_key_gen, xmss_sign, xmss_verify};

pub type F = KoalaBear;

/// Returns true when the Metal GPU backend is available on this host.
pub fn gpu_available() -> bool {
    gpu_poseidon::metal_available()
}

/// Returns true when prover code is allowed to route supported work to the GPU.
pub fn gpu_enabled() -> bool {
    gpu_poseidon::gpu_enabled()
}

/// Enables or disables the GPU backend. Enabling is ignored on hosts without Metal.
pub fn set_gpu_enabled(enabled: bool) {
    gpu_poseidon::set_gpu_enabled(enabled && gpu_available());
}

/// Enables GPU acceleration when `LEAN_MULTISIG_GPU` is set to a truthy value.
pub fn configure_gpu_from_env() {
    let requested = std::env::var("LEAN_MULTISIG_GPU")
        .map(|value| matches!(value.as_str(), "1" | "true" | "TRUE" | "yes" | "YES" | "on" | "ON"))
        .unwrap_or(false);
    set_gpu_enabled(requested);
}

/// Call once before proving. Compiles the aggregation program and precomputes DFT twiddles.
pub fn setup_prover() {
    configure_gpu_from_env();
    rec_aggregation::init_aggregation_bytecode();
    precompute_dft_twiddles::<F>(1 << 24);
}

/// Call once before verifying (not needed if `setup_prover` was already called).
pub fn setup_verifier() {
    rec_aggregation::init_aggregation_bytecode();
}

/// Bump-arena allocator.
///
/// **Optional.**
///
/// To enable, set it as the `#[global_allocator]` in your binary and call
/// [`init_allocator`] once at startup. Then bracket each proving call with
/// [`begin_phase`] / [`end_phase`] and **clone the outputs after
/// [`end_phase`]** so the cloned copy lands in the system allocator before the
/// next [`begin_phase`] resets the arena slabs.
///
/// See `tests/test_zk_alloc.rs` for a runnable end-to-end example.
pub use zk_alloc::{ZkAllocator, begin_phase, end_phase, init as init_allocator};