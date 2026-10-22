//! LNS (LEZ Name Service) clean-room resolver.
//!
//! Implements the SPEC.md resolution protocol using only standard crates.
//! No code from `jefdiesel/logos-names` is imported.

use async_trait::async_trait;
use dashmap::DashMap;
use lee::AccountId;
use sha2::{Digest, Sha256};
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use super::{NameResolver, ResolveError, ResolvedDestination};

/// Default Argon2id parameters from SPEC.md
const ARGON2_MEMORY_KIB: u32 = 65_536; // 64 MiB
const ARGON2_PASSES: u32 = 3;
const ARGON2_LANES: u32 = 1;
const ARGON2_OUTPUT_LEN: usize = 32;
const ARGON2_SALT: &[u8] = b"logos-names/v5";

/// Cache TTL: resolved names are cached in memory for 5 minutes.
const CACHE_TTL: Duration = Duration::from_secs(300);
#[allow(dead_code)]
const GRACE_PERIOD_SECS: u64 = 30 * 24 * 3600;

/// Cached resolution result with a timestamp.
#[derive(Debug, Clone)]
struct CachedEntry {
    result: ResolvedDestination,
    fetched_at: Instant,
}

impl CachedEntry {
    fn is_fresh(&self) -> bool {
        self.fetched_at.elapsed() < CACHE_TTL
    }
}

/// LNS resolver configuration.
#[derive(Debug, Clone)]
pub struct LnsConfig {
    pub registry_program_id: AccountId,
    pub enabled: bool,
}

impl Default for LnsConfig {
    fn default() -> Self {
        use std::str::FromStr;
        // Default testnet registry (LNS v5)
        let registry_program_id =
            AccountId::from_str("38jEfVV1RCyMzu1FGbYcCn5FqxCxKyY58VgzjruAh2gq").unwrap_or_default();
        Self {
            registry_program_id,
            enabled: true,
        }
    }
}

/// Clean-room LNS resolver.
///
/// Resolution protocol (from SPEC.md):
/// 1. Normalise: trim, lowercase, strip ".lez", validate [a-z0-9-]{1,32}
/// 2. Derive: Argon2id(name, "logos-names/v5", 64MiB, 3, 1) → master
///    id  = SHA-256("logos-names/v5/id"  ‖ master)
///    key = SHA-256("logos-names/v5/key" ‖ master)
/// 3. PDA: seed = SHA-256("logos-names/v5/name/" ‖ id), pda = PDA(registry, seed)
/// 4. Read account state from sequencer
/// 5. Decode NameRecord (Borsh)
/// 6. Decrypt sealed profile (AES-256-GCM)
/// 7. Decode Profile (Borsh), verify profile.name == input name
pub struct LnsResolver {
    #[allow(dead_code)]
    pub config: LnsConfig,
    enabled: AtomicBool,
    cache: DashMap<String, CachedEntry>,
}

impl LnsResolver {
    pub fn new(config: LnsConfig) -> Self {
        let enabled = AtomicBool::new(config.enabled);
        Self {
            config,
            enabled,
            cache: DashMap::new(),
        }
    }

    /// Enable or disable LNS resolution at runtime.
    pub fn set_enabled(&self, enabled: bool) {
        self.enabled.store(enabled, Ordering::Relaxed);
    }

    pub fn is_enabled(&self) -> bool {
        self.enabled.load(Ordering::Relaxed)
    }

    /// Clear the resolution cache (e.g. on wallet lock).
    pub fn clear_cache(&self) {
        self.cache.clear();
    }

    /// Normalise a `.lez` name input.
    /// Returns `Some(name)` (without ".lez") if valid, `None` if not a .lez name.
    pub fn normalise(input: &str) -> Option<String> {
        // ASCII only: Unicode lowercasing maps lookalikes such as U+212A KELVIN SIGN to 'k'.
        let trimmed = input.trim().to_ascii_lowercase();
        let name = trimmed.strip_suffix(".lez")?;

        // Validate: 1-32 chars, [a-z0-9-], no leading/trailing hyphen
        if name.is_empty() || name.len() > 32 {
            return None;
        }
        if name.starts_with('-') || name.ends_with('-') {
            return None;
        }
        if !name
            .chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-')
        {
            return None;
        }

        Some(name.to_string())
    }

    /// Derive the name identifier and decryption key from a normalised name.
    ///
    /// master = Argon2id(name, "logos-names/v5", 64MiB, 3 passes, 1 lane, 32 bytes)
    /// id     = SHA-256("logos-names/v5/id"  ‖ master)
    /// key    = SHA-256("logos-names/v5/key" ‖ master)
    pub fn derive(name: &str) -> ([u8; 32], [u8; 32]) {
        // Argon2id derivation
        let params = argon2::Params::new(
            ARGON2_MEMORY_KIB,
            ARGON2_PASSES,
            ARGON2_LANES,
            Some(ARGON2_OUTPUT_LEN),
        )
        .expect("valid Argon2 params");

        let argon2 =
            argon2::Argon2::new(argon2::Algorithm::Argon2id, argon2::Version::V0x13, params);

        let mut master = [0u8; 32];
        argon2
            .hash_password_into(name.as_bytes(), ARGON2_SALT, &mut master)
            .expect("Argon2id hashing should not fail");

        // Derive id
        let mut id_hasher = Sha256::new();
        id_hasher.update(b"logos-names/v5/id");
        id_hasher.update(master);
        let id: [u8; 32] = id_hasher.finalize().into();

        // Derive key
        let mut key_hasher = Sha256::new();
        key_hasher.update(b"logos-names/v5/key");
        key_hasher.update(master);
        let key: [u8; 32] = key_hasher.finalize().into();

        (id, key)
    }

    /// Compute the PDA for a name identifier.
    ///
    /// seed = SHA-256("logos-names/v5/name/" ‖ id)
    /// pda  = PDA(registry_program_id, seed)
    pub fn compute_pda_seed(id: &[u8; 32]) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(b"logos-names/v5/name/");
        hasher.update(id);
        hasher.finalize().into()
    }
}

#[async_trait]
impl NameResolver for LnsResolver {
    async fn resolve(&self, input: &str) -> Result<Option<ResolvedDestination>, ResolveError> {
        if !self.is_enabled() {
            return Err(ResolveError::Disabled);
        }

        let name = match Self::normalise(input) {
            Some(n) => n,
            None => return Ok(None), // Not a .lez name — passthrough
        };

        // Check cache
        if let Some(entry) = self.cache.get(&name)
            && entry.is_fresh()
        {
            return Ok(Some(entry.result.clone()));
        }

        // Derive identifier and decryption key (~100ms due to Argon2id)
        let (id, _key) = Self::derive(&name);
        let _pda_seed = Self::compute_pda_seed(&id);

        // TODO: Steps 3-7 — read PDA account from sequencer, decode NameRecord,
        // decrypt sealed profile with AES-256-GCM, decode Profile, verify name match.
        //
        // For now, return NameNotFound. This will be implemented when we have
        // sequencer access wired through the engine.
        Err(ResolveError::NameNotFound(name))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalise_valid_names() {
        assert_eq!(LnsResolver::normalise("alice.lez"), Some("alice".into()));
        assert_eq!(
            LnsResolver::normalise("  Alice.LEZ  "),
            Some("alice".into())
        );
        assert_eq!(
            LnsResolver::normalise("bob-123.lez"),
            Some("bob-123".into())
        );
        assert_eq!(LnsResolver::normalise("a.lez"), Some("a".into()));
    }

    #[test]
    fn normalise_invalid_names() {
        assert_eq!(LnsResolver::normalise("alice"), None); // no .lez
        assert_eq!(LnsResolver::normalise(".lez"), None); // empty name
        assert_eq!(LnsResolver::normalise("-alice.lez"), None); // leading hyphen
        assert_eq!(LnsResolver::normalise("alice-.lez"), None); // trailing hyphen
        assert_eq!(LnsResolver::normalise("alice bob.lez"), None); // space
        assert_eq!(LnsResolver::normalise("ALICE!.lez"), None); // invalid char

        // 33 chars — too long
        let long = format!("{}.lez", "a".repeat(33));
        assert_eq!(LnsResolver::normalise(&long), None);
    }

    #[test]
    fn normalise_rejects_non_ascii_case_folding() {
        // U+212A KELVIN SIGN lowercases to ASCII 'k' under full Unicode rules.
        assert_eq!(LnsResolver::normalise("\u{212A}ate.lez"), None);
    }

    #[test]
    fn normalise_max_length() {
        let max = format!("{}.lez", "a".repeat(32));
        assert_eq!(LnsResolver::normalise(&max), Some("a".repeat(32)));
    }

    #[test]
    fn derive_is_deterministic() {
        let (id1, key1) = LnsResolver::derive("alice");
        let (id2, key2) = LnsResolver::derive("alice");
        assert_eq!(id1, id2);
        assert_eq!(key1, key2);
    }

    #[test]
    fn derive_different_names_produce_different_keys() {
        let (id_a, key_a) = LnsResolver::derive("alice");
        let (id_b, key_b) = LnsResolver::derive("bob");
        assert_ne!(id_a, id_b);
        assert_ne!(key_a, key_b);
    }

    #[test]
    fn pda_seed_is_deterministic() {
        let id = [42u8; 32];
        let s1 = LnsResolver::compute_pda_seed(&id);
        let s2 = LnsResolver::compute_pda_seed(&id);
        assert_eq!(s1, s2);
    }

    #[tokio::test]
    async fn disabled_resolver_returns_error() {
        let resolver = LnsResolver::new(LnsConfig {
            enabled: false,
            ..Default::default()
        });
        let result = resolver.resolve("alice.lez").await;
        assert!(matches!(result, Err(ResolveError::Disabled)));
    }

    #[tokio::test]
    async fn non_lez_name_passes_through() {
        let resolver = LnsResolver::new(LnsConfig::default());
        let result = resolver.resolve("not-a-lez-name").await;
        assert!(matches!(result, Ok(None)));
    }

    #[test]
    fn default_registry_id_parses_successfully() {
        let config = LnsConfig::default();
        assert_ne!(config.registry_program_id, AccountId::default());
        assert_eq!(
            config.registry_program_id.to_string(),
            "38jEfVV1RCyMzu1FGbYcCn5FqxCxKyY58VgzjruAh2gq"
        );
    }

    #[test]
    fn jef_lez_derivation_and_pda() {
        let normalised = LnsResolver::normalise("jef.lez").expect("jef.lez must be valid");
        assert_eq!(normalised, "jef");

        let (id, key) = LnsResolver::derive(&normalised);
        assert_ne!(id, [0u8; 32]);
        assert_ne!(key, [0u8; 32]);

        let pda_seed = LnsResolver::compute_pda_seed(&id);
        assert_ne!(pda_seed, [0u8; 32]);

        // Verify derivation repeatability (A13 verification)
        let (id2, key2) = LnsResolver::derive(&normalised);
        assert_eq!(id, id2);
        assert_eq!(key, key2);
        assert_eq!(pda_seed, LnsResolver::compute_pda_seed(&id2));
    }
}
