//! LNS (LEZ Name Service) clean-room resolver.
//!
//! Implements the SPEC.md resolution protocol using only standard crates.
//! No code from `jefdiesel/logos-names` is imported.

use aes_gcm::{
    Aes256Gcm, Nonce,
    aead::{Aead, KeyInit, Payload},
};
use async_trait::async_trait;
use borsh::{BorshDeserialize, BorshSerialize};
use dashmap::DashMap;
use lee::AccountId;
use sequencer_service_rpc::{RpcClient as _, SequencerClientBuilder};
use sha2::{Digest, Sha256};
use std::io::Cursor;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use super::{NameResolver, ResolveError, ResolvedDestination};

/// Default Argon2id parameters from SPEC.md
const ARGON2_MEMORY_KIB: u32 = 65_536; // 64 MiB
const ARGON2_PASSES: u32 = 3;
const ARGON2_LANES: u32 = 1;
const ARGON2_OUTPUT_LEN: usize = 32;
const ARGON2_SALT: &[u8] = b"logos-names/v5";

/// Cache TTL: resolved names are cached in memory for 5 minutes.
const CACHE_TTL: Duration = Duration::from_secs(300);

/// Grace period: 30 days in milliseconds (SPEC §6: 2,592,000,000 ms).
pub const GRACE_PERIOD_MS: u64 = 2_592_000_000;

/// Default sequencer RPC endpoint for Logos testnet.
pub const DEFAULT_SEQUENCER_URL: &str = "https://testnet.lez.logos.co";

/// Associated data bound to sealed name records (SPEC §5).
pub const RECORD_ASSOCIATED_DATA: &[u8] = b"logos-names/v5/record";

const NONCE_LEN: usize = 12;
const TAG_LEN: usize = 16;
const PDA_PREFIX: &[u8; 32] = b"/LEE/v0.2/AccountId/PDA/\0\0\0\0\0\0\0\0";

/// Borsh-encoded on-chain NameRecord from SPEC.md §5.
#[derive(BorshDeserialize, BorshSerialize, Debug, Clone, PartialEq, Eq)]
pub struct NameRecord {
    pub version: u8,
    pub owner: [u8; 32],
    pub expires: u64,
    pub sealed: Vec<u8>,
}

/// Text record inside Profile from SPEC.md §5.
#[derive(BorshDeserialize, BorshSerialize, Debug, Clone, PartialEq, Eq)]
pub struct TextRecord {
    pub key: String,
    pub value: String,
}

/// Plaintext Profile inside sealed record from SPEC.md §5.
#[derive(BorshDeserialize, BorshSerialize, Debug, Clone, PartialEq, Eq)]
pub struct Profile {
    pub name: String,
    pub account: Option<AccountId>,
    pub npk: Option<[u8; 32]>,
    pub vpk: Vec<u8>,
    pub texts: Vec<TextRecord>,
}

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
        // Default testnet registry
        let registry_program_id =
            AccountId::from_str("66nUvzJtTxA729aUpTcAWDrb7cV9Heb2bDzceHQhLYad").unwrap_or_default();
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
    pub config: LnsConfig,
    sequencer_url: Option<String>,
    enabled: AtomicBool,
    cache: DashMap<String, CachedEntry>,
}

impl LnsResolver {
    pub fn new(config: LnsConfig) -> Self {
        Self::with_sequencer(config, None)
    }

    pub fn with_sequencer(config: LnsConfig, sequencer_url: Option<String>) -> Self {
        let enabled = AtomicBool::new(config.enabled);
        Self {
            config,
            sequencer_url,
            enabled,
            cache: DashMap::new(),
        }
    }

    /// Return the sequencer RPC URL in use (configured or default testnet).
    pub fn sequencer_url(&self) -> &str {
        self.sequencer_url
            .as_deref()
            .unwrap_or(DEFAULT_SEQUENCER_URL)
    }

    /// Set or update the sequencer RPC URL at runtime.
    pub fn set_sequencer_url(&mut self, url: Option<String>) {
        self.sequencer_url = url;
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
        let trimmed = input.trim().to_lowercase();
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

    /// Compute the public PDA AccountId for a name record on chain (SPEC §4).
    ///
    /// `PDA(program, seed) = SHA-256(pad32("/LEE/v0.2/AccountId/PDA/") ‖ program ‖ seed)`
    pub fn compute_record_pda(program: &AccountId, id: &[u8; 32]) -> AccountId {
        let seed = Self::compute_pda_seed(id);
        let mut hasher = Sha256::new();
        hasher.update(PDA_PREFIX);
        hasher.update(program.as_ref());
        hasher.update(seed);
        AccountId::new(hasher.finalize().into())
    }

    /// Decrypt a sealed profile payload using AES-256-GCM (SPEC §5).
    ///
    /// Sealed format: nonce (12 bytes) ‖ ciphertext + tag (16 bytes).
    /// Associated Data: `logos-names/v5/record`.
    pub fn decrypt_sealed(key: &[u8; 32], sealed: &[u8]) -> Result<Vec<u8>, ResolveError> {
        if sealed.len() < NONCE_LEN + TAG_LEN {
            return Err(ResolveError::DecryptionFailed(
                "sealed payload too short".into(),
            ));
        }
        let (nonce_bytes, ciphertext) = sealed.split_at(NONCE_LEN);
        let nonce = Nonce::from_slice(nonce_bytes);
        let cipher = Aes256Gcm::new_from_slice(key)
            .map_err(|e| ResolveError::DecryptionFailed(e.to_string()))?;
        let payload = Payload {
            msg: ciphertext,
            aad: RECORD_ASSOCIATED_DATA,
        };
        cipher
            .decrypt(nonce, payload)
            .map_err(|e| ResolveError::DecryptionFailed(e.to_string()))
    }

    /// Decode the profile from plaintext, ignoring any trailing zero padding (SPEC §5).
    pub fn decode_profile(plaintext: &[u8]) -> Result<Profile, ResolveError> {
        let mut cursor = Cursor::new(plaintext);
        Profile::deserialize_reader(&mut cursor)
            .map_err(|e| ResolveError::DecryptionFailed(format!("invalid profile encoding: {e}")))
    }

    /// Seal a profile payload using AES-256-GCM and zero-padding (SPEC §5).
    /// Padded to the next multiple of 256 bytes so length reveals little.
    pub fn seal_profile(
        key: &[u8; 32],
        profile: &Profile,
        nonce: Option<[u8; 12]>,
    ) -> Result<Vec<u8>, ResolveError> {
        let mut raw =
            borsh::to_vec(profile).map_err(|e| ResolveError::DecryptionFailed(e.to_string()))?;
        let padded_len = raw.len().div_ceil(256) * 256;
        raw.resize(padded_len, 0);

        let nonce_bytes = nonce.unwrap_or_else(|| {
            let mut n = [0u8; 12];
            rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut n);
            n
        });
        let cipher = Aes256Gcm::new_from_slice(key)
            .map_err(|e| ResolveError::DecryptionFailed(e.to_string()))?;
        let payload = Payload {
            msg: &raw,
            aad: RECORD_ASSOCIATED_DATA,
        };
        let ciphertext = cipher
            .encrypt(Nonce::from_slice(&nonce_bytes), payload)
            .map_err(|e| ResolveError::DecryptionFailed(e.to_string()))?;

        let mut sealed = Vec::with_capacity(NONCE_LEN + ciphertext.len());
        sealed.extend_from_slice(&nonce_bytes);
        sealed.extend_from_slice(&ciphertext);
        Ok(sealed)
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

        // 1. Check in-memory cache
        if let Some(entry) = self.cache.get(&name)
            && entry.is_fresh()
        {
            return Ok(Some(entry.result.clone()));
        }

        // 2. Derive identifier and decryption key (Argon2id + SHA-256)
        let (id, key) = Self::derive(&name);

        // 3. Compute public PDA account address
        let record_pda = Self::compute_record_pda(&self.config.registry_program_id, &id);

        // 4. Query on-chain account state from LEZ sequencer RPC
        let client = match SequencerClientBuilder::default().build(self.sequencer_url()) {
            Ok(c) => c,
            Err(e) => return Err(ResolveError::NetworkError(e.to_string())),
        };

        let account = match client.get_account(record_pda).await {
            Ok(Some(acc)) => acc,
            Ok(None) => return Err(ResolveError::NameNotFound(name)),
            Err(e) => return Err(ResolveError::NetworkError(e.to_string())),
        };

        // 5. Extract shard for registry_program_id
        let actor_state = account.data.actor_state(self.config.registry_program_id);
        if actor_state.is_empty() {
            return Err(ResolveError::NameNotFound(name));
        }

        // 6. Decode NameRecord (Borsh)
        let record = match NameRecord::try_from_slice(actor_state.as_ref()) {
            Ok(r) => r,
            Err(e) => {
                return Err(ResolveError::DecryptionFailed(format!(
                    "corrupt NameRecord: {e}"
                )));
            }
        };

        // 7. Check expiration & grace period (SPEC §6)
        let now_ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64;

        if record.expires < u64::MAX && now_ms >= record.expires.saturating_add(GRACE_PERIOD_MS) {
            return Err(ResolveError::NameNotFound(name));
        }

        // 8. Decrypt sealed profile with AES-256-GCM and decode Profile (Borsh)
        let (dest_account, npk, vpk, texts) = if record.sealed.is_empty() {
            // Name is registered with nothing set (e.g. freshly registered or transferred)
            (None, None, None, Vec::new())
        } else {
            match Self::decrypt_sealed(&key, &record.sealed) {
                Ok(plaintext) => match Self::decode_profile(&plaintext) {
                    Ok(profile) => {
                        if profile.name != name {
                            // SPEC §5: If profile opens to another name, treat as registered with nothing set
                            (None, None, None, Vec::new())
                        } else {
                            let vpk = if profile.vpk.is_empty() {
                                None
                            } else {
                                Some(profile.vpk)
                            };
                            let texts = profile
                                .texts
                                .into_iter()
                                .map(|t| (t.key, t.value))
                                .collect();
                            (profile.account, profile.npk, vpk, texts)
                        }
                    }
                    Err(_) => (None, None, None, Vec::new()),
                },
                Err(_) => {
                    // SPEC §5: If sealed does not open with key, treat as registered with nothing set
                    (None, None, None, Vec::new())
                }
            }
        };

        let destination = ResolvedDestination {
            name: name.clone(),
            account: dest_account,
            npk,
            vpk,
            expires: record.expires,
            texts,
        };

        // 9. Cache positive resolution result
        self.cache.insert(
            name,
            CachedEntry {
                result: destination.clone(),
                fetched_at: Instant::now(),
            },
        );

        Ok(Some(destination))
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
            "66nUvzJtTxA729aUpTcAWDrb7cV9Heb2bDzceHQhLYad"
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

    #[test]
    fn spec_section_10_derivation_test_vectors() {
        // jef test vector from SPEC.md §10
        let (id_jef, key_jef) = LnsResolver::derive("jef");
        assert_eq!(
            hex::encode(id_jef),
            "7041d9e447f06bdfe327d870402b1524cfe38bd03445b8fc3d0e87bc978eb763"
        );
        assert_eq!(
            hex::encode(key_jef),
            "aad91a1a3dd0fb56a213212fbea58fe25d9139db42fc59ce2116c3cfa3440088"
        );

        // Record PDA of jef with program = [0x07; 32]
        let program = AccountId::new([0x07; 32]);
        let pda = LnsResolver::compute_record_pda(&program, &id_jef);
        assert_eq!(
            pda.to_string(),
            "5b5xVGob2GYvrq21MSuxm1MfieucDEy9yxhDwdXndbpD"
        );

        // logos test vector
        let (id_logos, key_logos) = LnsResolver::derive("logos");
        assert_eq!(
            hex::encode(id_logos),
            "4a8bf61b00dbc63907a935aa15ed534bb32d866978aa1f2128f9b6f37e0c4025"
        );
        assert_eq!(
            hex::encode(key_logos),
            "d67dd628fa51fa62bd32ea82c3e9ff1b67f93b01103be956eaebc52f1699df44"
        );

        // a-b-c test vector
        let (id_abc, key_abc) = LnsResolver::derive("a-b-c");
        assert_eq!(
            hex::encode(id_abc),
            "707decf4fde6d9fb61d255c23b34e042c846a0f4b0834151dcb2c1ef4160e849"
        );
        assert_eq!(
            hex::encode(key_abc),
            "e3666a8572f7cabe94f6717491bff34c70eeca216436a142185bd8a86b6ccf31"
        );
    }

    #[test]
    fn spec_section_10_sealed_profile_decryption() {
        let key = hex::decode("aad91a1a3dd0fb56a213212fbea58fe25d9139db42fc59ce2116c3cfa3440088")
            .unwrap();
        let key_bytes: [u8; 32] = key.try_into().unwrap();

        let sealed_hex = concat!(
            "000102030405060708090a0b7a39f7ff67b20894263a28d040c0f2711c04ba247fcf5cb107e27b59",
            "05b8a0664b28cd25512addcb74af3efa5a8d6eb3bbb8e89fb8dba0aa2739252efed2be01ab019998",
            "a07d416c788d8c9b699891e85bedd1118da7089377220bdb0ab8ae29661bf20e006c5fbffb222237",
            "2ea0a2589ed49023186a77e9afee1af338f4a2377afa40da018789ca715318d981b556f71f9640eb",
            "d056d8dcbe2b71845b45a578721ccc2c889df37b926c7da5a5202dbf3d50dc04883673134ce0772f",
            "bcd7fbc8f31f455bb39b3d867d5e6772c86e59f42a9d04ffaacaa6119b1156d238665c0cf50028a9",
            "cbf8b3189fc45a15a724c5775a835a8ccdff6a573d8e046d78e847b7da5668bc8529aedb3bdc70a9",
            "9db9b9b4"
        );
        let sealed = hex::decode(sealed_hex).unwrap();

        let decrypted =
            LnsResolver::decrypt_sealed(&key_bytes, &sealed).expect("decrypt should succeed");
        assert_eq!(decrypted.len(), 256);

        let profile =
            LnsResolver::decode_profile(&decrypted).expect("decode profile should succeed");
        assert_eq!(profile.name, "jef");
        assert_eq!(profile.account, Some(AccountId::new([0x02; 32])));
        assert_eq!(profile.npk, None);
        assert_eq!(profile.vpk, Vec::<u8>::new());
        assert_eq!(profile.texts.len(), 1);
        assert_eq!(profile.texts[0].key, "chat");
        assert_eq!(profile.texts[0].value, "hi");
    }

    #[test]
    fn seal_and_open_roundtrip() {
        let (id, key) = LnsResolver::derive("alice");
        let profile = Profile {
            name: "alice".into(),
            account: Some(AccountId::new(id)),
            npk: Some([0x11; 32]),
            vpk: vec![0x22; 64],
            texts: vec![
                TextRecord {
                    key: "chat".into(),
                    value: "hello alice".into(),
                },
                TextRecord {
                    key: "color".into(),
                    value: "#ff0077".into(),
                },
            ],
        };

        let sealed = LnsResolver::seal_profile(&key, &profile, None).expect("sealing succeeds");
        let opened = LnsResolver::decrypt_sealed(&key, &sealed).expect("opening succeeds");
        let decoded = LnsResolver::decode_profile(&opened).expect("decoding succeeds");

        assert_eq!(decoded.name, profile.name);
        assert_eq!(decoded.account, profile.account);
        assert_eq!(decoded.npk, profile.npk);
        assert_eq!(decoded.vpk, profile.vpk);
        assert_eq!(decoded.texts, profile.texts);
    }

    #[tokio::test]
    async fn cache_hit_avoids_repeated_calls() {
        let resolver = LnsResolver::new(LnsConfig::default());
        let dest = ResolvedDestination {
            name: "cached".into(),
            account: Some(AccountId::default()),
            npk: None,
            vpk: None,
            expires: u64::MAX,
            texts: vec![],
        };
        resolver.cache.insert(
            "cached".into(),
            CachedEntry {
                result: dest.clone(),
                fetched_at: Instant::now(),
            },
        );

        let res = resolver.resolve("cached.lez").await.unwrap();
        assert!(res.is_some());
        assert_eq!(res.unwrap().name, "cached");
    }

    #[tokio::test]
    async fn live_testnet_unregistered_name_returns_not_found() {
        let resolver = LnsResolver::new(LnsConfig::default());
        let res = resolver.resolve("nonexistent-test-record-999.lez").await;
        assert!(matches!(res, Err(ResolveError::NameNotFound(_))));
    }
}
