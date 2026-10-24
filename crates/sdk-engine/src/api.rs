//! SDK API surface.
//!
//! [`SdkEngine`] is the central orchestrator. It owns `WalletCore`,
//! session store, request store, tx queue, decoder registry, verifier, and
//! resolver. Two API surfaces:
//!
//! - **[`DAppApi`]** — callable by third-party dApps via sessions.
//! - **[`OwnerApi`]** — callable only by the wallet UI (privileged).

use bip39::Mnemonic;
use lee::AccountId;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::Mutex;
use wallet::WalletCore;
use wallet::account::{AccountIdWithPrivacy, Label};

use crate::approval::{ApprovalDecision, ApprovalHandler, ApprovalPrompt};
use crate::decode::DecoderRegistry;
use crate::effects::EffectSimulator;
use crate::error::{SdkError, SdkResult};
use crate::queue::TxQueue;
use crate::request::{PendingRequest, RequestId, RequestKind, RequestStatus, RequestStore};
use crate::resolve::NameResolver;
use crate::resolve::lns::{LnsConfig, LnsResolver};
use crate::session::{GrantKind, SessionId, SessionStore};
use crate::store::PersistentStore;
use crate::verifier::{BuiltinVerifier, ProgramVerifier};

const DEFAULT_SESSION_TTL: Duration = Duration::from_secs(24 * 3600);
const DEFAULT_APPROVAL_TIMEOUT: Duration = Duration::from_secs(300);

#[derive(Debug, Clone)]
pub struct SdkConfig {
    pub wallet_config_path: PathBuf,
    pub wallet_storage_path: PathBuf,
    pub sdk_state_path: PathBuf,
    pub session_ttl: Duration,
    pub approval_timeout: Duration,
    pub lns_config: LnsConfig,
    pub program_verification_enabled: bool,
}

impl SdkConfig {
    pub fn new(data_dir: PathBuf) -> Self {
        Self {
            wallet_config_path: data_dir.join("wallet_config.json"),
            wallet_storage_path: data_dir.join("wallet_storage.json"),
            sdk_state_path: data_dir.join("sdk_state.json"),
            session_ttl: DEFAULT_SESSION_TTL,
            approval_timeout: DEFAULT_APPROVAL_TIMEOUT,
            lns_config: LnsConfig::default(),
            program_verification_enabled: true,
        }
    }
}

#[derive(Debug, Clone)]
pub struct SdkInfo {
    pub sdk_version: String,
    pub api_version: u32,
    pub network: String,
    pub wallet_initialized: bool,
    pub wallet_locked: bool,
}

#[derive(Debug, Clone)]
pub struct AccountView {
    pub account_id: AccountId,
    pub privacy: AccountPrivacy,
    pub label: Option<String>,
    pub balance: Option<u128>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AccountPrivacy {
    Public,
    Private,
}

/// The central SDK engine.
pub struct SdkEngine {
    wallet: Arc<Mutex<WalletCore>>,
    sessions: SessionStore,
    requests: RequestStore,
    tx_queue: TxQueue,
    decoders: DecoderRegistry,
    verifier: Box<dyn ProgramVerifier>,
    resolver: Box<dyn NameResolver>,
    store: Arc<Mutex<PersistentStore>>,
    approval_handler: Arc<dyn ApprovalHandler>,
    identity_secret: Arc<Mutex<Option<crate::identity::IdentitySecret>>>,
    config: SdkConfig,
}

/// dApp-facing API .
pub trait DAppApi {
    fn sdk_info(&self) -> impl std::future::Future<Output = SdkResult<SdkInfo>> + Send;

    fn connect(
        &self,
        caller_identity: String,
        api_version: u32,
    ) -> impl std::future::Future<Output = SdkResult<SessionId>> + Send;

    fn disconnect(
        &self,
        session_id: &SessionId,
    ) -> impl std::future::Future<Output = SdkResult<()>> + Send;

    fn request_accounts(
        &self,
        session_id: &SessionId,
    ) -> impl std::future::Future<Output = SdkResult<Vec<AccountView>>> + Send;

    fn list_accounts(
        &self,
        session_id: &SessionId,
    ) -> impl std::future::Future<Output = SdkResult<Vec<AccountView>>> + Send;

    fn get_balance(
        &self,
        session_id: &SessionId,
        account: &AccountId,
    ) -> impl std::future::Future<Output = SdkResult<u128>> + Send;

    fn propose_native_transfer(
        &self,
        session_id: &SessionId,
        from: AccountId,
        to: String,
        amount: u128,
    ) -> impl std::future::Future<Output = SdkResult<RequestId>> + Send;

    fn propose_token_transfer(
        &self,
        session_id: &SessionId,
        from_holding: AccountId,
        to_holding: AccountId,
        definition: AccountId,
        amount: u128,
    ) -> impl std::future::Future<Output = SdkResult<RequestId>> + Send;

    fn propose_transaction(
        &self,
        session_id: &SessionId,
        mentions: Vec<AccountId>,
        calldata: Vec<u8>,
        description: Option<String>,
    ) -> impl std::future::Future<Output = SdkResult<RequestId>> + Send;

    fn get_request_status(
        &self,
        request_id: &RequestId,
    ) -> impl std::future::Future<Output = SdkResult<RequestStatus>> + Send;

    fn cancel_request(
        &self,
        request_id: &RequestId,
    ) -> impl std::future::Future<Output = SdkResult<()>> + Send;

    fn resolve_name(
        &self,
        session_id: &SessionId,
        name: &str,
    ) -> impl std::future::Future<Output = SdkResult<crate::resolve::ResolvedDestination>> + Send;

    /// Request identity permission grants (`IdentityRead` or `IdentityPropose`) for this session.
    fn request_identity_access(
        &self,
        session_id: &SessionId,
        kind: GrantKind,
    ) -> impl std::future::Future<Output = SdkResult<()>> + Send;

    /// Retrieve the user's public identity commitment derived from the root seed.
    ///
    /// Requires `IdentityRead` grant.
    fn get_identity_commitment(
        &self,
        session_id: &SessionId,
    ) -> impl std::future::Future<Output = SdkResult<crate::identity::IdentityCommitment>> + Send;

    /// Derive a scope-specific pseudonymous nullifier for unlinkable actions across dApps.
    ///
    /// Requires `IdentityRead` grant.
    fn derive_scoped_nullifier(
        &self,
        session_id: &SessionId,
        scope_id: &str,
    ) -> impl std::future::Future<Output = SdkResult<crate::identity::ScopedNullifier>> + Send;

    /// Sign an arbitrary message (e.g. voting ballot or membership claim) using the scoped credential.
    ///
    /// Requires `IdentityPropose` grant.
    fn sign_identity_attestation(
        &self,
        session_id: &SessionId,
        scope_id: &str,
        message: &[u8],
    ) -> impl std::future::Future<Output = SdkResult<crate::identity::AttestationPayload>> + Send;

    /// Prepare an on-chain registration payload with SSS threshold shares encrypted to designated accountability trustees.
    ///
    /// Requires `IdentityPropose` grant.
    fn prepare_identity_registration(
        &self,
        session_id: &SessionId,
        scope_id: &str,
        node_pubkeys: &[[u8; 32]],
        threshold_k: u8,
    ) -> impl std::future::Future<Output = SdkResult<crate::identity::RegistrationPayload>> + Send;
}

/// Owner API  — privileged.
pub trait OwnerApi {
    fn create_wallet(
        &self,
        password: &str,
    ) -> impl std::future::Future<Output = SdkResult<Mnemonic>> + Send;

    fn restore_wallet(
        &self,
        mnemonic: &Mnemonic,
        password: &str,
    ) -> impl std::future::Future<Output = SdkResult<()>> + Send;

    fn lock(&self) -> impl std::future::Future<Output = SdkResult<()>> + Send;

    fn unlock(&self, password: &str) -> impl std::future::Future<Output = SdkResult<()>> + Send;

    fn create_account_public(
        &self,
        label: Option<String>,
    ) -> impl std::future::Future<Output = SdkResult<AccountId>> + Send;

    fn create_account_private(
        &self,
        label: Option<String>,
    ) -> impl std::future::Future<Output = SdkResult<AccountId>> + Send;

    fn list_all_accounts(
        &self,
    ) -> impl std::future::Future<Output = SdkResult<Vec<AccountView>>> + Send;

    fn list_sessions(
        &self,
    ) -> impl std::future::Future<Output = SdkResult<Vec<crate::session::Session>>> + Send;

    fn revoke_session(
        &self,
        session_id: &SessionId,
    ) -> impl std::future::Future<Output = SdkResult<()>> + Send;
}

impl SdkEngine {
    pub fn new(
        wallet: WalletCore,
        approval_handler: Arc<dyn ApprovalHandler>,
        config: SdkConfig,
    ) -> SdkResult<Self> {
        let store =
            PersistentStore::open(config.sdk_state_path.clone()).map_err(SdkError::Internal)?;

        let lns_enabled = store.state().lns_enabled;
        let verification_enabled = store.state().program_verification_enabled;

        let mut lns_config = config.lns_config.clone();
        lns_config.enabled = lns_enabled;

        Ok(Self {
            wallet: Arc::new(Mutex::new(wallet)),
            sessions: SessionStore::new(config.session_ttl),
            requests: RequestStore::new(),
            tx_queue: TxQueue::new(),
            decoders: DecoderRegistry::with_builtins(),
            verifier: Box::new(BuiltinVerifier::new(verification_enabled)),
            resolver: Box::new(LnsResolver::new(lns_config)),
            store: Arc::new(Mutex::new(store)),
            approval_handler,
            identity_secret: Arc::new(Mutex::new(None)),
            config,
        })
    }

    async fn validate_session(&self, session_id: &SessionId) -> SdkResult<crate::session::Session> {
        self.sessions
            .get(session_id)
            .await
            .ok_or_else(|| SdkError::SessionNotFound(session_id.clone()))
    }

    async fn require_grant(
        &self,
        session_id: &SessionId,
        account: &AccountId,
        kind: GrantKind,
    ) -> SdkResult<crate::session::Session> {
        let session = self.validate_session(session_id).await?;
        if !session.has_grant(account, kind) {
            return Err(SdkError::InsufficientGrant);
        }
        Ok(session)
    }

    async fn require_identity_grant(
        &self,
        session_id: &SessionId,
        kind: GrantKind,
    ) -> SdkResult<crate::session::Session> {
        let session = self.validate_session(session_id).await?;
        if !session.has_identity_grant(kind) {
            return Err(SdkError::InsufficientGrant);
        }
        Ok(session)
    }

    pub async fn set_identity_secret(&self, secret: Option<crate::identity::IdentitySecret>) {
        *self.identity_secret.lock().await = secret;
    }

    async fn resolve_destination(&self, input: &str) -> SdkResult<AccountId> {
        match self.resolver.resolve(input).await {
            Ok(Some(dest)) => {
                if let Some(account) = dest.account {
                    Ok(account)
                } else {
                    Err(SdkError::InvalidArgument(format!(
                        "Name '{}' resolved but has no public account; private .lez transfers not yet supported",
                        dest.name
                    )))
                }
            }
            Ok(None) => parse_account_id(input),
            Err(crate::resolve::ResolveError::Disabled) if !input.ends_with(".lez") => {
                parse_account_id(input)
            }
            Err(e) => Err(SdkError::NameResolutionError(e.to_string())),
        }
    }

    pub fn open_or_init(
        data_dir: PathBuf,
        password: &str,
        approval_handler: Arc<dyn ApprovalHandler>,
    ) -> SdkResult<Self> {
        let config = SdkConfig::new(data_dir.clone());
        if !data_dir.exists() {
            std::fs::create_dir_all(&data_dir).map_err(|e| SdkError::Internal(e.into()))?;
        }
        let wallet = if config.wallet_storage_path.exists() {
            WalletCore::new_update_chain(
                config.wallet_config_path.clone(),
                config.wallet_storage_path.clone(),
                None,
                password,
            )
            .map_err(SdkError::Internal)?
        } else {
            let (wallet, _mnemonic) = WalletCore::new_init_storage(
                config.wallet_config_path.clone(),
                config.wallet_storage_path.clone(),
                None,
                password,
            )
            .map_err(SdkError::Internal)?;
            wallet
        };

        Self::new(wallet, approval_handler, config)
    }

    pub async fn grant_account(
        &self,
        session_id: &SessionId,
        account: AccountId,
        kind: GrantKind,
    ) -> SdkResult<()> {
        self.sessions
            .update(session_id, |s| {
                s.add_grant(account, kind);
            })
            .await
            .ok_or_else(|| SdkError::SessionNotFound(session_id.clone()))?;
        Ok(())
    }

    pub async fn set_account_label(
        &self,
        account: AccountId,
        label: String,
        is_private: bool,
    ) -> SdkResult<()> {
        let mut wallet = self.wallet.lock().await;
        let privacy_account = if is_private {
            AccountIdWithPrivacy::Private(account)
        } else {
            AccountIdWithPrivacy::Public(account)
        };
        let _ = wallet
            .storage_mut()
            .add_label(Label::new(label), privacy_account);
        wallet.store_persistent_data().map_err(SdkError::Internal)?;
        Ok(())
    }

    pub fn sessions(&self) -> &SessionStore {
        &self.sessions
    }

    pub fn requests(&self) -> &RequestStore {
        &self.requests
    }

    pub fn approval_handler(&self) -> &Arc<dyn ApprovalHandler> {
        &self.approval_handler
    }

    pub fn wallet(&self) -> &Arc<Mutex<WalletCore>> {
        &self.wallet
    }

    pub fn config(&self) -> &SdkConfig {
        &self.config
    }
}

impl DAppApi for SdkEngine {
    async fn sdk_info(&self) -> SdkResult<SdkInfo> {
        let store = self.store.lock().await;
        Ok(SdkInfo {
            sdk_version: crate::SDK_VERSION.to_string(),
            api_version: crate::API_VERSION,
            network: "testnet-0.3-0.4".to_string(),
            wallet_initialized: true,
            wallet_locked: store.state().locked,
        })
    }

    async fn connect(&self, caller_identity: String, api_version: u32) -> SdkResult<SessionId> {
        {
            let store = self.store.lock().await;
            if store.state().locked {
                return Err(SdkError::WalletLocked);
            }
        }
        let session = self.sessions.create(caller_identity, api_version).await;
        log::info!("Session created: {}", session.id);
        Ok(session.id)
    }

    async fn disconnect(&self, session_id: &SessionId) -> SdkResult<()> {
        if self.sessions.revoke(session_id).await {
            Ok(())
        } else {
            Err(SdkError::SessionNotFound(session_id.clone()))
        }
    }

    async fn request_accounts(&self, session_id: &SessionId) -> SdkResult<Vec<AccountView>> {
        let _session = self.validate_session(session_id).await?;
        // TODO: Show account picker UI via approval handler.
        Ok(vec![])
    }

    async fn list_accounts(&self, session_id: &SessionId) -> SdkResult<Vec<AccountView>> {
        let session = self.validate_session(session_id).await?;
        let granted = session.granted_accounts();
        let wallet = self.wallet.lock().await;

        let mut views = Vec::new();
        for account_id in granted {
            let balance = wallet.get_account_balance(account_id).await.ok();
            views.push(AccountView {
                account_id,
                privacy: AccountPrivacy::Public,
                label: None,
                balance,
            });
        }
        Ok(views)
    }

    async fn get_balance(&self, session_id: &SessionId, account: &AccountId) -> SdkResult<u128> {
        self.require_grant(session_id, account, GrantKind::Read)
            .await?;
        let wallet = self.wallet.lock().await;
        wallet
            .get_account_balance(*account)
            .await
            .map_err(SdkError::Internal)
    }

    async fn propose_native_transfer(
        &self,
        session_id: &SessionId,
        from: AccountId,
        to: String,
        amount: u128,
    ) -> SdkResult<RequestId> {
        self.require_grant(session_id, &from, GrantKind::Propose)
            .await?;
        let to_account = self.resolve_destination(&to).await?;

        let request = PendingRequest::new(
            session_id.clone(),
            RequestKind::NativeTransfer {
                from,
                to: to_account,
                amount,
            },
        );
        let request_id = request.id.clone();

        let summary = ApprovalPrompt::auto_summary(&request);
        let effects =
            EffectSimulator::native_transfer(from, to_account, amount, wallet::DEFAULT_GAS_LIMIT);

        let verification = self
            .verifier
            .verify(&lee_core::native_token::NATIVE_TOKEN_PROGRAM_ID)
            .await;

        let prompt = ApprovalPrompt {
            request: request.clone(),
            summary,
            dapp_identity: self
                .sessions
                .get(session_id)
                .await
                .map(|s| s.caller_identity.clone())
                .unwrap_or_else(|| "unknown".into()),
            effects: Some(format!("{:?}", effects.source)),
            verification_status: Some(verification.to_string()),
            warnings: effects.warnings,
        };

        self.requests.insert(request).await;
        self.tx_queue
            .enqueue(crate::queue::QueueEntry {
                request_id: request_id.clone(),
                priority: 0,
            })
            .await;

        let handler = self.approval_handler.clone();
        let requests = self.requests.clone();
        let wallet = self.wallet.clone();
        let rid = request_id.clone();
        let timeout = self.config.approval_timeout;

        tokio::spawn(async move {
            let decision = handler.request_approval(prompt, timeout).await;
            match decision {
                ApprovalDecision::Approve => {
                    requests.set_status(&rid, RequestStatus::Approved).await;
                    let w = wallet.lock().await;
                    let facade =
                        wallet::program_facades::native_token_transfer::NativeTokenTransfer(&w);
                    match facade
                        .transfer(
                            wallet::AccountIdentity::Public(from),
                            wallet::AccountIdentity::PublicNoSign(to_account),
                            amount,
                            wallet::program_facades::CreditDelivery::Automatic,
                        )
                        .await
                    {
                        Ok((tx_hash, _secrets)) => {
                            requests
                                .set_status(&rid, RequestStatus::Submitted { tx_hash })
                                .await;
                        }
                        Err(e) => {
                            requests
                                .set_status(
                                    &rid,
                                    RequestStatus::Failed {
                                        reason: format!("{:?}", e),
                                    },
                                )
                                .await;
                        }
                    }
                }
                ApprovalDecision::Reject => {
                    requests.set_status(&rid, RequestStatus::Rejected).await;
                }
            }
        });

        Ok(request_id)
    }

    async fn propose_token_transfer(
        &self,
        session_id: &SessionId,
        from_holding: AccountId,
        to_holding: AccountId,
        definition: AccountId,
        amount: u128,
    ) -> SdkResult<RequestId> {
        self.require_grant(session_id, &from_holding, GrantKind::Propose)
            .await?;

        let request = PendingRequest::new(
            session_id.clone(),
            RequestKind::TokenTransfer {
                from_holding,
                to_holding,
                definition,
                amount,
            },
        );
        let request_id = request.id.clone();

        let summary = ApprovalPrompt::auto_summary(&request);
        let effects = EffectSimulator::token_transfer(
            from_holding,
            to_holding,
            definition,
            amount,
            wallet::DEFAULT_GAS_LIMIT,
        );

        let verification = self.verifier.verify(&definition).await;

        let prompt = ApprovalPrompt {
            request: request.clone(),
            summary,
            dapp_identity: self
                .sessions
                .get(session_id)
                .await
                .map(|s| s.caller_identity.clone())
                .unwrap_or_else(|| "unknown".into()),
            effects: Some(format!("{:?}", effects.source)),
            verification_status: Some(verification.to_string()),
            warnings: effects.warnings,
        };

        self.requests.insert(request).await;
        self.tx_queue
            .enqueue(crate::queue::QueueEntry {
                request_id: request_id.clone(),
                priority: 0,
            })
            .await;

        let handler = self.approval_handler.clone();
        let requests = self.requests.clone();
        let wallet = self.wallet.clone();
        let rid = request_id.clone();
        let timeout = self.config.approval_timeout;

        tokio::spawn(async move {
            let decision = handler.request_approval(prompt, timeout).await;
            match decision {
                ApprovalDecision::Approve => {
                    requests.set_status(&rid, RequestStatus::Approved).await;
                    let w = wallet.lock().await;
                    let accounts = vec![
                        wallet::AccountIdentity::Public(from_holding)
                            .select_program_actor_state(definition),
                        wallet::AccountIdentity::PublicNoSign(to_holding)
                            .select_program_actor_state(definition),
                    ];
                    let message = amount.to_le_bytes().to_vec();
                    match w.send_pub_tx(accounts, 0, message).await {
                        Ok(tx_hash) => {
                            requests
                                .set_status(&rid, RequestStatus::Submitted { tx_hash })
                                .await;
                        }
                        Err(e) => {
                            requests
                                .set_status(
                                    &rid,
                                    RequestStatus::Failed {
                                        reason: format!("{:?}", e),
                                    },
                                )
                                .await;
                        }
                    }
                }
                ApprovalDecision::Reject => {
                    requests.set_status(&rid, RequestStatus::Rejected).await;
                }
            }
        });

        Ok(request_id)
    }

    async fn propose_transaction(
        &self,
        session_id: &SessionId,
        mentions: Vec<AccountId>,
        calldata: Vec<u8>,
        description: Option<String>,
    ) -> SdkResult<RequestId> {
        if let Some(primary) = mentions.first() {
            self.require_grant(session_id, primary, GrantKind::Propose)
                .await?;
        } else {
            return Err(SdkError::InvalidArgument(
                "Transaction must mention at least one account".into(),
            ));
        }

        let request = PendingRequest::new(
            session_id.clone(),
            RequestKind::GenericCall {
                mentions: mentions.clone(),
                calldata: calldata.clone(),
                description,
            },
        );
        let request_id = request.id.clone();

        let decoded = mentions
            .first()
            .map(|primary| self.decoders.decode(primary, &calldata));

        let summary = if let Some(ref d) = decoded {
            if d.operation != "Unknown" {
                format!("{}: {}", d.program, d.operation)
            } else {
                ApprovalPrompt::auto_summary(&request)
            }
        } else {
            ApprovalPrompt::auto_summary(&request)
        };

        let effects_source = if let Some(ref d) = decoded {
            if d.operation != "Unknown" {
                format!("Decoded({})", d.operation)
            } else {
                format!(
                    "{:?}",
                    EffectSimulator::unavailable(wallet::DEFAULT_GAS_LIMIT).source
                )
            }
        } else {
            format!(
                "{:?}",
                EffectSimulator::unavailable(wallet::DEFAULT_GAS_LIMIT).source
            )
        };

        let verification = if let Some(primary) = mentions.first() {
            Some(self.verifier.verify(primary).await.to_string())
        } else {
            None
        };

        let prompt = ApprovalPrompt {
            request: request.clone(),
            summary,
            dapp_identity: self
                .sessions
                .get(session_id)
                .await
                .map(|s| s.caller_identity.clone())
                .unwrap_or_else(|| "unknown".into()),
            effects: Some(effects_source),
            verification_status: verification,
            warnings: vec![],
        };

        self.requests.insert(request).await;
        self.tx_queue
            .enqueue(crate::queue::QueueEntry {
                request_id: request_id.clone(),
                priority: 0,
            })
            .await;

        let handler = self.approval_handler.clone();
        let requests = self.requests.clone();
        let wallet = self.wallet.clone();
        let rid = request_id.clone();
        let timeout = self.config.approval_timeout;
        let mentions_to_send = mentions.clone();
        let calldata_to_send = calldata.clone();

        tokio::spawn(async move {
            let decision = handler.request_approval(prompt, timeout).await;
            match decision {
                ApprovalDecision::Approve => {
                    requests.set_status(&rid, RequestStatus::Approved).await;
                    let w = wallet.lock().await;
                    if let Some(primary) = mentions_to_send.first() {
                        let program = *primary;
                        let mut accounts = Vec::with_capacity(mentions_to_send.len());
                        for (idx, &acc) in mentions_to_send.iter().enumerate() {
                            if idx == 0 {
                                accounts.push(
                                    wallet::AccountIdentity::Public(acc)
                                        .select_program_actor_state(program),
                                );
                            } else {
                                accounts.push(
                                    wallet::AccountIdentity::PublicNoSign(acc)
                                        .select_program_actor_state(program),
                                );
                            }
                        }
                        match w.send_pub_tx(accounts, 0, calldata_to_send).await {
                            Ok(tx_hash) => {
                                requests
                                    .set_status(&rid, RequestStatus::Submitted { tx_hash })
                                    .await;
                            }
                            Err(e) => {
                                requests
                                    .set_status(
                                        &rid,
                                        RequestStatus::Failed {
                                            reason: format!("{:?}", e),
                                        },
                                    )
                                    .await;
                            }
                        }
                    }
                }
                ApprovalDecision::Reject => {
                    requests.set_status(&rid, RequestStatus::Rejected).await;
                }
            }
        });

        Ok(request_id)
    }

    async fn get_request_status(&self, request_id: &RequestId) -> SdkResult<RequestStatus> {
        self.requests
            .get_status(request_id)
            .await
            .ok_or_else(|| SdkError::RequestNotFound(request_id.clone()))
    }

    async fn cancel_request(&self, request_id: &RequestId) -> SdkResult<()> {
        let status = self.get_request_status(request_id).await?;
        if status == RequestStatus::PendingApproval {
            self.requests
                .set_status(request_id, RequestStatus::Cancelled)
                .await;
            Ok(())
        } else {
            Err(SdkError::RequestAlreadyFinalized)
        }
    }

    async fn resolve_name(
        &self,
        session_id: &SessionId,
        name: &str,
    ) -> SdkResult<crate::resolve::ResolvedDestination> {
        let _session = self.validate_session(session_id).await?;
        match self.resolver.resolve(name).await {
            Ok(Some(dest)) => Ok(dest),
            Ok(None) => Err(SdkError::InvalidArgument(format!(
                "'{}' is not a .lez name",
                name
            ))),
            Err(e) => Err(SdkError::NameResolutionError(e.to_string())),
        }
    }

    async fn request_identity_access(
        &self,
        session_id: &SessionId,
        kind: GrantKind,
    ) -> SdkResult<()> {
        let _ = self.validate_session(session_id).await?;
        if kind != GrantKind::IdentityRead && kind != GrantKind::IdentityPropose {
            return Err(SdkError::InvalidArgument(
                "Must specify IdentityRead or IdentityPropose".into(),
            ));
        }
        self.sessions
            .update(session_id, |s| {
                s.add_identity_grant(kind);
            })
            .await
            .ok_or_else(|| SdkError::SessionNotFound(session_id.clone()))?;
        Ok(())
    }

    async fn get_identity_commitment(
        &self,
        session_id: &SessionId,
    ) -> SdkResult<crate::identity::IdentityCommitment> {
        self.require_identity_grant(session_id, GrantKind::IdentityRead)
            .await?;
        let guard = self.identity_secret.lock().await;
        let secret = guard.as_ref().ok_or(SdkError::WalletLocked)?;
        Ok(crate::identity::derive_identity_commitment(secret))
    }

    async fn derive_scoped_nullifier(
        &self,
        session_id: &SessionId,
        scope_id: &str,
    ) -> SdkResult<crate::identity::ScopedNullifier> {
        self.require_identity_grant(session_id, GrantKind::IdentityRead)
            .await?;
        let guard = self.identity_secret.lock().await;
        let secret = guard.as_ref().ok_or(SdkError::WalletLocked)?;
        Ok(crate::identity::derive_scoped_nullifier(secret, scope_id))
    }

    async fn sign_identity_attestation(
        &self,
        session_id: &SessionId,
        scope_id: &str,
        message: &[u8],
    ) -> SdkResult<crate::identity::AttestationPayload> {
        self.require_identity_grant(session_id, GrantKind::IdentityPropose)
            .await?;
        let guard = self.identity_secret.lock().await;
        let secret = guard.as_ref().ok_or(SdkError::WalletLocked)?;
        crate::identity::sign_identity_attestation(secret, scope_id, message)
    }

    async fn prepare_identity_registration(
        &self,
        session_id: &SessionId,
        scope_id: &str,
        node_pubkeys: &[[u8; 32]],
        threshold_k: u8,
    ) -> SdkResult<crate::identity::RegistrationPayload> {
        self.require_identity_grant(session_id, GrantKind::IdentityPropose)
            .await?;
        let guard = self.identity_secret.lock().await;
        let secret = guard.as_ref().ok_or(SdkError::WalletLocked)?;
        crate::identity::prepare_identity_registration(secret, scope_id, node_pubkeys, threshold_k)
    }
}

impl OwnerApi for SdkEngine {
    async fn create_wallet(&self, password: &str) -> SdkResult<Mnemonic> {
        let config_path = self.config.wallet_config_path.clone();
        let storage_path = self.config.wallet_storage_path.clone();

        let (new_wallet, mnemonic) =
            WalletCore::new_init_storage(config_path, storage_path, None, password)
                .map_err(SdkError::Internal)?;

        let mut wallet = self.wallet.lock().await;
        *wallet = new_wallet;
        wallet.store_persistent_data().map_err(SdkError::Internal)?;

        let mut store = self.store.lock().await;
        let seed = mnemonic.to_seed(password);
        let identity = crate::identity::derive_identity_secret(&seed);
        *self.identity_secret.lock().await = Some(identity);

        store.state_mut().locked = false;
        store.save().map_err(SdkError::Internal)?;

        Ok(mnemonic)
    }

    async fn restore_wallet(&self, mnemonic: &Mnemonic, password: &str) -> SdkResult<()> {
        let mut wallet = self.wallet.lock().await;
        wallet.restore_storage(mnemonic);
        if !password.is_empty() {
            wallet.set_password(password).map_err(SdkError::Internal)?;
        }
        wallet.store_persistent_data().map_err(SdkError::Internal)?;

        let seed = mnemonic.to_seed(password);
        let identity = crate::identity::derive_identity_secret(&seed);
        *self.identity_secret.lock().await = Some(identity);

        let mut store = self.store.lock().await;
        store.state_mut().locked = false;
        store.save().map_err(SdkError::Internal)?;
        Ok(())
    }

    async fn lock(&self) -> SdkResult<()> {
        let sessions = self.sessions.list().await;
        for s in &sessions {
            self.sessions.revoke(&s.id).await;
        }
        *self.identity_secret.lock().await = None;
        let mut store = self.store.lock().await;
        store.state_mut().locked = true;
        store.save().map_err(SdkError::Internal)?;
        log::info!("Wallet locked, {} sessions revoked", sessions.len());
        Ok(())
    }

    async fn unlock(&self, password: &str) -> SdkResult<()> {
        let storage_path = &self.config.wallet_storage_path;
        if storage_path.exists()
            && wallet::storage::Storage::from_path(storage_path, password).is_err()
        {
            return Err(SdkError::InvalidPassword);
        }
        let mut store = self.store.lock().await;
        store.state_mut().locked = false;
        store.save().map_err(SdkError::Internal)?;
        Ok(())
    }

    async fn create_account_public(&self, label: Option<String>) -> SdkResult<AccountId> {
        {
            let store = self.store.lock().await;
            if store.state().locked {
                return Err(SdkError::WalletLocked);
            }
        }
        let mut wallet = self.wallet.lock().await;
        let (account_id, _chain_index) = wallet.create_new_account_public(None);

        if let Some(label_str) = label {
            let _ = wallet.storage_mut().add_label(
                Label::new(label_str),
                AccountIdWithPrivacy::Public(account_id),
            );
            wallet.store_persistent_data().map_err(SdkError::Internal)?;
        }
        Ok(account_id)
    }

    async fn create_account_private(&self, label: Option<String>) -> SdkResult<AccountId> {
        {
            let store = self.store.lock().await;
            if store.state().locked {
                return Err(SdkError::WalletLocked);
            }
        }
        let mut wallet = self.wallet.lock().await;
        let (account_id, _chain_index) = wallet.create_new_account_private(None);

        if let Some(label_str) = label {
            let _ = wallet.storage_mut().add_label(
                Label::new(label_str),
                AccountIdWithPrivacy::Private(account_id),
            );
            wallet.store_persistent_data().map_err(SdkError::Internal)?;
        }
        Ok(account_id)
    }

    async fn list_all_accounts(&self) -> SdkResult<Vec<AccountView>> {
        let wallet = self.wallet.lock().await;
        // Use the key chain to enumerate all accounts
        let key_chain = wallet.storage().key_chain();
        let public_accounts = key_chain.public_account_ids();

        let mut views = Vec::new();
        for (account_id, _) in public_accounts {
            let balance = wallet.get_account_balance(account_id).await.ok();
            // Try to find a label via resolve
            let label_text = wallet
                .storage()
                .labels_for_account(AccountIdWithPrivacy::Public(account_id))
                .next()
                .map(|l| l.as_ref().to_string());
            views.push(AccountView {
                account_id,
                privacy: AccountPrivacy::Public,
                label: label_text,
                balance,
            });
        }

        let private_accounts = key_chain.private_account_ids();
        for (account_id, _) in private_accounts {
            let label_text = wallet
                .storage()
                .labels_for_account(AccountIdWithPrivacy::Private(account_id))
                .next()
                .map(|l| l.as_ref().to_string());
            views.push(AccountView {
                account_id,
                privacy: AccountPrivacy::Private,
                label: label_text,
                balance: None,
            });
        }

        Ok(views)
    }

    async fn list_sessions(&self) -> SdkResult<Vec<crate::session::Session>> {
        Ok(self.sessions.list().await)
    }

    async fn revoke_session(&self, session_id: &SessionId) -> SdkResult<()> {
        if self.sessions.revoke(session_id).await {
            Ok(())
        } else {
            Err(SdkError::SessionNotFound(session_id.clone()))
        }
    }
}

fn parse_account_id(input: &str) -> SdkResult<AccountId> {
    input
        .parse::<AccountId>()
        .map_err(|e| SdkError::InvalidArgument(format!("invalid account id '{}': {}", input, e)))
}
