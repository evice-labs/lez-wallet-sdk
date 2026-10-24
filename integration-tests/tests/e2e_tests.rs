use integration_tests::harness::{MockApprovalHandler, TestEnv};
use sdk_engine::SdkEngine;
use sdk_engine::api::{AccountPrivacy, DAppApi, OwnerApi};
use sdk_engine::approval::ApprovalDecision;
use sdk_engine::session::GrantKind;
use sdk_ffi::*;
use std::ffi::{CStr, CString};
use std::sync::Arc;

#[tokio::test]
async fn test_wallet_lifecycle_and_account_derivation() {
    let env = TestEnv::new();
    let handler = Arc::new(MockApprovalHandler::new(ApprovalDecision::Approve));

    // Initialize engine with clean temporary storage
    let engine = SdkEngine::open_or_init(env.data_dir.clone(), "testpass_master_123", handler)
        .expect("failed to initialize wallet engine");

    let _mnemonic = engine
        .create_wallet("testpass_master_123")
        .await
        .expect("failed to create wallet");

    // Check SDK info
    let info = engine.sdk_info().await.expect("failed to get sdk info");
    assert_eq!(info.api_version, sdk_engine::API_VERSION);
    assert!(info.wallet_initialized);
    assert!(!info.wallet_locked);

    // Derive public account
    let pub_acc = engine
        .create_account_public(None)
        .await
        .expect("failed to derive public account");

    // Derive private shielded account
    let priv_acc = engine
        .create_account_private(Some("E2E Shielded Pool".to_string()))
        .await
        .expect("failed to derive private account");

    // Verify both accounts are listed
    let accounts = engine
        .list_all_accounts()
        .await
        .expect("failed to list accounts");
    assert!(
        accounts
            .iter()
            .any(|a| a.account_id == pub_acc && a.privacy == AccountPrivacy::Public)
    );
    assert!(
        accounts
            .iter()
            .any(|a| a.account_id == priv_acc && a.privacy == AccountPrivacy::Private)
    );

    // Update label
    engine
        .set_account_label(pub_acc, "Renamed Treasury".to_string(), false)
        .await
        .expect("failed to rename account");
    let updated = engine
        .list_all_accounts()
        .await
        .expect("failed to list accounts");
    let found = updated.iter().find(|a| a.account_id == pub_acc).unwrap();
    assert_eq!(found.label.as_deref(), Some("Renamed Treasury"));

    // Lock the wallet
    engine.lock().await.expect("failed to lock wallet");
    let locked_info = engine.sdk_info().await.expect("failed to get sdk info");
    assert!(locked_info.wallet_locked);

    // Operations requiring private keys should fail when locked
    let err = engine.create_account_public(None).await;
    assert!(err.is_err());

    // Security check: Unlock wallet with WRONG password must fail with InvalidPassword
    let bad_unlock = engine.unlock("wrong_password_xyz").await;
    assert!(
        matches!(
            bad_unlock,
            Err(sdk_engine::error::SdkError::InvalidPassword)
        ),
        "unlock with wrong password must return InvalidPassword error, got: {:?}",
        bad_unlock
    );
    let still_locked_info = engine.sdk_info().await.expect("failed to get sdk info");
    assert!(still_locked_info.wallet_locked);

    // Unlock wallet with correct password
    engine
        .unlock("testpass_master_123")
        .await
        .expect("failed to unlock wallet");
    let unlocked_info = engine.sdk_info().await.expect("failed to get sdk info");
    assert!(!unlocked_info.wallet_locked);

    // Verify accounts persist after unlock
    let post_unlock_accs = engine
        .list_all_accounts()
        .await
        .expect("failed to list accounts post-unlock");
    assert!(post_unlock_accs.len() >= 2);
    assert!(post_unlock_accs.iter().any(|a| a.account_id == pub_acc));
    assert!(post_unlock_accs.iter().any(|a| a.account_id == priv_acc));
}

#[tokio::test]
async fn test_dapp_session_and_granular_grants() {
    let env = TestEnv::new();
    let handler = Arc::new(MockApprovalHandler::new(ApprovalDecision::Approve));
    let engine = SdkEngine::open_or_init(env.data_dir.clone(), "testpass_master_123", handler)
        .expect("failed to initialize wallet engine");

    let alice = engine
        .create_account_public(Some("Alice".to_string()))
        .await
        .expect("failed to derive alice");
    let bob = engine
        .create_account_public(Some("Bob".to_string()))
        .await
        .expect("failed to derive bob");

    // Connect dApp
    let session_id = engine
        .connect("dex.lez".to_string(), 1)
        .await
        .expect("failed to connect dApp");

    // Without grants, listing authorized accounts should be empty
    let initial_accounts = engine
        .list_accounts(&session_id)
        .await
        .expect("failed to list dApp accounts");
    assert!(initial_accounts.is_empty());

    // Balance query without Read grant must fail
    let bal_err = engine.get_balance(&session_id, &alice).await;
    assert!(bal_err.is_err());

    // Transfer proposal without Propose grant must fail
    let prop_err = engine
        .propose_native_transfer(&session_id, alice, bob.to_string(), 500)
        .await;
    assert!(prop_err.is_err());

    // Issue Read grant for Alice
    engine
        .grant_account(&session_id, alice, GrantKind::Read)
        .await
        .expect("failed to issue read grant");

    // Now balance query succeeds
    let balance = engine
        .get_balance(&session_id, &alice)
        .await
        .expect("failed to get balance with read grant");
    assert_eq!(balance, 0);

    // But transfer proposal still fails (needs Propose grant)
    let prop_err2 = engine
        .propose_native_transfer(&session_id, alice, bob.to_string(), 500)
        .await;
    assert!(prop_err2.is_err());

    // Issue Propose grant for Alice
    engine
        .grant_account(&session_id, alice, GrantKind::Propose)
        .await
        .expect("failed to issue propose grant");

    // Propose transfer now succeeds, producing RequestId
    let request_id = engine
        .propose_native_transfer(&session_id, alice, bob.to_string(), 500)
        .await
        .expect("failed to propose transfer with propose grant");

    // Check request status
    let status = engine
        .get_request_status(&request_id)
        .await
        .expect("failed to query request status");
    // Under mock approve handler, it will transition
    assert!(matches!(
        status,
        sdk_engine::RequestStatus::PendingApproval
            | sdk_engine::RequestStatus::Approved
            | sdk_engine::RequestStatus::Failed { .. }
    ));

    // Revoke session
    engine
        .revoke_session(&session_id)
        .await
        .expect("failed to revoke session");

    // Operations after revocation must fail
    let post_revoke_err = engine.get_balance(&session_id, &alice).await;
    assert!(post_revoke_err.is_err());
}

#[tokio::test]
async fn test_identity_accountability_scoped_nullifiers() {
    let env = TestEnv::new();
    let handler = Arc::new(MockApprovalHandler::new(ApprovalDecision::Approve));
    let engine = SdkEngine::open_or_init(env.data_dir.clone(), "testpass_master_123", handler)
        .expect("failed to initialize wallet engine");

    let _mnemonic = engine
        .create_wallet("testpass_master_123")
        .await
        .expect("failed to create wallet");

    let session_id = engine
        .connect("forum.lez".to_string(), 1)
        .await
        .expect("failed to connect");

    // Request IdentityRead grant
    engine
        .request_identity_access(&session_id, GrantKind::IdentityRead)
        .await
        .expect("failed to request identity access");

    // Retrieve master commitment
    let commitment = engine
        .get_identity_commitment(&session_id)
        .await
        .expect("failed to get identity commitment");
    assert_eq!(commitment.0.len(), 32);

    // Derive scoped nullifier for Governance Alpha
    let nullifier_alpha = engine
        .derive_scoped_nullifier(&session_id, "governance_alpha")
        .await
        .expect("failed to derive alpha nullifier");

    // Derive scoped nullifier for Governance Beta
    let nullifier_beta = engine
        .derive_scoped_nullifier(&session_id, "governance_beta")
        .await
        .expect("failed to derive beta nullifier");

    // Cross-dApp Unlinkability Guarantee: different scopes must produce different nullifiers
    assert_ne!(nullifier_alpha, nullifier_beta);

    // Determinism Guarantee: same scope must produce identical nullifier
    let nullifier_alpha_repeat = engine
        .derive_scoped_nullifier(&session_id, "governance_alpha")
        .await
        .expect("failed to re-derive alpha nullifier");
    assert_eq!(nullifier_alpha, nullifier_alpha_repeat);

    // Request IdentityPropose grant for attestation signing and SSS
    engine
        .request_identity_access(&session_id, GrantKind::IdentityPropose)
        .await
        .expect("failed to request propose grant");

    // Sign BIP-340 Schnorr attestation
    let attestation = engine
        .sign_identity_attestation(&session_id, "governance_alpha", b"vote_ballot_proposal_42")
        .await
        .expect("failed to sign identity attestation");
    assert_eq!(attestation.signature.len(), 64);

    // Two-Tier Shamir Secret Sharing registration payload
    let sk1 = sdk_engine::identity::generate_ephemeral_scalar();
    let pk1 = sdk_engine::identity::derive_xonly_pubkey(&sk1);
    let sk2 = sdk_engine::identity::generate_ephemeral_scalar();
    let pk2 = sdk_engine::identity::derive_xonly_pubkey(&sk2);
    let sk3 = sdk_engine::identity::generate_ephemeral_scalar();
    let pk3 = sdk_engine::identity::derive_xonly_pubkey(&sk3);
    let trustee_pubkeys = vec![pk1, pk2, pk3];
    let reg_payload = engine
        .prepare_identity_registration(&session_id, "community_council", &trustee_pubkeys, 2)
        .await
        .expect("failed to prepare SSS registration");
    assert_eq!(reg_payload.threshold_k, 2);
    assert_eq!(reg_payload.encrypted_shares.len(), 3);
}

unsafe extern "C" fn mock_e2e_approval_cb(
    _prompt_json: *const std::os::raw::c_char,
    _user_data: *mut std::ffi::c_void,
) -> i32 {
    -1 // deferred modal
}

#[test]
fn test_ffi_c_abi_end_to_end_lifecycle() {
    let env = TestEnv::new();
    let path_str = CString::new(env.data_dir.to_str().unwrap()).unwrap();

    let engine = unsafe { lez_wallet_engine_new(path_str.as_ptr()) };
    assert!(!engine.is_null());

    // Register callback
    let cb_res = unsafe {
        lez_wallet_set_approval_callback(engine, mock_e2e_approval_cb, std::ptr::null_mut())
    };
    unsafe { lez_wallet_free_string(cb_res) };

    // Create wallet via FFI
    let pass = CString::new("testpass_ffi_123").unwrap();
    let res_ptr = unsafe { lez_wallet_create_wallet(engine, pass.as_ptr()) };
    let res_str = unsafe { CStr::from_ptr(res_ptr) }.to_str().unwrap();
    let res_json: serde_json::Value = serde_json::from_str(res_str).unwrap();
    assert_eq!(res_json["ok"], true);
    unsafe { lez_wallet_free_string(res_ptr) };

    // Create sender and recipient
    let l_alice = CString::new("Alice FFI").unwrap();
    let alice_ptr = unsafe { lez_wallet_create_account_public(engine, l_alice.as_ptr()) };
    let alice_str = unsafe { CStr::from_ptr(alice_ptr) }.to_str().unwrap();
    let alice_json: serde_json::Value = serde_json::from_str(alice_str).unwrap();
    let alice_acc = alice_json["account_id"].as_str().unwrap().to_string();
    unsafe { lez_wallet_free_string(alice_ptr) };

    let l_bob = CString::new("Bob FFI").unwrap();
    let bob_ptr = unsafe { lez_wallet_create_account_public(engine, l_bob.as_ptr()) };
    let bob_str = unsafe { CStr::from_ptr(bob_ptr) }.to_str().unwrap();
    let bob_json: serde_json::Value = serde_json::from_str(bob_str).unwrap();
    let bob_acc = bob_json["account_id"].as_str().unwrap().to_string();
    unsafe { lez_wallet_free_string(bob_ptr) };

    // Connect dApp
    let caller = CString::new("e2e_dapp").unwrap();
    let conn_ptr = unsafe { lez_wallet_connect(engine, caller.as_ptr(), 1) };
    let conn_str = unsafe { CStr::from_ptr(conn_ptr) }.to_str().unwrap();
    let conn_json: serde_json::Value = serde_json::from_str(conn_str).unwrap();
    let sid = conn_json["session_id"].as_str().unwrap().to_string();
    unsafe { lez_wallet_free_string(conn_ptr) };

    // Grant propose
    let sid_cstr = CString::new(sid).unwrap();
    let alice_cstr = CString::new(alice_acc).unwrap();
    let grant_cstr = CString::new("propose").unwrap();
    let g_ptr = unsafe {
        lez_wallet_grant_account(
            engine,
            sid_cstr.as_ptr(),
            alice_cstr.as_ptr(),
            grant_cstr.as_ptr(),
        )
    };
    unsafe { lez_wallet_free_string(g_ptr) };

    // Propose transfer
    let bob_cstr = CString::new(bob_acc).unwrap();
    let amt_cstr = CString::new("1000").unwrap();
    let prop_ptr = unsafe {
        lez_wallet_propose_native_transfer(
            engine,
            sid_cstr.as_ptr(),
            alice_cstr.as_ptr(),
            bob_cstr.as_ptr(),
            amt_cstr.as_ptr(),
        )
    };
    let prop_str = unsafe { CStr::from_ptr(prop_ptr) }.to_str().unwrap();
    let prop_json: serde_json::Value = serde_json::from_str(prop_str).unwrap();
    assert_eq!(prop_json["ok"], true);
    let req_id = prop_json["request_id"].as_str().unwrap().to_string();
    unsafe { lez_wallet_free_string(prop_ptr) };

    std::thread::sleep(std::time::Duration::from_millis(50));

    // Submit user decision: 0 (Reject)
    let req_cstr = CString::new(req_id.clone()).unwrap();
    let dec_ptr = unsafe { lez_wallet_submit_approval_decision(engine, req_cstr.as_ptr(), 0) };
    let dec_str = unsafe { CStr::from_ptr(dec_ptr) }.to_str().unwrap();
    let dec_json: serde_json::Value = serde_json::from_str(dec_str).unwrap();
    assert_eq!(dec_json["ok"], true);
    unsafe { lez_wallet_free_string(dec_ptr) };

    std::thread::sleep(std::time::Duration::from_millis(50));

    // Verify rejection status
    let status_ptr = unsafe { lez_wallet_get_request_status(engine, req_cstr.as_ptr()) };
    let status_str = unsafe { CStr::from_ptr(status_ptr) }.to_str().unwrap();
    let status_json: serde_json::Value = serde_json::from_str(status_str).unwrap();
    assert_eq!(status_json["ok"], true);
    assert_eq!(status_json["status"], "rejected");
    unsafe { lez_wallet_free_string(status_ptr) };

    // Free engine
    unsafe { lez_wallet_engine_free(engine) };
}

#[tokio::test]
async fn test_security_flaws_and_access_control() {
    let env = TestEnv::new();
    let handler = Arc::new(MockApprovalHandler::new(ApprovalDecision::Approve));
    let engine = SdkEngine::open_or_init(
        env.data_dir.clone(),
        "correct_master_pass_123",
        handler.clone(),
    )
    .expect("failed to initialize wallet engine");

    let _mnemonic = engine
        .create_wallet("correct_master_pass_123")
        .await
        .expect("failed to create wallet");

    let alice = engine
        .create_account_public(Some("Alice Safe".to_string()))
        .await
        .expect("failed to derive alice");
    let bob = engine
        .create_account_public(Some("Bob Safe".to_string()))
        .await
        .expect("failed to derive bob");

    // 1. Password Verification Security
    engine.lock().await.expect("failed to lock");

    // Test multiple wrong password permutations
    for bad_pwd in &[
        "",
        "wrong",
        "correct_master_pass",
        "correct_master_pass_1234",
    ] {
        let res = engine.unlock(bad_pwd).await;
        assert!(
            matches!(res, Err(sdk_engine::error::SdkError::InvalidPassword)),
            "unlock with '{}' must return InvalidPassword, got {:?}",
            bad_pwd,
            res
        );
        let info = engine.sdk_info().await.expect("info");
        assert!(
            info.wallet_locked,
            "wallet must remain locked after failed attempt"
        );
    }

    // Unlock with correct password
    engine
        .unlock("correct_master_pass_123")
        .await
        .expect("unlock with correct password must succeed");

    // 2. Granular Grant Boundary & Privilege Escalation Protection
    let session_id = engine
        .connect("untrusted_dapp.lez".to_string(), 1)
        .await
        .expect("connect dApp");

    // Attempt calling identity API without grant -> must fail
    let id_err = engine.get_identity_commitment(&session_id).await;
    assert!(matches!(
        id_err,
        Err(sdk_engine::error::SdkError::InsufficientGrant)
    ));

    let null_err = engine.derive_scoped_nullifier(&session_id, "scope_a").await;
    assert!(matches!(
        null_err,
        Err(sdk_engine::error::SdkError::InsufficientGrant)
    ));

    // Attempt signing attestation with only IdentityRead -> must fail (requires IdentityPropose)
    engine
        .request_identity_access(&session_id, GrantKind::IdentityRead)
        .await
        .expect("grant IdentityRead");
    let sign_err = engine
        .sign_identity_attestation(&session_id, "scope_a", b"malicious_message")
        .await;
    assert!(matches!(
        sign_err,
        Err(sdk_engine::error::SdkError::InsufficientGrant)
    ));

    // 3. Program Verification & Transaction Inspection
    engine
        .grant_account(&session_id, alice, GrantKind::Propose)
        .await
        .expect("grant propose");

    let req_id = engine
        .propose_native_transfer(&session_id, alice, bob.to_string(), 250)
        .await
        .expect("propose native transfer");

    tokio::time::sleep(std::time::Duration::from_millis(50)).await;

    // Verify approval prompt carries verification status
    let prompts = handler.recorded_prompts().await;
    assert!(!prompts.is_empty());
    let last_prompt = prompts.last().unwrap();
    assert!(
        last_prompt
            .verification_status
            .as_deref()
            .unwrap_or_default()
            .contains("Verified"),
        "Native token transfer must be recognized as Verified, got: {:?}",
        last_prompt.verification_status
    );

    // Verify request ID matches
    assert_eq!(last_prompt.request.id, req_id);

    // 4. Session Revocation Security
    engine
        .revoke_session(&session_id)
        .await
        .expect("revoke session");

    // Post-revocation access is completely blocked
    let post_rev_bal = engine.get_balance(&session_id, &alice).await;
    assert!(matches!(
        post_rev_bal,
        Err(sdk_engine::error::SdkError::SessionNotFound(_))
    ));
}

#[tokio::test]
async fn test_lns_name_resolution_and_ffi_safety() {
    let env = TestEnv::new();
    let handler = Arc::new(MockApprovalHandler::new(ApprovalDecision::Approve));
    let engine = SdkEngine::open_or_init(env.data_dir.clone(), "testpass_lns_123", handler)
        .expect("failed to initialize wallet engine");

    let alice = engine
        .create_account_public(Some("Alice".to_string()))
        .await
        .expect("create alice");

    let session_id = engine
        .connect("test_resolver.lez".to_string(), 1)
        .await
        .expect("connect");

    // 1. Invalid Name Format Rejections (SPEC §2)
    let invalid_names = [
        "-leading-hyphen.lez",
        "trailing-hyphen-.lez",
        ".lez",
        "has space.lez",
        "UPPER!.lez",
    ];
    for invalid in &invalid_names {
        let res = engine.resolve_name(&session_id, invalid).await;
        assert!(res.is_err(), "Invalid name '{}' must be rejected", invalid);
    }

    // Bare name without .lez passed to resolve_name directly must return InvalidArgument
    let bare_res = engine.resolve_name(&session_id, "bob").await;
    assert!(
        matches!(
            bare_res,
            Err(sdk_engine::error::SdkError::InvalidArgument(_))
        ),
        "Bare name without .lez must return InvalidArgument"
    );

    // Unregistered name on testnet must return NameResolutionError
    let unreg_res = engine
        .resolve_name(&session_id, "definitely-unregistered-xyz999.lez")
        .await;
    assert!(
        matches!(
            unreg_res,
            Err(sdk_engine::error::SdkError::NameResolutionError(_))
        ),
        "Unregistered name must return NameResolutionError"
    );

    // 2. Transfer to Unregistered LNS Name Must Be Rejected Before Transaction Creation
    engine
        .grant_account(&session_id, alice, GrantKind::Propose)
        .await
        .expect("grant propose");

    let transfer_unreg = engine
        .propose_native_transfer(
            &session_id,
            alice,
            "definitely-unregistered-xyz999.lez".to_string(),
            100,
        )
        .await;
    assert!(
        matches!(
            transfer_unreg,
            Err(sdk_engine::error::SdkError::NameResolutionError(_))
        ),
        "Transfer to unregistered .lez name must fail without proposing a transaction"
    );
}

#[test]
fn test_lns_ffi_c_abi_safety() {
    let ffi_env = TestEnv::new();
    let path_str = CString::new(ffi_env.data_dir.to_str().unwrap()).unwrap();
    let ffi_engine = unsafe { lez_wallet_engine_new(path_str.as_ptr()) };
    assert!(!ffi_engine.is_null());

    let name = CString::new("alice.lez").unwrap();
    let sess = CString::new("mock_session_id").unwrap();

    // 1. Null engine pointer safety
    let null_ptr_res =
        unsafe { lez_wallet_resolve_name(std::ptr::null_mut(), sess.as_ptr(), name.as_ptr()) };
    let null_res_str = unsafe { CStr::from_ptr(null_ptr_res) }.to_str().unwrap();
    let null_res_json: serde_json::Value = serde_json::from_str(null_res_str).unwrap();
    assert_eq!(null_res_json["ok"], false);
    assert_eq!(null_res_json["error"], "Null engine handle");
    unsafe { lez_wallet_free_string(null_ptr_res) };

    // 2. Null parameter pointers safety
    let null_param_res =
        unsafe { lez_wallet_resolve_name(ffi_engine, std::ptr::null(), name.as_ptr()) };
    let null_param_str = unsafe { CStr::from_ptr(null_param_res) }.to_str().unwrap();
    let null_param_json: serde_json::Value = serde_json::from_str(null_param_str).unwrap();
    assert_eq!(null_param_json["ok"], false);
    unsafe { lez_wallet_free_string(null_param_res) };

    // 3. Invalid/unauthorized session call safety
    let uninit_res = unsafe { lez_wallet_resolve_name(ffi_engine, sess.as_ptr(), name.as_ptr()) };
    let uninit_str = unsafe { CStr::from_ptr(uninit_res) }.to_str().unwrap();
    let uninit_json: serde_json::Value = serde_json::from_str(uninit_str).unwrap();
    assert_eq!(uninit_json["ok"], false);
    unsafe { lez_wallet_free_string(uninit_res) };

    unsafe { lez_wallet_engine_free(ffi_engine) };
}
