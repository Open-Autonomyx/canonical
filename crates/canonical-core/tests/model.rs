//! The trust model, end to end, through the public API of canonical-core.

use canonical_core::*;

fn echo_core() -> (Core, Core, String) {
    let alice = Core::create().unwrap();
    let mut bob = Core::create().unwrap();
    bob.expose("tool/echo", |payload| {
        let mut m = std::collections::BTreeMap::new();
        m.insert("echo".to_string(), payload);
        Json::Obj(m)
    });
    let echo = bob.resource("tool/echo");
    (alice, bob, echo)
}

fn invoke(
    from: &Signer,
    to: &str,
    resource: &str,
    payload: Json,
    grant: Option<CorsGrant>,
) -> Message {
    compose(
        from,
        ComposeParams {
            to,
            action: "invoke",
            resource,
            payload,
            grant,
        },
        now_ms(),
    )
    .unwrap()
}

#[test]
fn denies_without_a_contract_origin_grants_nothing() {
    let (alice, mut bob, echo) = echo_core();
    let msg = invoke(alice.signer(), bob.id(), &echo, Json::Int(1), None);
    let out = bob.handle(&msg);
    assert!(!out.decision.ok);
}

#[test]
fn allows_with_provider_contract_and_runs_handler() {
    let (alice, mut bob, echo) = echo_core();
    let grant = bob.share(alice.id(), "tool/echo", "invoke", vec![]);
    let msg = invoke(
        alice.signer(),
        bob.id(),
        &echo,
        Json::str("hi"),
        Some(grant),
    );
    let out = bob.handle(&msg);
    assert!(out.decision.ok, "{:?}", out.decision.reason);
    match out.result {
        Some(Json::Obj(m)) => assert!(matches!(m.get("echo"), Some(Json::Str(s)) if s == "hi")),
        other => panic!("unexpected result: {other:?}"),
    }
}

#[test]
fn attenuated_delegation_narrows_and_is_accepted() {
    let (alice, mut bob, echo) = echo_core();
    let carol = Core::create().unwrap();
    let grant = bob.share(alice.id(), "tool/echo", "invoke", vec![]);
    let sub = attenuate(
        alice.signer(),
        &grant,
        carol.id(),
        None,
        None,
        vec![],
        now_ms(),
    );
    let msg = invoke(
        carol.signer(),
        bob.id(),
        &echo,
        Json::str("via carol"),
        Some(sub),
    );
    assert!(bob.handle(&msg).decision.ok);
}

#[test]
fn delegation_cannot_widen() {
    let (alice, mut bob, _echo) = echo_core();
    let carol = Core::create().unwrap();
    let grant = bob.share(alice.id(), "tool/echo", "invoke", vec![]);
    let wide = bob.resource("tool/*");
    let widened = attenuate(
        alice.signer(),
        &grant,
        carol.id(),
        None,
        Some(&wide),
        vec![],
        now_ms(),
    );
    let secret = bob.resource("tool/secret");
    let msg = invoke(
        carol.signer(),
        bob.id(),
        &secret,
        Json::str("x"),
        Some(widened),
    );
    assert!(!bob.handle(&msg).decision.ok);
}

#[test]
fn replay_is_rejected() {
    let (alice, mut bob, echo) = echo_core();
    let grant = bob.share(alice.id(), "tool/echo", "invoke", vec![]);
    let msg = invoke(
        alice.signer(),
        bob.id(),
        &echo,
        Json::str("hi"),
        Some(grant),
    );
    assert!(bob.handle(&msg).decision.ok);
    assert!(!bob.handle(&msg).decision.ok);
}

#[test]
fn tampered_message_is_rejected() {
    let (alice, mut bob, echo) = echo_core();
    let grant = bob.share(alice.id(), "tool/echo", "invoke", vec![]);
    let mut msg = invoke(
        alice.signer(),
        bob.id(),
        &echo,
        Json::str("hi"),
        Some(grant),
    );
    msg.payload = Json::str("tampered");
    assert!(!bob.handle(&msg).decision.ok);
}

#[test]
fn contract_minted_for_someone_else_is_rejected() {
    let (alice, mut bob, echo) = echo_core();
    let mallory = Core::create().unwrap();
    let grant = bob.share(mallory.id(), "tool/echo", "invoke", vec![]); // not for alice
    let msg = invoke(
        alice.signer(),
        bob.id(),
        &echo,
        Json::str("hi"),
        Some(grant),
    );
    assert!(!bob.handle(&msg).decision.ok);
}

#[test]
fn message_aimed_at_the_wrong_edge_is_rejected() {
    let (alice, bob, echo) = echo_core();
    let mut other = Core::create().unwrap();
    let grant = bob.share(alice.id(), "tool/echo", "invoke", vec![]);
    let msg = invoke(
        alice.signer(),
        bob.id(),
        &echo,
        Json::str("hi"),
        Some(grant),
    );
    assert!(!other.handle(&msg).decision.ok);
}

#[test]
fn expiry_caveat_is_enforced_fail_closed() {
    let owner = Signer::generate().unwrap();
    let sub = Signer::generate().unwrap();
    let resource = make_resource(&owner.id, "x");
    let grant = issue_grant(
        &owner,
        IssueParams {
            subject: &sub.id,
            action: "invoke",
            resource: &resource,
            caveats: vec![Caveat::expiry(1000)],
            proof: None,
        },
        500,
    );
    assert!(verify_grant(&grant, &owner.id, 500).ok);
    assert!(!verify_grant(&grant, &owner.id, 2000).ok);
}

#[test]
fn unknown_caveat_fails_closed() {
    let owner = Signer::generate().unwrap();
    let sub = Signer::generate().unwrap();
    let resource = make_resource(&owner.id, "x");
    let grant = issue_grant(
        &owner,
        IssueParams {
            subject: &sub.id,
            action: "invoke",
            resource: &resource,
            caveats: vec![Caveat::unknown("from-the-future")],
            proof: None,
        },
        0,
    );
    assert!(!verify_grant(&grant, &owner.id, 0).ok);
}

#[test]
fn not_before_caveat_is_enforced() {
    let owner = Signer::generate().unwrap();
    let sub = Signer::generate().unwrap();
    let resource = make_resource(&owner.id, "x");
    let grant = issue_grant(
        &owner,
        IssueParams {
            subject: &sub.id,
            action: "invoke",
            resource: &resource,
            caveats: vec![Caveat::not_before(1000)],
            proof: None,
        },
        0,
    );
    assert!(!verify_grant(&grant, &owner.id, 500).ok); // not yet valid
    assert!(verify_grant(&grant, &owner.id, 1500).ok); // now valid
}

#[test]
fn revoking_a_contract_denies_further_use() {
    let (alice, mut bob, echo) = echo_core();
    let grant = bob.share(alice.id(), "tool/echo", "invoke", vec![]);
    let first = invoke(
        alice.signer(),
        bob.id(),
        &echo,
        Json::str("hi"),
        Some(grant.clone()),
    );
    assert!(bob.handle(&first).decision.ok);

    bob.revoke(&grant);
    let second = invoke(
        alice.signer(),
        bob.id(),
        &echo,
        Json::str("hi"),
        Some(grant),
    );
    let out = bob.handle(&second);
    assert!(!out.decision.ok);
    assert_eq!(out.decision.reason.as_deref(), Some("contract revoked"));
}

#[test]
fn revoking_a_parent_invalidates_its_delegations() {
    let (alice, mut bob, echo) = echo_core();
    let carol = Core::create().unwrap();
    let parent = bob.share(alice.id(), "tool/echo", "invoke", vec![]);
    let sub = attenuate(
        alice.signer(),
        &parent,
        carol.id(),
        None,
        None,
        vec![],
        now_ms(),
    );

    // revoke the parent; the delegated sub-contract must stop working too
    bob.revoke(&parent);
    let msg = invoke(
        carol.signer(),
        bob.id(),
        &echo,
        Json::str("via carol"),
        Some(sub),
    );
    assert!(!bob.handle(&msg).decision.ok);
}

#[test]
fn subtree_grant_does_not_cover_sibling_paths() {
    let (alice, mut bob, _echo) = echo_core();
    // a grant for the "tool/*" subtree must not reach a sibling like "toolbox/secret"
    let grant = bob.share(alice.id(), "tool/*", "invoke", vec![]);
    let sibling = bob.resource("toolbox/secret");
    let msg = invoke(
        alice.signer(),
        bob.id(),
        &sibling,
        Json::str("x"),
        Some(grant.clone()),
    );
    assert!(!bob.handle(&msg).decision.ok);

    // but it does cover a real child under "tool/"
    let child = bob.resource("tool/echo");
    let msg = invoke(
        alice.signer(),
        bob.id(),
        &child,
        Json::str("ok"),
        Some(grant),
    );
    assert!(bob.handle(&msg).decision.ok);
}

#[test]
fn extreme_timestamp_is_denied_not_panicked() {
    let (alice, mut bob, echo) = echo_core();
    let grant = bob.share(alice.id(), "tool/echo", "invoke", vec![]);
    // a signed but absurd issuedAt must fail closed, never overflow/panic the edge
    let msg = compose(
        alice.signer(),
        ComposeParams {
            to: bob.id(),
            action: "invoke",
            resource: &echo,
            payload: Json::str("x"),
            grant: Some(grant),
        },
        i64::MIN,
    )
    .unwrap();
    let out = bob.handle(&msg);
    assert!(!out.decision.ok);
    assert_eq!(
        out.decision.reason.as_deref(),
        Some("message outside freshness window")
    );
}

#[test]
fn contract_not_rooted_at_provider_is_rejected() {
    let owner = Signer::generate().unwrap();
    let stranger = Signer::generate().unwrap();
    let sub = Signer::generate().unwrap();
    let resource = make_resource(&owner.id, "tool/echo");
    // stranger signs a grant for a resource they do not own
    let grant = issue_grant(
        &stranger,
        IssueParams {
            subject: &sub.id,
            action: "invoke",
            resource: &resource,
            caveats: vec![],
            proof: None,
        },
        now_ms(),
    );
    assert!(!verify_grant(&grant, &owner.id, now_ms()).ok);
}
