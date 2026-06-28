//! The edge: CORS is enforced here, and nowhere else. Default-deny. The edge is
//! the whole of a provider's authority and the entire trust boundary.
//!
//! Verification is local and self-contained: a message carries its own proof
//! (the contract), so the edge needs no external lookup and no round-trip.

use std::collections::HashSet;

use crate::cors::{authorizes, verify_grant};
use crate::identity::verify_record;
use crate::message::Message;
use crate::resource::resource_owner;
use crate::sys;

#[derive(Debug, Clone)]
pub struct Decision {
    pub ok: bool,
    pub reason: Option<String>,
}

impl Decision {
    fn allow() -> Decision {
        Decision {
            ok: true,
            reason: None,
        }
    }
    fn deny(reason: impl Into<String>) -> Decision {
        Decision {
            ok: false,
            reason: Some(reason.into()),
        }
    }
}

pub struct Edge {
    owner_id: String,
    window_ms: i64,
    seen: HashSet<String>,
    revoked: HashSet<String>,
}

impl Edge {
    pub fn new(owner_id: String) -> Edge {
        Edge::with_window(owner_id, 60_000)
    }

    pub fn with_window(owner_id: String, window_ms: i64) -> Edge {
        Edge {
            owner_id,
            window_ms,
            seen: HashSet::new(),
            revoked: HashSet::new(),
        }
    }

    /// Revoke a contract by its signature. Any request whose contract chain
    /// passes through a revoked link is denied — so revoking a parent also
    /// invalidates everything delegated from it. Provider-local; no network.
    pub fn revoke(&mut self, sig: impl Into<String>) {
        self.revoked.insert(sig.into());
    }

    /// The complete trust decision for one request — pure CORS, at the boundary.
    pub fn admit(&mut self, msg: &Message) -> Decision {
        let now = sys::now_ms();
        // 1. integrity
        if !verify_record(&msg.from, &msg.signing_json(), &msg.sig) {
            return Decision::deny("forged or tampered message");
        }
        // 2. addressed to us, for a resource we own
        if msg.to != self.owner_id {
            return Decision::deny("message not addressed to this edge");
        }
        if resource_owner(&msg.resource) != self.owner_id {
            return Decision::deny("resource not owned by this edge");
        }
        // 3. freshness — abs_diff never overflows, so a malformed signed
        //    timestamp (e.g. i64::MIN) fails closed instead of panicking.
        if now.abs_diff(msg.issued_at) > self.window_ms.unsigned_abs() {
            return Decision::deny("message outside freshness window");
        }
        // 4. replay
        if self.seen.contains(&msg.nonce) {
            return Decision::deny("replayed nonce");
        }
        // 5. CORS — the only trust. No contract, no access. Origin grants nothing.
        let grant = match &msg.grant {
            Some(g) => g,
            None => {
                return Decision::deny(format!(
                    "no CORS contract for {} {}",
                    msg.action, msg.resource
                ))
            }
        };
        if grant.subject != msg.from {
            return Decision::deny("contract not held by the sender");
        }
        if !authorizes(grant, &msg.action, &msg.resource) {
            return Decision::deny("contract does not authorize this action/resource");
        }
        let gc = verify_grant(grant, &self.owner_id, now);
        if !gc.ok {
            return Decision::deny(format!(
                "invalid contract: {}",
                gc.reason.unwrap_or_default()
            ));
        }
        // revocation: deny if any link in the contract chain has been revoked
        if !self.revoked.is_empty() {
            let mut link = Some(grant);
            while let Some(cur) = link {
                if self.revoked.contains(&cur.sig) {
                    return Decision::deny("contract revoked");
                }
                link = cur.proof.as_deref();
            }
        }
        self.seen.insert(msg.nonce.clone());
        Decision::allow()
    }
}
