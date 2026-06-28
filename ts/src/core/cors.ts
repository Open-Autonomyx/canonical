// Canonical Core — CORS: the one and only trust primitive.
//
// Trust is NOT based on origin. A resource is reachable only when its provider
// has issued an explicit, signed sharing contract. Only CORS is trusted.
//
// A grant IS a contract. Only the provider — the resource owner — holds the
// authority to originate one. Every valid grant chains, by monotone
// attenuation, back to that provider; a consumer only ever holds a delegated
// sub-contract, never authority of its own.

import { signRecord, verifyRecord, type Signer } from "./identity.ts";
import { actionSubsumes, resourceSubsumes } from "./resource.ts";

export interface Caveat {
  readonly type: string;
  readonly [k: string]: unknown;
}

/** A short-lived contract: invalid after `notAfter` (ms since epoch). */
export function expiry(notAfter: number): Caveat {
  return { type: "expiry", notAfter };
}

/** A contract that only becomes valid at `notBefore` (ms since epoch). */
export function notBefore(notBefore: number): Caveat {
  return { type: "notBefore", notBefore };
}

export interface CorsGrant {
  /** who signed this link of the contract — the provider, or a re-delegator. */
  readonly issuer: string;
  /** who may use it. */
  readonly subject: string;
  /** the action, e.g. "invoke" / "read"; "*" means any. */
  readonly action: string;
  /** the resource "<ownerId>:<path>"; path may end with "/*". */
  readonly resource: string;
  readonly caveats?: readonly Caveat[];
  readonly issuedAt: number;
  /** parent contract, embedded so the edge can verify with no external lookup. */
  readonly proof?: CorsGrant;
  readonly sig: string;
}

/** Does this contract, on its face, permit `action` on `resource`? */
export function authorizes(grant: CorsGrant, action: string, resource: string): boolean {
  return actionSubsumes(grant.action, action) && resourceSubsumes(grant.resource, resource);
}

function caveatsHold(caveats: readonly Caveat[] | undefined, now: number): GrantCheck {
  for (const c of caveats ?? []) {
    if (c.type === "expiry") {
      const notAfter = c["notAfter"];
      if (typeof notAfter !== "number" || now > notAfter) return { ok: false, reason: "contract expired" };
    } else if (c.type === "notBefore") {
      const nb = c["notBefore"];
      if (typeof nb !== "number" || now < nb) return { ok: false, reason: "contract not yet valid" };
    } else {
      // Fail closed: an edge that does not understand a caveat must not honour it.
      return { ok: false, reason: `unknown caveat '${c.type}'` };
    }
  }
  return { ok: true };
}

export interface IssueParams {
  subject: string;
  action: string;
  resource: string;
  caveats?: readonly Caveat[];
  proof?: CorsGrant;
}

/** The provider originates a contract for one of its own resources. */
export async function issueGrant(owner: Signer, params: IssueParams, now: number = Date.now()): Promise<CorsGrant> {
  const body = {
    issuer: owner.id,
    subject: params.subject,
    action: params.action,
    resource: params.resource,
    // Omit empty/absent caveats so the signed bytes match the Rust core, which
    // never emits an empty caveat array. Keeps the two cores one trust domain.
    caveats: params.caveats && params.caveats.length > 0 ? params.caveats : undefined,
    issuedAt: now,
    proof: params.proof,
  };
  return signRecord(owner, body);
}

export interface AttenuateParams {
  subject: string;
  action?: string;
  resource?: string;
  caveats?: readonly Caveat[];
}

/** A holder delegates part of a contract it holds to another subject. */
export async function attenuate(
  holder: Signer,
  parent: CorsGrant,
  params: AttenuateParams,
  now: number = Date.now(),
): Promise<CorsGrant> {
  return issueGrant(
    holder,
    {
      subject: params.subject,
      action: params.action ?? parent.action,
      resource: params.resource ?? parent.resource,
      caveats: params.caveats,
      proof: parent,
    },
    now,
  );
}

export interface GrantCheck {
  readonly ok: boolean;
  readonly reason?: string;
}

// Verify the contract chains, by valid signatures and monotone attenuation, all
// the way back to the resource provider. There is no origin shortcut: only the
// provider can root a contract, and no link may widen what its parent granted.
export async function verifyGrant(grant: CorsGrant, providerId: string, now: number, depth = 0): Promise<GrantCheck> {
  if (depth > 32) return { ok: false, reason: "contract chain too deep" };
  if (!(await verifyRecord(grant.issuer, grant))) return { ok: false, reason: "invalid contract signature" };
  const cav = caveatsHold(grant.caveats, now);
  if (!cav.ok) return cav;
  if (grant.issuer === providerId) return { ok: true };
  if (!grant.proof) return { ok: false, reason: "contract not rooted at the provider" };
  if (grant.proof.subject !== grant.issuer) return { ok: false, reason: "delegation not held by its issuer" };
  if (!actionSubsumes(grant.proof.action, grant.action)) return { ok: false, reason: "delegation widens the action" };
  if (!resourceSubsumes(grant.proof.resource, grant.resource)) return { ok: false, reason: "delegation widens the resource" };
  return verifyGrant(grant.proof, providerId, now, depth + 1);
}
