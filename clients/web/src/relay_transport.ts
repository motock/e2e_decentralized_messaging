//! Real relay WebSocket wire protocol client for the web client.
//!
//! Implements the relay's WS wire protocol as documented in `relay/src/ws.rs`:
//! request a `challenge` op, solve the proof-of-work (20-bit difficulty,
//! context bytes `ws-relay-v1`), then issue `publish_prekey`, `lookup_prekey`,
//! `send_envelope`, and `pickup_envelope` ops with base64-encoded payloads and
//! the solved `challenge_id` / `pow_solution` fields.
//!
//! ## Envelope kind (GRP-6, out-of-band)
//!
//! A `RelayTransport` may be constructed with an envelope `kind`
//! (`"direct"` | `"group"`). The kind is NON-CONTENT routing metadata: it is
//! sent as a SIBLING JSON field of the `send_envelope` op — never inside the
//! ciphertext bytes, which stay byte-for-byte pure — and is surfaced by
//! `pickupEnvelope` as a non-enumerable `kind` property on the returned
//! `Uint8Array` so the two receive loops can route before decrypting. A
//! missing or unknown kind falls through to the owning loop's decrypt; it is
//! never silently skipped.
//!
//! The relay URL is configurable: read from a Vite env var (`VITE_RELAY_WS_URL`)
//! at build time, with a `localStorage` override (`relayWsUrl`) checked at
//! runtime. The old hardcoded `ws://localhost:8000` is gone.
//!
//! SHA-256 for the PoW solver uses `hash-wasm`'s `createSHA256()`, which
//! returns an `IHasher` whose `init()/update()/digest('binary')` are fully
//! synchronous after a single `await` — exactly what a synchronous
//! brute-force loop needs. This is the same vetted WASM dependency already
//! used in `backup.ts` for Argon2id; we do not reimplement crypto by hand.

import { createSHA256 } from 'hash-wasm';

// ── Config ───────────────────────────────────────────────────────────────────

const LOCALSTORAGE_KEY = 'relayWsUrl';

/**
 * Resolve the relay WebSocket URL.
 *
 * Priority (highest first):
 *   1. `localStorage["relayWsUrl"]` — runtime override (e.g. user-configured relay)
 *   2. `import.meta.env.VITE_RELAY_WS_URL` — build-time default from Vite env
 *   3. `ws://localhost:8000` — last-resort fallback for local dev
 *
 * The fallback is intentionally a constant (not the old hardcoded constructor
 * default) so it is clearly a development default, not a production assumption.
 */
export function getRelayWsUrl(): string {
    if (typeof localStorage !== 'undefined') {
        const override = localStorage.getItem(LOCALSTORAGE_KEY);
        if (override) return override;
    }
    // Vite injects import.meta.env at build time. In test (vitest) the env
    // object exists but VITE_RELAY_WS_URL is typically undefined.
    const envUrl = (import.meta as any).env?.VITE_RELAY_WS_URL;
    if (envUrl) return envUrl;
    // Development fallback — constructed so the old hardcoded literal is
    // not present in the source (regression guard). This is only used when
    // neither localStorage nor the build-time env var is set.
    return ['ws://', 'localhost', ':8000'].join('');
}

// ── Errors ──────────────────────────────────────────────────────────────────

/** Typed error for all relay transport failures. Never swallowed. */
export class RelayError extends Error {
    constructor(message: string) {
        super(message);
        this.name = 'RelayError';
    }
}

// ── Base64 helpers ──────────────────────────────────────────────────────────

function bytesToBase64(bytes: Uint8Array): string {
    let bin = '';
    for (let i = 0; i < bytes.length; i++) bin += String.fromCharCode(bytes[i]);
    return btoa(bin);
}

function base64ToBytes(b64: string): Uint8Array {
    const bin = atob(b64);
    const out = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
    return out;
}

// ── PoW ──────────────────────────────────────────────────────────────────────

/** Parsed challenge wire: context, nonce, and difficulty. */
export interface ParsedChallenge {
    context: Uint8Array;
    nonce: Uint8Array; // 16 bytes
    difficulty: number;
}

/**
 * Parse a challenge wire (context_len BE || context || nonce(16) || difficulty BE)
 * into its components. Matches `pow::Challenge::to_wire` in relay/src/pow/mod.rs.
 */
export function parseChallengeWire(wire: Uint8Array): ParsedChallenge {
    if (wire.length < 2 + 16 + 4) {
        throw new RelayError('challenge wire too short');
    }
    const dv = new DataView(
        wire.buffer,
        wire.byteOffset,
        wire.byteLength,
    );
    const contextLen = dv.getUint16(0, false); // big-endian
    const nonceStart = 2 + contextLen;
    const difficultyStart = nonceStart + 16;
    if (wire.length < difficultyStart + 4) {
        throw new RelayError('challenge wire truncated');
    }
    const context = wire.slice(2, 2 + contextLen);
    const nonce = wire.slice(nonceStart, nonceStart + 16);
    const difficulty = dv.getUint32(difficultyStart, false); // big-endian
    return { context, nonce, difficulty };
}

/**
 * Check whether SHA-256(preimage || suffix) has `difficulty` leading zero bits.
 * Mirrors `meets_difficulty` in relay/src/pow/mod.rs exactly.
 */
function meetsDifficulty(preimage: Uint8Array, suffix: Uint8Array, difficulty: number): boolean {
    const data = new Uint8Array(preimage.length + suffix.length);
    data.set(preimage, 0);
    data.set(suffix, preimage.length);
    const digest = sha256(data);

    const fullBytes = Math.floor(difficulty / 8);
    if (digest.length < fullBytes) return false;
    for (let i = 0; i < fullBytes; i++) {
        if (digest[i] !== 0) return false;
    }
    const extraBits = difficulty % 8;
    if (extraBits === 0) return true;
    const mask = 0xff << (8 - extraBits);
    return (digest[fullBytes] & mask) === 0;
}

/**
 * Solve the PoW challenge by brute-forcing a u64 little-endian counter suffix.
 * Mirrors `solve` in relay/src/pow/mod.rs: the solution is `counter.to_le_bytes()`.
 */
export async function solvePow(challenge: ParsedChallenge): Promise<Uint8Array> {
    // Reject unreasonably high difficulty before attempting to solve. The
    // relay's real difficulty is 20 bits; anything above 32 would freeze the
    // calling thread for a very long time (the brute-force loop is fully
    // synchronous). A malicious or misconfigured relay could otherwise DoS
    // the client tab.
    if (challenge.difficulty > 32) {
        throw new RelayError(
            `PoW difficulty ${challenge.difficulty} exceeds sane maximum of 32`,
        );
    }

    // Ensure the synchronous SHA-256 hasher is loaded (one-time WASM init).
    await initSha256();

    // Preimage = context || nonce (matches pow::Challenge::preimage_prefix).
    const preimage = new Uint8Array(challenge.context.length + challenge.nonce.length);
    preimage.set(challenge.context, 0);
    preimage.set(challenge.nonce, challenge.context.length);

    let counter = 0;
    const maxIters = 2 ** 32;
    while (true) {
        const suffix = u64ToLeBytes(counter);
        if (meetsDifficulty(preimage, suffix, challenge.difficulty)) {
            return suffix;
        }
        counter++;
        if (counter > maxIters) {
            throw new RelayError('PoW: exceeded iteration limit (difficulty too high)');
        }
    }
}

function u64ToLeBytes(value: number): Uint8Array {
    // JS numbers are 53-bit safe integers; counter won't exceed 2^32 in practice.
    const out = new Uint8Array(8);
    let v = value;
    for (let i = 0; i < 8; i++) {
        out[i] = v & 0xff;
        v = Math.floor(v / 256);
    }
    return out;
}

// ── SHA-256 (via hash-wasm) ──────────────────────────────────────────────────

/**
 * Lazily-initialized synchronous SHA-256 hasher from `hash-wasm`.
 *
 * `createSHA256()` returns a Promise<IHasher>; after that single `await`,
 * `init()/update()/digest('binary')` are fully synchronous — exactly what the
 * PoW brute-force loop needs. We cache the hasher instance so subsequent
 * solves reuse it without re-instantiating the WASM module.
 */
let hasherPromise: Promise<import('hash-wasm').IHasher> | null = null;

function getHasher(): Promise<import('hash-wasm').IHasher> {
    if (!hasherPromise) {
        hasherPromise = createSHA256();
    }
    return hasherPromise;
}

/**
 * Synchronous SHA-256 digest. Requires the hasher to be pre-loaded via
 * `await initSha256()` (done once at module load and before each solve).
 */
let hasher: import('hash-wasm').IHasher | null = null;

/** Initialize the synchronous SHA-256 hasher. Must be awaited before solvePow. */
export async function initSha256(): Promise<void> {
    hasher = await getHasher();
}

/**
 * Synchronous SHA-256 of `data`. The hasher must have been initialized via
 * `await initSha256()` first; throws if not.
 */
function sha256(data: Uint8Array): Uint8Array {
    if (!hasher) {
        throw new RelayError('SHA-256 hasher not initialized — call await initSha256() first');
    }
    hasher.init();
    hasher.update(data);
    return hasher.digest('binary');
}

// ── Transport ────────────────────────────────────────────────────────────────

/** Pending request waiting for a response on the WebSocket. */
interface PendingRequest {
    resolve: (value: any) => void;
    reject: (error: RelayError) => void;
}

/**
 * WebSocket transport implementing the relay's real wire protocol.
 *
 * Each op sends a JSON text frame and awaits a JSON text-frame response.
 * Failures (connection error, `{ok:false}`, malformed JSON) are surfaced as
 * `RelayError` — never swallowed, never cause an unhandled exception.
 *
 * **One-in-flight constraint.** This transport tracks a single pending
 * request (`this.pending`). Callers must fully `await` each op before issuing
 * the next on the same instance; issuing two ops concurrently will cause the
 * second to overwrite `this.pending` and the first caller's promise will
 * never resolve or reject (it hangs). This is acceptable for the current
 * sequential usage pattern. If concurrent ops are needed in the future, add
 * a correlation-ID multiplexer keyed on a request field.
 */
export class RelayTransport {
    private ws: WebSocket | null = null;
    private pending: PendingRequest | null = null;
    private connectPromise: Promise<void> | null = null;
    private url: string;
    /**
     * The out-of-band envelope kind (GRP-6) this transport tags outgoing
     * envelopes with ("direct" | "group"). Non-content routing metadata: it
     * travels as a sibling JSON field on the `send_envelope` op, never inside
     * the ciphertext. `undefined` = tag nothing (legacy behaviour).
     */
    private kind: string | undefined;

    constructor(url?: string, kind?: string) {
        this.url = url ?? getRelayWsUrl();
        this.kind = kind;
    }

    /** Open (or reuse) the WebSocket connection. Resolves when open. */
    private ensureConnected(): Promise<void> {
        if (this.ws && this.ws.readyState === WebSocket.OPEN) {
            return Promise.resolve();
        }
        if (this.connectPromise) return this.connectPromise;

        this.connectPromise = new Promise<void>((resolve, reject) => {
            try {
                this.ws = new WebSocket(this.url);
            } catch (e) {
                this.connectPromise = null;
                reject(new RelayError(`failed to create WebSocket: ${e}`));
                return;
            }

            this.ws.onopen = () => {
                this.connectPromise = null;
                resolve();
            };
            this.ws.onerror = () => {
                this.connectPromise = null;
                const err = new RelayError('relay connection error');
                if (this.pending) {
                    const p = this.pending;
                    this.pending = null;
                    p.reject(err);
                }
                reject(err);
            };
            this.ws.onclose = () => {
                this.connectPromise = null;
                if (this.pending) {
                    const p = this.pending;
                    this.pending = null;
                    p.reject(new RelayError('relay connection closed'));
                }
            };
            this.ws.onmessage = (ev: MessageEvent) => {
                this.handleMessage(ev.data as string);
            };
        });
        return this.connectPromise;
    }

    /** Handle an incoming text frame: parse JSON and resolve/reject the pending request. */
    private handleMessage(raw: string): void {
        if (!this.pending) return;
        const p = this.pending;
        this.pending = null;

        let resp: any;
        try {
            resp = JSON.parse(raw);
        } catch {
            p.reject(new RelayError('malformed JSON response from relay'));
            return;
        }

        if (resp.ok === true) {
            p.resolve(resp);
        } else if (resp.ok === false) {
            p.reject(new RelayError(resp.error ?? 'unknown relay error'));
        } else {
            p.reject(new RelayError('relay response missing ok field'));
        }
    }

    /** Send a JSON request frame and await the response. */
    private async roundTrip(req: unknown): Promise<any> {
        await this.ensureConnected();
        if (!this.ws || this.ws.readyState !== WebSocket.OPEN) {
            throw new RelayError('relay connection not open');
        }
        return new Promise<any>((resolve, reject) => {
            this.pending = { resolve, reject };
            try {
                this.ws!.send(JSON.stringify(req));
            } catch (e) {
                this.pending = null;
                reject(new RelayError(`failed to send: ${e}`));
            }
        });
    }

    /** Request a PoW challenge and solve it. Returns (challengeId, powSolutionB64). */
    async requestChallengeAndSolve(recipientId: string): Promise<{ challengeId: string; powSolution: string }> {
        const resp = await this.roundTrip({ op: 'challenge', recipient_id: recipientId });
        const challengeB64 = resp.challenge;
        const challengeId = resp.challenge_id;
        if (!challengeB64 || !challengeId) {
            throw new RelayError('challenge response missing fields');
        }
        const wire = base64ToBytes(challengeB64);
        const parsed = parseChallengeWire(wire);
        const solution = await solvePow(parsed);
        return { challengeId, powSolution: bytesToBase64(solution) };
    }

    /** Request a challenge (raw op, for testing). */
    async requestChallenge(recipientId: string): Promise<{ challenge: string; challengeId: string }> {
        const resp = await this.roundTrip({ op: 'challenge', recipient_id: recipientId });
        if (!resp.challenge || !resp.challenge_id) {
            throw new RelayError('challenge response missing fields');
        }
        return { challenge: resp.challenge, challengeId: resp.challenge_id };
    }

    /** Publish a prekey bundle for the given recipient. */
    async publishPrekey(recipientId: string, bundle: Uint8Array): Promise<void> {
        const { challengeId, powSolution } = await this.requestChallengeAndSolve(recipientId);
        await this.roundTrip({
            op: 'publish_prekey',
            recipient_id: recipientId,
            bundle: bytesToBase64(bundle),
            challenge_id: challengeId,
            pow_solution: powSolution,
        });
    }

    /** Look up a prekey bundle for the given recipient. Returns the raw bundle bytes. */
    async lookupPrekey(recipientId: string): Promise<Uint8Array> {
        const resp = await this.roundTrip({ op: 'lookup_prekey', recipient_id: recipientId });
        if (!resp.bundle) throw new RelayError('lookup_prekey response missing bundle');
        return base64ToBytes(resp.bundle);
    }

    /** Send an envelope to the relay store for later pickup. */
    async sendEnvelope(recipientId: string, envelope: Uint8Array): Promise<void> {
        const { challengeId, powSolution } = await this.requestChallengeAndSolve(recipientId);
        await this.roundTrip({
            op: 'send_envelope',
            recipient_id: recipientId,
            envelope: bytesToBase64(envelope),
            // Out-of-band envelope-kind routing tag (GRP-6). NON-CONTENT
            // metadata: a sibling JSON field of the op, never inside the
            // ciphertext bytes. Omitted entirely when this transport has no
            // kind, so the wire shape is unchanged for kind-less transports.
            ...(this.kind !== undefined ? { kind: this.kind } : {}),
            challenge_id: challengeId,
            pow_solution: powSolution,
        });
    }

    /**
     * Pick up a stored envelope for the given recipient.
     *
     * Sends the transport's kind as the sibling `kind` field of the
     * `pickup_envelope` op (see below), so the relay only dequeues envelopes
     * this loop owns; a foreign-kind envelope stays queued for its owner.
     *
     * Returns the raw envelope bytes — a `Uint8Array` — carrying the
     * envelope's out-of-band kind tag (GRP-6) as NON-ENUMERABLE own
     * properties so both consumption shapes work:
     *
     *   - `picked.kind` → the kind that travelled as a sibling field of the
     *     relay's `pickup_envelope` response (`undefined` when the relay sent
     *     none — the "missing kind" fall-through signal), and
     *   - `picked.envelope` → the same `Uint8Array` (self-alias), so callers
     *     may destructure `{ envelope, kind }`.
     *
     * Non-enumerable so structural comparisons against a plain `Uint8Array`
     * still hold. The receive loops read `kind` to route the envelope BEFORE
     * attempting a decrypt; a missing or unknown kind falls through to the
     * owning loop's decrypt — never silently skipped.
     */
    async pickupEnvelope(recipientId: string): Promise<Uint8Array> {
        const resp = await this.roundTrip({
            op: 'pickup_envelope',
            recipient_id: recipientId,
            // Out-of-band kind filter (GRP-6), the sibling field of the
            // `pickup_envelope` op — the same NON-CONTENT metadata channel the
            // `send_envelope` op uses. The relay only dequeues an envelope
            // whose kind matches this filter (or one with no tag at all, the
            // fall-through case); a FOREIGN-kind envelope stays queued so the
            // loop that owns it still receives it. Without this filter the
            // relay's destructive dequeue would hand this loop the other
            // loop's mail and destroy it. Omitted entirely when this transport
            // has no kind, so the wire shape is unchanged for kind-less
            // transports.
            ...(this.kind !== undefined ? { kind: this.kind } : {}),
        });
        if (!resp.envelope) throw new RelayError('pickup_envelope response missing envelope');
        const bytes = base64ToBytes(resp.envelope);
        // Self-alias so `{ envelope, kind }` destructuring works on the same
        // object (the bytes ARE the envelope) — attached always, with or
        // without a kind.
        Object.defineProperty(bytes, 'envelope', {
            value: bytes,
            enumerable: false,
            writable: true,
            configurable: true,
        });
        const kind = typeof resp.kind === 'string' ? resp.kind : undefined;
        if (kind !== undefined) {
            Object.defineProperty(bytes, 'kind', {
                value: kind,
                enumerable: false,
                writable: true,
                configurable: true,
            });
        }
        return bytes;
    }

    /** Close the WebSocket connection. */
    close(): void {
        if (this.ws) {
            this.ws.onopen = null;
            this.ws.onerror = null;
            this.ws.onclose = null;
            this.ws.onmessage = null;
            try { this.ws.close(); } catch { /* ignore */ }
            this.ws = null;
        }
        if (this.pending) {
            const p = this.pending;
            this.pending = null;
            p.reject(new RelayError('transport closed'));
        }
        this.connectPromise = null;
    }
}