import React from 'react';
import Banner from './Banner';
import { Conversation } from './Conversation';
import { SafetyNumberVerification } from './SafetyNumberVerification';
import { BackupPanel } from './BackupPanel';
import { GroupConversation } from './GroupConversation';
import { DeviceLinking } from './DeviceLinking';
import { ensureWasmInit } from './wasm_init';
import {
    fanout_establish,
    fanout_remove_device,
    publish_bundle_bytes,
    FanoutDeviceInput,
    FanoutHandle,
} from '../../../core/bindings/wasm/pkg/index.js';
// Namespace import for the bindings the checked-in ambient fallback does not
// declare (the signed-device-list ones, cast locally further down). The named
// imports above stay named: destructuring them from the namespace at module
// scope would resolve them at import time, which breaks the partial wasm mocks
// the tests install.
import * as wasmBindings from '../../../core/bindings/wasm/pkg/index.js';
import { SealGlyph } from './design/SealGlyph';
import { StorageGate } from './storage';
import { getStorageKey, getStoragePassword } from './storage_key';
import { loadOrGenerateIdentity, type PersistedIdentity } from './identity';
import { getRelayWsUrl, RelayTransport } from './relay_transport';
import { useRelayConnection, RelayConnectionPanel } from './useRelayConnection';
import { applyDeviceListUpdate, type DeviceList, type DeviceListEntry } from './Conversation';
import {
    lookupDeviceList,
    publishSignedDeviceList,
    type DiscoveryTransport,
} from './discovery';
import { revokeDevice } from './revocation';
import './design/AppShell.css';

// SafetyNumberVerification's deriveSafetyNumber calls the real
// wasm.derive_safety_number binding, which requires 33-byte compressed
// Curve25519 identity keys and throws on any other length.  The identity
// is now loaded from persistent storage (or generated and persisted on
// first run) via `loadOrGenerateIdentity`.  Both this and the safety number
// derivation itself require wasm_init's async init to have completed first
// (see wasm_init.ts) — the identity stays null (and SafetyNumberVerification
// unrendered) until that finishes.
class SafetyNumberErrorBoundary extends React.Component<
    { children: React.ReactNode },
    { error: Error | null }
> {
    constructor(props: { children: React.ReactNode }) {
        super(props);
        this.state = { error: null };
    }
    static getDerivedStateFromError(error: Error) {
        return { error };
    }
    render() {
        if (this.state.error) {
            return <div role="alert">Safety number unavailable: {this.state.error.message}</div>;
        }
        return this.props.children;
    }
}

type ViewId = 'direct' | 'group' | 'link' | 'backup';

// The WASM identity handle GroupConversation expects, derived from its own
// props so App.tsx does not have to import the wasm pkg directly.
type GroupIdentity = NonNullable<React.ComponentProps<typeof GroupConversation>['identity']>;

const NAV_ITEMS: { id: ViewId; label: string; title: string; subtitle: string }[] = [
    { id: 'direct', label: 'Direct', title: 'Direct message', subtitle: 'One-to-one, Double Ratchet' },
    { id: 'group', label: 'Group', title: 'Group conversation', subtitle: 'Sender Keys group crypto' },
    { id: 'link', label: 'Link', title: 'Link a device', subtitle: 'QR code + safety-number confirmation' },
    { id: 'backup', label: 'Backup', title: 'Encrypted backup', subtitle: 'Passphrase-protected export / import' },
];

// DR-6b: revocation support for the account's linked devices, inlined here
// (App owns the recipient device list — spec/v0.md §8.3 — and the live
// sender-side fan-out session, so a revoke does both halves of the job):
//
//   1. `revokeDeviceOnSession` calls `fanout_remove_device` on the LIVE
//      handle, mutating the session the handle holds — the removal sticks in
//      the session rather than only in the UI.
//   2. `removeDeviceFromList` drops the device from the held list (purely,
//      bumping the list version so a stale or replayed list can never
//      resurrect the revoked device — §8.4 monotonicity). Conversation
//      re-establishes its fan-out session from this list on every send, so a
//      later 1:1 send produces no envelope for the revoked device while the
//      survivors still receive.
//
// No keys, plaintext or full identifiers are logged here.

/** The live sender-side fan-out session App holds for revocation. */
type FanoutSessionHandle = FanoutHandle;

/**
 * Establish a live fan-out session over the account's linked devices.
 *
 * `identityHandle` is the WASM identity handle App holds (PersistedIdentity's
 * `handle`); it is cast at this boundary exactly like Conversation does for
 * its own `fanout_establish` call. Throws when any device's bundle does not
 * match its vouched-for key or is malformed — the caller must fail closed (no
 * live session), never fall back to a partial session.
 */
function establishFanoutSession(
    identityHandle: unknown,
    devices: DeviceListEntry[],
): FanoutSessionHandle {
    const inputs = devices.map(
        (entry) =>
            // expected_identity_key_bytes is the key the PRIMARY vouched for
            // (entry.identityKey), never the bundle's own key — the binding
            // compares the two and rejects a mismatched bundle.
            new FanoutDeviceInput(entry.deviceId, entry.identityKey, entry.bundleBytes),
    );
    return fanout_establish(
        identityHandle as unknown as Parameters<typeof fanout_establish>[0],
        inputs,
    );
}

/**
 * Drop `deviceId` from the LIVE fan-out session `handle` holds. Mutates the
 * session, so a later `fanout_devices`/`fanout_encrypt` on the same handle
 * reflects the removal.
 */
function revokeDeviceOnSession(handle: FanoutSessionHandle, deviceId: number): void {
    fanout_remove_device(handle, deviceId);
}

/**
 * Drop `deviceId` from the held device list, purely.
 *
 * The returned list's version is strictly newer than the held one, so the
 * §8.4 monotonic guard ignores any stale or replayed list that still carries
 * the revoked device: a revocation can never be undone by an old update.
 */
function removeDeviceFromList(held: DeviceList, deviceId: number): DeviceList {
    return {
        version: held.version + 1,
        devices: held.devices.filter((device) => device.deviceId !== deviceId),
    };
}

/** True when `deviceId` is actually in `list` — the revoke guard for unknown ids. */
function isListedDevice(list: DeviceList | undefined, deviceId: number): boolean {
    return !!list && list.devices.some((device) => device.deviceId === deviceId);
}

// ---------------------------------------------------------------------------
// MD-17: signed device-list discovery
// ---------------------------------------------------------------------------
//
// App owns the account's device list (spec/v0.md §8.3) and now loads it from —
// and publishes it to — the signed-discovery layer (discovery.ts, MD-9) rather
// than relying solely on the `deviceList` prop. The prop stays as an
// initial/override value for tests; discovery populates state when it is absent.
//
// The signed-device-list bindings this module needs are not declared in the
// checked-in ambient fallback (`wasm-bindings.d.ts`), so they are reached
// through a local cast, mirroring discovery.ts and link_primary.ts. When
// `prepare-wasm` has run, wasm-pack's generated `index.d.ts` declares them and
// the cast is a no-op.
interface DeviceListSignBindings {
    /** Sign a versioned list; returns the on-the-wire blob. */
    sign_device_list(
        primaryPrivateBytes: Uint8Array,
        version: number,
        packedEntries: Uint8Array,
    ): Uint8Array;
}

const deviceListSignWasm = wasmBindings as unknown as DeviceListSignBindings;

/**
 * Pack device-list entries for `sign_device_list`:
 * `u32_le(deviceId) | u32_le(identityLen) | identity | u32_le(bundleLen) | bundle`,
 * concatenated with no count prefix (the layout `toConversationDeviceList`
 * parses). Mirrors link_primary.ts's packer; kept local so App does not depend
 * on the linking module's internals.
 */
function packDeviceListEntries(entries: DeviceListEntry[]): Uint8Array {
    let size = 0;
    for (const entry of entries) {
        size += 4 + 4 + entry.identityKey.length + 4 + entry.bundleBytes.length;
    }
    const out = new Uint8Array(size);
    const view = new DataView(out.buffer);
    let pos = 0;
    for (const entry of entries) {
        if (
            !Number.isSafeInteger(entry.deviceId) ||
            entry.deviceId < 0 ||
            entry.deviceId > 0xffffffff
        ) {
            throw new Error('device list: device id is out of range');
        }
        // Validate before signing: a malformed entry must never be signed and
        // published, because peers verify the signature and then trust the
        // contents. Identity keys are 33-byte compressed Curve25519 keys (the
        // length every other binding requires) and a bundle is never empty.
        if (entry.identityKey.length !== 33) {
            throw new Error('device list: identity key is not 33 bytes');
        }
        if (entry.bundleBytes.length === 0) {
            throw new Error('device list: bundle is empty');
        }
        view.setUint32(pos, entry.deviceId, true);
        pos += 4;
        view.setUint32(pos, entry.identityKey.length, true);
        pos += 4;
        out.set(entry.identityKey, pos);
        pos += entry.identityKey.length;
        view.setUint32(pos, entry.bundleBytes.length, true);
        pos += 4;
        out.set(entry.bundleBytes, pos);
        pos += entry.bundleBytes.length;
    }
    return out;
}

/** The version an account's first published device list carries. */
const DEVICE_LIST_INITIAL_VERSION = 1;

/**
 * This account's OWN signed device list: the devices linked to this account
 * (device 0 is the primary), the exact signed bytes the relay holds, and the
 * version those bytes were signed at.
 *
 * The three fields are set together and never separately, so the bytes and the
 * version can never diverge — MD-18 re-signs from these bytes and MD-16's
 * freshness guard compares a scanned version against this one.
 */
interface HeldOwnList {
    version: number;
    bytes: Uint8Array;
    devices: DeviceListEntry[];
}

/**
 * Wrap a discovery transport so the raw blob the last `lookupDiscovery` saw is
 * observable.
 *
 * `lookupDeviceList` verifies and converts a blob but does not hand back the
 * signed bytes, and App must keep the exact bytes it holds (for MD-18
 * revocation and DeviceLinking's freshness guard). Recording them here keeps
 * the held bytes and the held version in lockstep with a single fetch, without
 * changing discovery.ts's contract.
 */
function recordingDiscovery(inner: DiscoveryTransport): {
    transport: DiscoveryTransport;
    lastBlob: () => Uint8Array | null;
} {
    let blob: Uint8Array | null = null;
    return {
        transport: {
            publishDiscovery: (handle, bytes) => inner.publishDiscovery(handle, bytes),
            lookupDiscovery: async (handle) => {
                blob = await inner.lookupDiscovery(handle);
                return blob;
            },
        },
        lastBlob: () => blob,
    };
}

/**
 * Build, sign and publish the account's initial (version 1) device list
 * containing only device 0 — this device — and return the signed bytes plus
 * the entry that was published.
 *
 * Device 0's identity key is the account's own public identity key and its
 * bundle is the receiver session's published bundle, so a peer that fetches the
 * list can fan out to this device exactly as it would to a linked one.
 */
async function seedOwnDeviceList(
    transport: DiscoveryTransport,
    recipientId: string,
    identity: PersistedIdentity,
    receiverSession: unknown,
): Promise<HeldOwnList> {
    const device0: DeviceListEntry = {
        deviceId: 0,
        identityKey: identity.publicBytes,
        bundleBytes: publish_bundle_bytes(
            receiverSession as Parameters<typeof publish_bundle_bytes>[0],
        ),
    };
    const signedBytes = deviceListSignWasm.sign_device_list(
        identity.handle.private_bytes(),
        DEVICE_LIST_INITIAL_VERSION,
        packDeviceListEntries([device0]),
    );
    await publishSignedDeviceList(transport, recipientId, signedBytes);
    return {
        version: DEVICE_LIST_INITIAL_VERSION,
        bytes: signedBytes,
        devices: [device0],
    };
}

/** Store and record id the linking handshake (MD-16) persists the link under. */
const ACCOUNT_DEVICE_LIST_STORE = 'identity' as const;
const ACCOUNT_DEVICE_LIST_RECORD_ID = 'account-device-list';

/** The parts of the persisted account-device link record the receive path needs. */
export interface AccountDeviceLink {
    /** The account handle this device is linked to. */
    accountHandle: string;
    /** This device's id in the account's signed list (the primary is 0). */
    deviceId: number;
}

/**
 * MD-17b: structurally validate the persisted account-device link record.
 *
 * The linking handshake writes `{ accountHandle, deviceId, signedListBytesBase64 }`
 * under the `identity` store. Anything else — no record at all, a record from an
 * older/foreign writer, or a corrupted one — yields `null`, so the caller falls
 * back to the bare recipient id. This never throws: a bad record must not break
 * render, and the record's list bytes are never logged or echoed.
 */
export function parseAccountDeviceLink(raw: unknown): AccountDeviceLink | null {
    if (typeof raw !== 'object' || raw === null) return null;
    const { accountHandle, deviceId, signedListBytesBase64 } = raw as Record<string, unknown>;
    if (typeof accountHandle !== 'string' || accountHandle.length === 0) return null;
    if (typeof deviceId !== 'number' || !Number.isInteger(deviceId) || deviceId < 0) return null;
    if (typeof signedListBytesBase64 !== 'string') return null;
    return { accountHandle, deviceId };
}

export default function App({ deviceList: deviceListProp }: { deviceList?: DeviceList } = {}) {
    const [identity, setIdentity] = React.useState<PersistedIdentity | null>(null);
    // The encrypted store opened for identity loading, held so the relay
    // connection can persist/restore the receiver session through it. It is
    // set in the same synchronous block as `identity` so a single render
    // carries both (see the startup effect below).
    const [sessionGate, setSessionGate] = React.useState<StorageGate | undefined>(undefined);
    // Relay endpoint, resolved at startup via getRelayWsUrl() (localStorage >
    // VITE_RELAY_WS_URL > dev default) and editable at runtime through the
    // relay panel. An empty field resets to that same resolution order.
    const [relayUrl, setRelayUrl] = React.useState<string>(getRelayWsUrl());
    const [copied, setCopied] = React.useState(false);
    const [view, setView] = React.useState<ViewId>('direct');
    // The active direct-conversation peer and their real remote identity key, reported by
    // Conversation once a session has been established (lookup_prekey + establish_session_from_bundle)
    // — see Conversation's onRemoteIdentityKeyChange prop. SafetyNumberVerification renders this
    // real key instead of a demo/self placeholder.
    const [activePeerId, setActivePeerId] = React.useState<string>('');
    const [remoteIdentityKey, setRemoteIdentityKey] = React.useState<Uint8Array | null>(null);

    // DR-6: the recipient's verified device list (spec/v0.md §8.3), owned by App
    // as app-level state. The prop injects it (tests / a future DiscoveryRecord
    // transport); updates are applied MONOTONICALLY (§8.4) — an update whose
    // version is not newer than the one already held is ignored, so a stale or
    // replayed list can never replace a newer one.
    const [deviceList, setDeviceList] = React.useState<DeviceList | undefined>(undefined);
    React.useEffect(() => {
        if (deviceListProp === undefined) return;
        setDeviceList((held) => applyDeviceListUpdate(held, deviceListProp));
    }, [deviceListProp]);

    // MD-17b: this device's account-device link, as persisted by the linking
    // handshake (MD-16). `null` means "not linked / no usable record" — the
    // receive loop then polls the bare recipient id, which is also what the
    // primary device (id 0) does.
    const [accountDeviceLink, setAccountDeviceLink] = React.useState<AccountDeviceLink | null>(
        null,
    );
    React.useEffect(() => {
        if (!identity || !sessionGate) return;
        let cancelled = false;
        (async () => {
            let link: AccountDeviceLink | null = null;
            try {
                const raw = await sessionGate.get(
                    ACCOUNT_DEVICE_LIST_STORE,
                    ACCOUNT_DEVICE_LIST_RECORD_ID,
                );
                link = parseAccountDeviceLink(raw);
            } catch {
                // A missing or undecryptable record is not fatal: fall back to
                // the bare recipient id. The record carries signed list bytes,
                // so nothing about it is logged.
                link = null;
            }
            if (!cancelled) setAccountDeviceLink(link);
        })();
        return () => {
            cancelled = true;
        };
    }, [identity, sessionGate]);

    // Retry-with-backoff prekey publish + Connecting/Connected/Unreachable
    // status. The receiver session it produces on success is handed to
    // Conversation's receive loop.
    //
    // Declared here (ahead of the discovery effects below) because MD-17's
    // own-list load needs `conn.receiverSession` to build device 0's bundle.
    const conn = useRelayConnection(identity, relayUrl, sessionGate);

    // MD-17: this account's OWN signed device list (device 0 is the primary),
    // loaded from — or seeded into — the signed-discovery layer. It is
    // deliberately NOT the `deviceList` state below: that one is the
    // RECIPIENT's list, and Conversation fans a 1:1 send out to every device in
    // it. Seeding our own device 0 there would make every send fan out to this
    // very device, addressing an envelope to the peer that only we can read.
    //
    // `null` means "no signed own list held yet".
    const [ownList, setOwnList] = React.useState<HeldOwnList | null>(null);
    // Mirror of `ownList` for the discovery effect, which must read the held
    // version before awaiting without re-running whenever the list changes
    // (re-running would re-look-up the list it just stored).
    const ownListRef = React.useRef<HeldOwnList | null>(null);
    // Set the held own list — bytes, version and devices in one step, so the
    // pair can never diverge.
    const holdOwnList = React.useCallback((next: HeldOwnList) => {
        ownListRef.current = next;
        setOwnList(next);
    }, []);

    // A transport for discovery lookups/publishes. Kept separate from the
    // group transport (which is tagged 'group') and from Conversation's own
    // direct transport: discovery blobs are opaque and untagged, so a plain
    // instance is correct. Memoized on relayUrl so a runtime URL change is
    // picked up.
    const discoveryTransport = React.useMemo(
        () => new RelayTransport(relayUrl),
        [relayUrl],
    );
    // Close the superseded discovery transport when relayUrl changes (same
    // ref-based pattern as the group transport above, so StrictMode's
    // mount→cleanup→mount does not close the live instance).
    const prevDiscoveryTransportRef = React.useRef<RelayTransport | null>(null);
    React.useEffect(() => {
        const prev = prevDiscoveryTransportRef.current;
        prevDiscoveryTransportRef.current = discoveryTransport;
        if (prev && prev !== discoveryTransport) prev.close();
    }, [discoveryTransport]);

    // MD-17: load the account's OWN device list once identity and the receiver
    // session are both available. When the relay holds none, seed version 1
    // with device 0 (this device), sign it with the identity's private bytes,
    // publish it, and hold it. A verification failure is NOT fatal here — the
    // held list is left untouched (fail closed) and the error never escapes
    // render.
    React.useEffect(() => {
        if (!identity || !conn.receiverSession) return;
        let cancelled = false;
        (async () => {
            try {
                const held = ownListRef.current;
                const recorder = recordingDiscovery(discoveryTransport);
                const verified = await lookupDeviceList(
                    recorder.transport,
                    identity.recipientId,
                    identity.publicBytes,
                    // §8.4 baseline for OUR OWN list only — never another
                    // account's version.
                    held?.version ?? null,
                );
                if (cancelled) return;
                if (verified) {
                    const bytes = recorder.lastBlob();
                    // Bytes and version come from the same fetch, so they stay
                    // in lockstep (MD-18 re-signs from these bytes).
                    if (bytes) {
                        holdOwnList({
                            version: verified.version,
                            bytes,
                            devices: verified.deviceList.devices,
                        });
                    }
                    return;
                }
                if (held) {
                    // The relay's blob is gone (TTL) or older than what we
                    // hold: re-publish the held list at its own version rather
                    // than seeding v1, which would drop every linked device
                    // from the published list.
                    await publishSignedDeviceList(
                        discoveryTransport,
                        identity.recipientId,
                        held.bytes,
                    );
                    return;
                }
                // Absent: seed and publish v1 containing only device 0.
                const seeded = await seedOwnDeviceList(
                    discoveryTransport,
                    identity.recipientId,
                    identity,
                    conn.receiverSession,
                );
                if (cancelled) return;
                holdOwnList(seeded);
            } catch {
                // Fail closed: an unverifiable or unreachable own list leaves
                // whatever is already held untouched. Never rethrow out of the
                // effect — a discovery failure must not take down the app.
            }
        })();
        return () => {
            cancelled = true;
        };
    }, [identity, conn.receiverSession, discoveryTransport, holdOwnList]);

    // MD-17: the list App holds for each PEER, keyed by peer id. ONE map holds
    // both the devices and the version they were signed at, so the §8.4
    // baseline and the list it guards can never diverge. The baseline must be
    // per account: comparing a peer's version against this account's own list
    // (or another peer's) would reject a fresh version-1 list from a new peer
    // and compare unrelated accounts.
    const peerListsRef = React.useRef(new Map<string, DeviceList>());
    // The peer the recipient `deviceList` currently belongs to. Only a genuine
    // switch may reset the list: re-reporting the SAME peer's key must not
    // clear a list that the monotonic lookup would then decline to re-apply.
    // The account is tracked alongside the peer so a per-peer baseline left
    // over from a previous account cannot reject a fresh list for the same
    // peer id.
    const recipientListOwnerRef = React.useRef<{
        account: string | null;
        peer: string;
    } | null>(null);

    // MD-17: when Conversation reports a peer's real remote identity key, fetch
    // that peer's signed list and apply it only when strictly newer than the
    // list held FOR THAT PEER (§8.4). A verification failure leaves the held
    // list untouched and never throws out of render.
    React.useEffect(() => {
        const peerId = activePeerId;
        const account = identity?.recipientId ?? null;
        const owner = recipientListOwnerRef.current;
        // Switching peers must never leave the PREVIOUS peer's devices in the
        // recipient list: Conversation fans a 1:1 send out to every device in
        // it, so a stale list would encrypt the envelopes to the old peer's
        // bundles while addressing them to the new peer — undecryptable, and
        // the message is lost. Reset BEFORE the lookup and independently of its
        // result: to the list already held for the NEW peer (switching back
        // must not drop devices the monotonic lookup would decline to
        // re-apply), else to the injected baseline.
        //
        // Only a switch AWAY from a real peer resets. The first peer to become
        // active is not a switch — there is no previous peer's list to clear —
        // and resetting there would resurrect devices revoked from the held
        // list by restoring the (static) injected baseline.
        const peerChanged = owner !== null && owner.peer !== '' && owner.peer !== peerId;
        const accountChanged = owner !== null && owner.account !== account;
        // Track the owner on EVERY run, so the next run compares against the
        // peer actually held rather than the last one that triggered a reset.
        recipientListOwnerRef.current = { account, peer: peerId };
        if (owner === null || peerChanged || accountChanged) {
            // A baseline from another account is meaningless for this one.
            if (accountChanged) peerListsRef.current.clear();
            setDeviceList(
                (peerId ? peerListsRef.current.get(peerId) : undefined) ?? deviceListProp,
            );
        }
        if (!remoteIdentityKey || !peerId) return;
        let cancelled = false;
        (async () => {
            try {
                const heldVersion = peerListsRef.current.get(peerId)?.version ?? null;
                const verified = await lookupDeviceList(
                    discoveryTransport,
                    peerId,
                    remoteIdentityKey,
                    heldVersion,
                );
                if (cancelled || !verified) return;
                // Set the recipient's list directly: the per-peer baseline
                // above already proved this list is newer than the one held for
                // this peer, and comparing against the shared state would
                // reject a peer's fresh list whenever another account's list
                // happened to be newer.
                const next: DeviceList = {
                    version: verified.deviceList.version,
                    devices: verified.deviceList.devices,
                };
                peerListsRef.current.set(peerId, next);
                setDeviceList(next);
            } catch {
                // Unverified peer list: keep the held list, swallow the error.
            }
        })();
        return () => {
            cancelled = true;
        };
    }, [
        remoteIdentityKey,
        activePeerId,
        discoveryTransport,
        deviceListProp,
        identity?.recipientId,
    ]);

    // DR-6b: the LIVE sender-side fan-out session over the linked devices,
    // kept in lockstep with the held list so a revoke can call
    // `fanout_remove_device` on the session the handle holds — the removal
    // sticks in the session rather than only in the UI. Re-established
    // whenever the list changes; a list whose devices fail fan-out
    // establishment leaves NO live session (fail closed) rather than a
    // partial one.
    const [fanoutSession, setFanoutSession] = React.useState<FanoutSessionHandle | null>(null);
    React.useEffect(() => {
        if (!deviceList || deviceList.devices.length === 0 || !identity) {
            setFanoutSession(null);
            return;
        }
        try {
            setFanoutSession(establishFanoutSession(identity.handle, deviceList.devices));
        } catch {
            // Fail closed: no session at all beats a session missing the
            // devices that failed. Conversation's own send path applies the
            // same rule (its fan-out send throws rather than silently
            // dropping a device).
            setFanoutSession(null);
        }
    }, [deviceList, identity]);

    // DR-6b / MD-18: revoke a linked device.
    //
    // When the account's OWN signed list is held, a revoke is a PUBLISHED act:
    // `revokeDevice` verifies the held bytes against the primary, drops the
    // device, signs version+1 and publishes it, and App then holds the new list
    // and the new raw bytes together. A verification or publish failure leaves
    // the held list (and its bytes) untouched — fail closed, never a partial
    // list on the relay.
    //
    // Without a signed own list (the injected-prop path used by tests and a
    // future DiscoveryRecord transport) the local shortcut still applies: drop
    // the device from the held list and call `fanout_remove_device` on the live
    // handle. An id that is not in the list is a no-op.
    const handleRevokeDevice = React.useCallback(
        async (deviceId: number) => {
            const heldOwn = ownListRef.current;
            if (heldOwn && identity) {
                try {
                    const { signedListBytes, deviceList: next } = await revokeDevice({
                        currentListBytes: heldOwn.bytes,
                        primaryIdentityHandle: identity.handle,
                        deviceId,
                        accountHandle: identity.recipientId,
                        transport: discoveryTransport,
                    });
                    // List and bytes in one step, so they can never diverge.
                    holdOwnList({
                        version: next.version,
                        bytes: signedListBytes,
                        devices: next.devices,
                    });
                } catch {
                    // Fail closed: an unverifiable list or a failed publish
                    // leaves whatever is already held untouched.
                }
                return;
            }
            if (!isListedDevice(deviceList, deviceId)) return;
            setDeviceList((held) => (held ? removeDeviceFromList(held, deviceId) : held));
            if (fanoutSession) revokeDeviceOnSession(fanoutSession, deviceId);
        },
        [deviceList, fanoutSession, identity, discoveryTransport, holdOwnList],
    );

    const handleRemoteIdentityKeyChange = React.useCallback(
        (peerId: string, key: Uint8Array | null) => {
            setActivePeerId(peerId);
            setRemoteIdentityKey(key);
        },
        [],
    );

    React.useEffect(() => {
        let cancelled = false;
        (async () => {
            await ensureWasmInit();
            if (cancelled) return;

            // Load persisted identity or generate+persist a new one.
            // Fail-closed: if storage is corrupt or unavailable, this throws
            // and the identity stays null — we never silently fall back to
            // an unpersisted identity that would change the user's address.
            const gate = new StorageGate({
                indexedDB: globalThis.indexedDB,
                keyBytes: getStorageKey(),
            });
            await gate.open();
            const id = await loadOrGenerateIdentity(gate);
            if (cancelled) return;
            // Set both in the same synchronous block (no await between them) so
            // React batches them into ONE render where identity and sessionGate
            // are both present — useRelayConnection then receives the gate on
            // that render and persists the receiver session it creates.
            setSessionGate(gate);
            setIdentity(id);
            // Prekey publishing (with retry/backoff + human status) is driven
            // by useRelayConnection below, which starts once `identity` is set.
        })();
        return () => {
            cancelled = true;
        };
    }, []);

    // Retry-with-backoff prekey publish + Connecting/Connected/Unreachable
    // status. The receiver session it produces on success is handed to
    // Conversation's receive loop.
    //
    // (Declared above, ahead of the MD-17 discovery effects, which need
    // `conn.receiverSession`.)

    // The group view reaches the relay through the same transport surface as
    // the direct path, tagged with this loop's out-of-band envelope kind
    // ("group"). The kind is injected HERE (rather than left to
    // GroupConversation's own `transport ?? new RelayTransport(getRelayWsUrl(),
    // 'group')` default) because App always injects a transport, so the
    // default never fires: without the tag the shipped app's group loop sent
    // untagged and picked up unfiltered, and the relay's destructive dequeue
    // handed it the direct loop's mail, which the group loop then dropped.
    // Memoized on relayUrl so a runtime URL change is picked up.
    const groupTransport = React.useMemo(
        () => new RelayTransport(relayUrl, 'group'),
        [relayUrl],
    );

    // Close the superseded transport when relayUrl changes so its socket does
    // not leak. Deliberately ref-based rather than a plain unmount cleanup:
    // React StrictMode double-invokes effects (mount → cleanup → mount) with
    // the SAME memoized instance, so an unmount cleanup would close the live
    // transport and never reopen it. This only closes an instance that was
    // genuinely replaced.
    const prevGroupTransportRef = React.useRef<RelayTransport | null>(null);
    React.useEffect(() => {
        const prev = prevGroupTransportRef.current;
        prevGroupTransportRef.current = groupTransport;
        if (prev && prev !== groupTransport) prev.close();
    }, [groupTransport]);

    const handleRelayUrlChange = React.useCallback((url: string) => {
        if (url === '') {
            // Reset: clear the override and fall back to the default resolution.
            localStorage.removeItem('relayWsUrl');
            setRelayUrl(getRelayWsUrl());
        } else {
            localStorage.setItem('relayWsUrl', url);
            setRelayUrl(url);
        }
    }, []);

    const recipientId = identity?.recipientId ?? null;
    const activeItem = NAV_ITEMS.find((item) => item.id === view)!;

    const handleCopyRecipientId = async () => {
        if (!recipientId) return;
        try {
            await navigator.clipboard.writeText(recipientId);
            setCopied(true);
            setTimeout(() => setCopied(false), 2000);
        } catch {
            // Clipboard API may be unavailable; ignore silently.
        }
    };

    return (
        <div className="shell">
            <div style={{ display: 'flex', flexDirection: 'column', flex: 1, minHeight: 0 }}>
                <Banner />
                <div className="shell-body">
                    <nav className="rail" aria-label="Sections">
                        <div className="rail-identity">
                            {recipientId ? (
                                <SealGlyph value={recipientId} size={40} title="Your identity seal" />
                            ) : (
                                <div style={{ width: 40, height: 40 }} />
                            )}
                            <span className="rail-identity-label">You</span>
                        </div>
                        {recipientId && (
                            <div className="rail-recipient-id">
                                <button
                                    type="button"
                                    className="rail-recipient-id-copy"
                                    onClick={handleCopyRecipientId}
                                    title="Copy your recipient ID"
                                >
                                    <code>{recipientId}</code>
                                    <span className="rail-recipient-id-copy-label">
                                        {copied ? 'Copied!' : 'Copy'}
                                    </span>
                                </button>
                            </div>
                        )}
                        <RelayConnectionPanel
                            status={conn.status}
                            error={conn.error}
                            resolvedUrl={conn.resolvedUrl}
                            relayUrl={relayUrl}
                            onRelayUrlChange={handleRelayUrlChange}
                            onRetry={conn.retry}
                        />
                        <div className="rail-nav">
                            {NAV_ITEMS.map((item) => (
                                <button
                                    key={item.id}
                                    type="button"
                                    className="rail-nav-item"
                                    aria-current={view === item.id ? 'page' : undefined}
                                    onClick={() => setView(item.id)}
                                >
                                    {item.label}
                                </button>
                            ))}
                        </div>
                    </nav>
                    <div className="shell-main">
                        <header className="view-header">
                            <div>
                                <h1>{activeItem.title}</h1>
                                <div className="view-header-sub">{activeItem.subtitle}</div>
                            </div>
                        </header>
                        <div className="view-body">
                            <div className="view-content">
                                {view === 'direct' && (
                                    <Conversation
                                        identity={identity ?? undefined}
                                        receiverSession={conn.receiverSession ?? undefined}
                                        onRemoteIdentityKeyChange={handleRemoteIdentityKeyChange}
                                        deviceList={deviceList}
                                        accountHandle={accountDeviceLink?.accountHandle}
                                        deviceId={accountDeviceLink?.deviceId}
                                    />
                                )}
                                {view === 'group' && (
                                    <GroupConversation
                                        identity={identity?.handle as unknown as GroupIdentity}
                                        selfRecipientId={recipientId ?? undefined}
                                        storageGate={sessionGate}
                                        transport={groupTransport}
                                    />
                                )}
                                {view === 'link' && (
                                    <SafetyNumberErrorBoundary>
                                        {identity && (
                                            <DeviceLinking
                                                localIdentityKey={identity.publicBytes}
                                                // The linked-devices section shows
                                                // THIS account's devices: the own
                                                // list when discovery has one, else
                                                // the injected list (tests / a
                                                // future DiscoveryRecord transport).
                                                deviceList={
                                                    ownList
                                                        ? {
                                                              version: ownList.version,
                                                              devices: ownList.devices,
                                                          }
                                                        : deviceList
                                                }
                                                // MD-18: revocation works for
                                                // BOTH sources — the held own
                                                // list (re-signed and
                                                // re-published at version+1)
                                                // and the injected list (local
                                                // shortcut). `handleRevokeDevice`
                                                // picks the path from whether a
                                                // signed own list is held.
                                                onRevokeDevice={handleRevokeDevice}
                                                // MD-17: hand the primary scan path
                                                // the exact signed bytes and version
                                                // App holds so it can enforce §8.4
                                                // freshness. Both come from the ONE
                                                // own-list state, so they never
                                                // diverge; `heldListVersion` is the
                                                // version actually held, or 0 ONLY
                                                // when there is genuinely no signed
                                                // list — never undefined/null, which
                                                // would disable the guard. Spread
                                                // through a cast because
                                                // DeviceLinkingProps does not yet
                                                // declare these (MD-16); the props
                                                // are inert until it does.
                                                {...({
                                                    currentListBytes: ownList?.bytes ?? null,
                                                    heldListVersion: ownList?.version ?? 0,
                                                } as Record<string, unknown>)}
                                            />
                                        )}
                                    </SafetyNumberErrorBoundary>
                                )}
                                {view === 'backup' && <BackupPanel storagePassword={getStoragePassword()} />}
                            </div>
                            {view === 'direct' && (
                                <aside className="trust-drawer" aria-label="Conversation trust">
                                    <h2>Verify this conversation</h2>
                                    <SafetyNumberErrorBoundary>
                                        {identity && remoteIdentityKey ? (
                                            <SafetyNumberVerification
                                                localIdentityKey={identity.publicBytes}
                                                remoteIdentityKey={remoteIdentityKey}
                                                conversationId={activePeerId}
                                            />
                                        ) : (
                                            <p className="trust-loading">
                                                Send a message to a recipient ID to see the safety
                                                number for this conversation.
                                            </p>
                                        )}
                                    </SafetyNumberErrorBoundary>
                                </aside>
                            )}
                        </div>
                    </div>
                </div>
            </div>
        </div>
    );
}
