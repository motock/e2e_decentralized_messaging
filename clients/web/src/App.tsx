import React from 'react';
import Banner from './Banner';
import { Conversation } from './Conversation';
import { SafetyNumberVerification } from './SafetyNumberVerification';
import { BackupPanel } from './BackupPanel';
import { GroupConversation } from './GroupConversation';
import { DeviceLinking } from './DeviceLinking';
import { ensureWasmInit } from './wasm_init';
import { SealGlyph } from './design/SealGlyph';
import { StorageGate } from './storage';
import { getStorageKey, getStoragePassword } from './storage_key';
import { loadOrGenerateIdentity, type PersistedIdentity } from './identity';
import { getRelayWsUrl, RelayTransport } from './relay_transport';
import { useRelayConnection, RelayConnectionPanel } from './useRelayConnection';
import { applyDeviceListUpdate, type DeviceList } from './deviceList';
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
    const conn = useRelayConnection(identity, relayUrl, sessionGate);

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
                                            <DeviceLinking localIdentityKey={identity.publicBytes} />
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
