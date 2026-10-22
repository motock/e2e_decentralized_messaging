import React from 'react';
import { SealGlyph } from './design/SealGlyph';
import { useGroupConversation } from './useGroupConversation';
import type { IdentityHandle } from '../../../core/bindings/wasm/pkg/index.js';
import type { StorageGate } from './storage';
import './GroupConversation.css';

// The state machine and side effects (group crypto, StorageGate persistence,
// receive loop, send path) live in useGroupConversation.ts; this module is the
// presentation layer plus the public prop/transport surface other modules and
// tests import.
export type { GroupMessage, GroupMessageResult } from './useGroupConversation';

// Sender Keys group crypto UI on top of the WASM group bindings
// (group_create/group_add_member/group_remove_member/group_encrypt/
// group_decrypt - core/bindings/wasm/src/lib.rs).
//
// Members are real peers, added by recipient ID. The component looks up the
// peer's published prekey bundle via `lookupPrekey` (RelayTransport, same as
// direct messaging in Conversation.tsx), extracts the identity key with
// `bundle_identity_key_bytes`, and passes that real looked-up public key to
// `group_add_member`. There is no demo/local-identity member path: every chip
// in the member list is a relay-reachable peer.
//
// Group membership (the member list with recipient IDs and public keys) is
// persisted via the existing StorageGate pattern (encrypted IndexedDB), so
// it survives a page reload — matching how identity persistence already works
// in identity.ts.
//
// The group's *sender-key ratchet state* is persisted too, via the real
// serialize/restore bindings (group_to_bytes / group_from_bytes,
// core/bindings/wasm/src/lib.rs). The persisted blob is what lets a reload
// resume the running session instead of starting a new one. Starting a new one
// is not itself a key-reuse hazard: GroupSession::new seeds the chain key from
// a fresh CSPRNG (core/protocol/src/group.rs), not from the sender's public
// key, so a rebuilt session cannot re-derive a (key, nonce) pair the old one
// already used. The reuse hazard is resuming a *stale* blob: a restored chain
// that lags the last ciphertext emitted would encrypt from a position already
// used. The save therefore happens before each send, and a failed save aborts
// the send. The serialized blob is secret ratchet state (the chain key,
// verbatim), so it is stored ONLY through the encrypted StorageGate, never
// plaintext, and never logged. On reload the component restores the session
// with group_from_bytes; only a record that predates ratchet persistence (no
// blob) falls back to replaying group_create + group_add_member, and a record
// whose blob is present but corrupt fails closed (no group is restored).

/**
 * The transport surface `GroupConversation` needs for looking up a real
 * peer's published prekey bundle. `RelayTransport` satisfies this; tests
 * inject a mock that implements only this narrow interface so the crypto
 * boundary stays real while the network boundary is mocked — the same
 * pattern as Conversation.tsx's `ConversationTransport`.
 */
export interface GroupTransport {
    lookupPrekey(recipientId: string): Promise<Uint8Array>;
    sendEnvelope(recipientId: string, envelope: Uint8Array): Promise<void>;
    /**
     * Pick up a stored envelope addressed to `recipientId` (the local user's own
     * recipient ID). Returns the raw envelope bytes — a `Uint8Array` carrying
     * the envelope's out-of-band kind tag (GRP-6) as a non-enumerable `kind`
     * property (`"direct"` | `"group"`, or `undefined` when the relay sent no
     * tag: the "missing kind" fall-through signal). Rejects with an error whose
     * message is "NotFound" or "Expired" when the mailbox is empty — the receive
     * loop treats these as a normal empty poll, not an exceptional condition.
     *
     * The declared return type is the union the real transport can produce:
     * the bytes themselves, or a `{ envelope, kind? }` result. Callers
     * normalize with `picked instanceof Uint8Array ? picked : picked.envelope`
     * (the real transport self-aliases `envelope` on the bytes, so both arms
     * yield the same bytes).
     */
    pickupEnvelope(
        recipientId: string,
    ): Promise<Uint8Array | { envelope: Uint8Array; kind?: string }>;
}

export interface GroupConversationProps {
    /** Defaults to a real `RelayTransport`; tests inject a mock here. */
    transport?: GroupTransport;
    /**
     * An opened `StorageGate` for persisting group membership. If omitted,
     * the component creates one from `globalThis.indexedDB` (production path).
     * Tests inject a mock to simulate persistence across reloads.
     */
    storageGate?: StorageGate;
    /**
     * The local persisted identity, used for group_create, group_encrypt and
     * group_decrypt. REQUIRED: there is no demo-identity fallback. Omitting
     * this prop (or `selfRecipientId`) makes the component fail closed — it
     * renders a visible "unavailable" alert, starts no receive loop, and never
     * generates a demo identity.
     */
    identity?: InstanceType<typeof IdentityHandle>;
    /**
     * The local user's own recipient ID (base64 of their public key). REQUIRED
     * alongside `identity` — the receive loop polls the relay for envelopes
     * addressed to this ID. Omitting either prop fails closed.
     */
    selfRecipientId?: string;
}

export const GroupConversation: React.FC<GroupConversationProps> = ({
    transport,
    storageGate,
    identity: identityProp,
    selfRecipientId,
}) => {
    const {
        ready,
        error,
        group,
        realMembers,
        removedRealMembers,
        messages,
        input,
        setInput,
        peerIdInput,
        setPeerIdInput,
        addingPeer,
        peerError,
        decryptionWarning,
        sendError,
        createGroup,
        addPeer,
        removePeer,
        reAddPeer,
        send,
    } = useGroupConversation({ transport, storageGate, identity: identityProp, selfRecipientId });

    if (error) {
        return <div role="alert" className="group-error">Group conversation unavailable: {error}</div>;
    }

    if (!ready) {
        return <div className="group-loading">Loading…</div>;
    }

    return (
        <div data-testid="group-conversation" className="group-view">
            {!group ? (
                <button onClick={createGroup} data-testid="create-group-button" className="group-create group-create-button">
                    Create Group
                </button>
            ) : (
                <>
                    <div data-testid="member-list" className="group-members">
                        {realMembers.length === 0 && removedRealMembers.length === 0 && (
                            <p data-testid="member-list-empty" className="group-members-empty">
                                No members yet. Add a peer by recipient ID.
                            </p>
                        )}
                        {realMembers.map((m) => (
                            <div key={m.recipientId} data-testid={`member-${m.recipientId}`} className="member-chip in-group">
                                <SealGlyph value={m.recipientId} size={20} tone="verified" title={`${m.recipientId}'s seal`} />
                                <span className="member-chip-name">{m.recipientId}</span>
                                <button onClick={() => removePeer(m.recipientId)} data-testid={`remove-peer-${m.recipientId}`}>
                                    Remove
                                </button>
                            </div>
                        ))}
                        {removedRealMembers.map((m) => (
                            <div key={m.recipientId} className="member-chip">
                                <SealGlyph value={m.recipientId} size={20} tone="neutral" title={`${m.recipientId}'s seal`} />
                                <span className="member-chip-name">{m.recipientId}</span>
                                <button onClick={() => reAddPeer(m.recipientId)} data-testid={`add-peer-${m.recipientId}`}>
                                    Add
                                </button>
                            </div>
                        ))}
                    </div>
                    <div className="group-peer-add">
                        <input
                            value={peerIdInput}
                            onChange={(e) => setPeerIdInput(e.target.value)}
                            placeholder="Recipient ID"
                            data-testid="group-peer-id-input"
                            className="group-input"
                        />
                        <button onClick={addPeer} disabled={addingPeer} data-testid="add-peer-button" className="group-add-peer">
                            {addingPeer ? 'Adding…' : 'Add Peer'}
                        </button>
                        {peerError && (
                            <div role="alert" className="group-peer-error">{peerError}</div>
                        )}
                    </div>
                    <div data-testid="group-message-list" className="group-log">
                        {messages.length === 0 ? (
                            <p className="group-empty">No messages yet.</p>
                        ) : (
                            messages.map((msg) => (
                                <div
                                    key={msg.id}
                                    data-testid={`message-${msg.id}`}
                                    data-group-id={msg.groupId}
                                    className="group-msg"
                                >
                                    {!msg.sentByMe && msg.senderLabel && (
                                        <span
                                            className="group-msg-sender"
                                            data-testid={`sender-${msg.id}`}
                                            title={msg.senderId}
                                        >
                                            {msg.senderLabel}
                                        </span>
                                    )}
                                    <p className="group-msg-text">{msg.plaintext}</p>
                                    {msg.sentByMe && msg.sendStatus && (
                                        <span
                                            className={`group-msg-status status-${msg.sendStatus}`}
                                            data-testid={`send-status-${msg.id}`}
                                            title={msg.sendError}
                                        >
                                            {msg.sendStatus === 'sent'
                                                ? 'sent'
                                                : msg.sendStatus === 'partial'
                                                  ? `sent to ${(msg.sendTotal ?? 0) - (msg.sendFailures ?? 0)} of ${msg.sendTotal ?? 0}`
                                                  : 'failed'}
                                        </span>
                                    )}
                                </div>
                            ))
                        )}
                    </div>
                    <div className="group-composer">
                        <input
                            value={input}
                            onChange={(e) => setInput(e.target.value)}
                            placeholder="Type a group message"
                            data-testid="group-message-input"
                            className="group-input"
                        />
                        <button onClick={send} data-testid="group-send-button" className="group-send">
                            Send
                        </button>
                    </div>
                    {decryptionWarning && (
                        <p className="group-warning" role="alert">{decryptionWarning}</p>
                    )}
                    {sendError && (
                        <p className="group-warning group-send-error" role="alert">{sendError}</p>
                    )}
                </>
            )}
        </div>
    );
};
