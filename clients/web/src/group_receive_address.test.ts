import { describe, expect, it } from 'vitest';
import { groupReceiveAddress } from './useGroupConversation';

// GF-4: the group receive loop must poll *this device's* mailbox, not the
// account's bare handle. The address rule is the same one the direct
// Conversation loop uses (MD-17b): device 0 is addressed bare, a linked device
// is addressed `${accountHandle}:${deviceId}`.
describe('groupReceiveAddress', () => {
    it('should_poll_the_bare_handle_for_the_primary_device', () => {
        // In App, accountHandle IS selfRecipientId (both identity.recipientId),
        // so the primary device polls the bare handle.
        expect(
            groupReceiveAddress({ accountHandle: 'acct-handle', deviceId: 0, selfRecipientId: 'acct-handle' }),
        ).toBe('acct-handle');
    });

    it('should_fall_back_to_self_recipient_id_for_device_zero', () => {
        // Same rule as the direct Conversation loop (MD-17b): only device >= 1
        // is device-qualified; device 0 keeps the pre-GF-4 address.
        expect(
            groupReceiveAddress({ accountHandle: 'acct-handle', deviceId: 0, selfRecipientId: 'self-id' }),
        ).toBe('self-id');
    });

    it('should_poll_the_device_qualified_mailbox_for_a_linked_device', () => {
        expect(
            groupReceiveAddress({ accountHandle: 'acct-handle', deviceId: 2, selfRecipientId: 'self-id' }),
        ).toBe('acct-handle:2');
    });

    it('should_poll_self_recipient_id_when_no_props_are_supplied', () => {
        expect(groupReceiveAddress({ selfRecipientId: 'self-id' })).toBe('self-id');
    });

    it('should_fall_back_to_self_recipient_id_when_device_id_is_undefined', () => {
        expect(
            groupReceiveAddress({ accountHandle: 'acct-handle', selfRecipientId: 'self-id' }),
        ).toBe('self-id');
    });

    it('should_fall_back_to_self_recipient_id_when_device_id_is_null', () => {
        expect(
            groupReceiveAddress({
                accountHandle: 'acct-handle',
                deviceId: null as unknown as number,
                selfRecipientId: 'self-id',
            }),
        ).toBe('self-id');
    });

    it('should_fall_back_to_self_recipient_id_when_account_handle_is_missing', () => {
        expect(groupReceiveAddress({ deviceId: 2, selfRecipientId: 'self-id' })).toBe('self-id');
    });

    it('should_fall_back_to_self_recipient_id_when_account_handle_is_empty', () => {
        expect(
            groupReceiveAddress({ accountHandle: '', deviceId: 2, selfRecipientId: 'self-id' }),
        ).toBe('self-id');
    });

    it('should_fall_back_to_self_recipient_id_for_a_negative_device_id', () => {
        expect(
            groupReceiveAddress({ accountHandle: 'acct-handle', deviceId: -1, selfRecipientId: 'self-id' }),
        ).toBe('self-id');
    });

    it('should_return_undefined_when_nothing_is_known', () => {
        expect(groupReceiveAddress({})).toBeUndefined();
    });
});
