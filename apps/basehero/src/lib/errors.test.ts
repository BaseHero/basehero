import { describe, expect, it } from 'vitest';
import { BackendError } from './backend/types';
import { errorMessage, messageFor } from './errors';

describe('account errors', () => {
  it.each([
    ['BadCredentials', 'Email or password is wrong.'],
    ['BadKit', "That kit doesn't match this account."],
    ['Network', "Can't reach BaseHero. Check your connection."],
    ['RateLimited', 'Too many tries. Wait a few minutes, then try again.'],
    ['NeedsUpdate', 'This version of BaseHero is too old. Update it to continue.'],
  ])('%s', (kind, expected) => expect(messageFor(kind)).toBe(expected));
  it('distinguishes used invites and taken email addresses', () => {
    expect(errorMessage(new BackendError('Conflict', 'invite_used'))).toBe('That invite code has already been used.');
    expect(errorMessage(new BackendError('Conflict', 'email_taken'))).toBe('That email already has an account.');
  });
});
