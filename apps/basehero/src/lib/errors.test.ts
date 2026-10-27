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
  it.each([
    ['invite_used: Invite already used', 'That invite code has already been used.'],
    ['email_taken: Email already in use', 'That email already has an account.'],
  ])('shows the right sign-up conflict for %s from the shell', (message, expected) => {
    expect(errorMessage(new BackendError('Conflict', message))).toBe(expected);
  });
});
