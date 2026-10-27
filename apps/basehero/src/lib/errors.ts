import { BackendError } from './backend/types';

export function messageFor(kind: string, message = ''): string {
  switch (kind) {
    case 'BadCredentials': return 'Email or password is wrong.';
    case 'BadKit': return "That kit doesn't match this account.";
    case 'Network': return "Can't reach BaseHero. Check your connection.";
    case 'RateLimited': return 'Too many tries. Wait a few minutes, then try again.';
    case 'NeedsUpdate': return 'This version of BaseHero is too old. Update it to continue.';
    case 'Conflict': return message.includes('invite_used') ? 'That invite code has already been used.' :
      message.includes('email_taken') ? 'That email already has an account.' : 'That account already exists.';
    default: return 'Something went wrong. Try again.';
  }
}

export function errorMessage(error: unknown): string {
  return error instanceof BackendError ? messageFor(error.kind, error.message) : messageFor('Network');
}
