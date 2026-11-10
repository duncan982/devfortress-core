/**
 * Tests for OAuthRedirectValidator's state-binding error message.
 *
 * TODO 311: the message used to end with "(Filing 2 Claim 7)" — a claim
 * number shipped in a runtime string, which the standing rule (no claim
 * numbers in code, comments or commit messages) bars regardless of
 * whether the cited number is otherwise correct. This asserts the
 * citation is gone while the message still tells a caller what happened
 * and how to fix it.
 */
import { OAuthRedirectValidator } from '../src/security-extensions';

describe('OAuthRedirectValidator state-binding error message', () => {
  it('throws when `state` is passed with no `stateSigningSecret` configured', () => {
    const validator = new OAuthRedirectValidator({
      allowedRedirectURIs: ['https://app.example.com/callback'],
    });

    expect(() =>
      validator.validate('https://app.example.com/callback', 'some-state')
    ).toThrow();
  });

  it('does not cite a claim or filing number', () => {
    const validator = new OAuthRedirectValidator({
      allowedRedirectURIs: ['https://app.example.com/callback'],
    });

    let message = '';
    try {
      validator.validate('https://app.example.com/callback', 'some-state');
    } catch (error) {
      message = (error as Error).message;
    }

    expect(message).not.toMatch(/Filing\s*\d/i);
    expect(message).not.toMatch(/Claim\s*\d/i);
  });

  it('still communicates what happened and how to fix it', () => {
    const validator = new OAuthRedirectValidator({
      allowedRedirectURIs: ['https://app.example.com/callback'],
    });

    let message = '';
    try {
      validator.validate('https://app.example.com/callback', 'some-state');
    } catch (error) {
      message = (error as Error).message;
    }

    expect(message).toMatch(/no `stateSigningSecret` is configured/);
    expect(message).toMatch(/HMAC state-redirect binding cannot be enforced/);
    expect(message).toMatch(/Configure `stateSigningSecret`/);
  });
});
