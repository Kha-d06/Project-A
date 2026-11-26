# Vault cryptography

This specifies what `apps/web/src/lib/vault.ts` and `lib/vault-sharing.ts` do
today, what they protect against and what they don't, and the reviewed plan for
changing the key derivation. The browser extension imports the same module, so
it behaves identically.

## 1. Keys

```
master password ──NFC──► PBKDF2-SHA256 (600,000 iterations, 16-byte random salt) ──► KEK (AES-256-GCM, wrap/unwrap only)
                                                                                      │ wraps
random 256-bit vault key (AES-256-GCM, non-extractable once unwrapped) ◄──────────────┘
        │ encrypts
vault document (JSON, padded to a multiple of 1 KiB)
```

- **Master password:** never sent to the server, and separate from the account password. At least 12 characters (`MIN_MASTER_LENGTH`).
- **Wrapped key:** `iv (12 random bytes) ‖ AES-GCM(KEK, raw vault key)`, with associated data `sentinel-vault:1:<user id>:key`.
- **Vault data:** `iv (12 random bytes) ‖ AES-GCM(vault key, padded JSON)`, with associated data `sentinel-vault:1:<user id>:data`.
- **Nonces:** random 96-bit IVs. With one key encrypting at most a few thousand saves over a vault's life, the random-IV collision bound is far below concern.
- **Associated data** binds each ciphertext to the account and to its role. A vault copied into another account, or the two fields swapped, doesn't decrypt.
- **Changing the master password** generates a new salt, KEK *and* vault key, and re-encrypts everything (`changeMasterPassword`).
- **Stored on the server:** `kdf {name, iterations, salt}`, `wrapped_key`, `data`, `version`. The server can't decrypt any of them.

## 2. What's inside

The vault document holds:
- logins, notes and passkeys;
- TOTP secrets (`otpauth://` or base32), generated on the device;
- the person's sharing key pair, and the recipients' key fingerprints they have checked.

Keeping TOTP secrets in the vault puts both factors behind the master password. The interface says so and suggests a separate authenticator for email, banking and the Qalaa account itself.

## 3. Sharing and emergency access

- Each person has an ECDH P-256 key pair. The private key lives inside their encrypted vault; the public key is published.
- **To share:** generate an ephemeral key pair, run ECDH with the recipient's public key, and encrypt the entry with AES-256-GCM under the derived key (random IV). The server relays the ciphertext and the ephemeral public key.
- **Emergency access:** a snapshot of the vault is sealed the same way to the trusted contact, then released by the server after the waiting period unless the owner denies it.
- **Key verification:**
  - Each key has a fingerprint: the first 128 bits of SHA-256 over the SPKI, shown as 8 groups of 4 hex digits.
  - The recipient's fingerprint is remembered inside the vault at first share.
  - A different key later blocks sharing until the person confirms they compared it.
  - This is trust on first use. Comparing fingerprints in person or by phone is what makes the first share safe.
- **Known weaknesses** (format v2 planned, audit QA-14):
  - The ECDH output is used directly as the AES key, with no HKDF and no context.
  - There is no associated data.
  - Shares aren't signed by the sender, so the server could forge a share that appears to come from someone.

## 4. Threats

| Threat | Protected? |
|---|---|
| Database or backup stolen | Yes. Offline guessing costs 600,000 PBKDF2 rounds per guess, so a weak master password is still guessable. |
| Server operator reads vaults | Not with the stored data. |
| Server substitutes a sharing key | Detected after first share (pinned fingerprint); undetected at first share unless fingerprints are compared. |
| **Server serves malicious vault JavaScript** | **No.** The web vault runs the code the server sends. Use the extension or the native app for vault work; they ship separately. Audit QA-12. |
| XSS on the dashboard | Limited by a nonce-based `strict-dynamic` CSP; any XSS on the vault page would still be serious. |
| Malware on the unlocked device | No. It can read memory and keystrokes. |
| Forgotten master password | Not recoverable today. See §5. |
| Rollback (server serves an older vault) | Not prevented. The `version` counter stops lost updates between devices, but isn't authenticated. |

## 5. Planned: Argon2id and a recovery kit (not shipped)

Decided with the project owner. Before any code touches real vaults, this plan has to be reviewed. Its rules:

1. **Library.** Argon2id from libsodium's `crypto_pwhash` (libsodium.js, an exact version at least two weeks old), loaded as WebAssembly in both the web app and the extension. No custom Argon2.
2. **Parameters.** Memory 64 MiB, 3 passes, parallelism 1, 16-byte salt. This is above OWASP's minimum (19 MiB, 2 passes) and around one second on a mid-range phone; measure on target devices before fixing it. The parameters are stored: `kdf: {name: "Argon2id", memory_kib, passes, parallelism, salt}`.
3. **Read before write.**
   - Release A teaches every client (web and extension) to *unlock* Argon2id vaults.
   - Only release B starts *writing* them.
   - A device on an older version can never meet a vault it can't open.
4. **Migration at unlock, never blind.**
   - After a successful PBKDF2 unlock, derive the Argon2id KEK with a fresh salt and **re-wrap the same vault key**; the data isn't re-encrypted.
   - Save with the expected `version`; if another device saved first, keep the old wrapping and retry next time.
   - The PBKDF2 unlock path stays for vaults that haven't migrated.
   - No server-side job and no forced re-encryption.
5. **Recovery kit** (opt-in, offered at migration and at vault creation).
   - A random 256-bit recovery key is shown once, as a printable kit (text plus QR code).
   - It wraps the vault key separately (`recovery_wrapped_key`, associated data `…:recovery`).
   - To recover: enter the kit, unwrap the vault key, set a new master password. A new kit is issued, and the old wrapping is deleted.
   - Changing the master password keeps the recovery wrapping only if the person still holds the kit.
   - The server can't reset a vault. Losing both the master password and the kit still loses the vault, and the interface says so.
6. **Tests before release.**
   - Known-answer vectors for Argon2id from the libsodium test suite.
   - Round trips: PBKDF2 vault → unlock → migrate → unlock with Argon2id.
   - A concurrent save from a second device.
   - Recovery with the kit.
   - The same vectors run in the extension's tests.

## 6. Web vault caveat

Until vault code is delivered separately from the server (a signed, integrity-pinned
bundle, or vault work moved to the extension and native app), the web vault's
end-to-end encryption holds against a stolen database, not against a compromised
web server. The vault page should say this next to the feature.
