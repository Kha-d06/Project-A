# Vault key-derivation migration: specification for review

**Status: proposal. Nothing here is implemented.** No code that writes the new
format may merge until an independent reviewer has signed off on §10, and no
release may *write* the new format until the "read" release (§6, release A) has
been out for the agreed period. Current behaviour is specified in
[vault-crypto.md](vault-crypto.md).

## 1. Goals and non-goals

**Goals:**
- Replace PBKDF2 with a memory-hard KDF (Argon2id).
- Add an optional recovery kit.
- Lock no one out, lose no data, and never require the server to hold anything that decrypts a vault.

**Non-goals:**
- Changing the vault cipher (AES-256-GCM stays) or the document format.
- Changing sharing (format v2 for sharing is a separate change, audit QA-14).
- Server-side password reset (impossible by design).

## 2. Current key hierarchy (format 1, deployed)

```
master password ─NFC─► PBKDF2-HMAC-SHA256(salt 16 B, 600,000 it.) ─► KEK₁ (AES-256-GCM, wrapKey/unwrapKey)
KEK₁ ─wraps─► VK (random 256-bit AES-GCM key)           AAD "sentinel-vault:1:<uid>:key"
VK   ─encrypts─► padded JSON document                    AAD "sentinel-vault:1:<uid>:data"
```

Stored on the server (`vaults` table): `kdf {name:"PBKDF2-SHA256", iterations, salt}`, `wrapped_key` (base64, 60 bytes: iv 12 ‖ ciphertext 32 ‖ tag 16), `data`, `version`.

Server validation (`app/api/vault.py`):
- the name must be `PBKDF2-SHA256`;
- iterations between 310,000 and 10,000,000;
- salt 16 to 64 bytes;
- wrapped key exactly 60 bytes;
- a save must name the current `version`, or it is refused with 409.

## 3. Proposed key hierarchy (format 1, KDF 2)

```
master password ─NFC─► Argon2id(salt 16 B, m = 65,536 KiB, t = 3, p = 1, out 32 B) ─► KEK₂
KEK₂ ─wraps─► VK                                         AAD "sentinel-vault:1:<uid>:key"      (unchanged)
recovery key RK (random 32 B) ─HKDF-SHA256(info "qalaa-vault-recovery:1")─► KEKᵣ
KEKᵣ ─wraps─► VK   (optional)                            AAD "sentinel-vault:1:<uid>:recovery"
VK ─encrypts─► document                                  AAD "sentinel-vault:1:<uid>:data"     (unchanged)
```

- **VK doesn't change** during migration, so the document isn't re-encrypted. Only the wrapping changes. That is what makes the migration small and reversible on the client.
- **The Argon2id output** is imported as a raw AES-GCM key (non-extractable, `wrapKey`/`unwrapKey` usages).
- **The parameters are stored**, so they can be raised later the same way.
- **Library:**
  - preferred: libsodium's `crypto_pwhash` with `ALG_ARGON2ID13` (libsodium.js "sumo" build, ISC licence, WebAssembly, audited upstream);
  - alternative: `hash-wasm` (MIT).
  - Exact version at least two weeks old, pinned; no custom implementation.
- **Parameter floor and ceiling,** enforced by both the client and the server: memory 19,456 to 1,048,576 KiB, passes 2 to 10, parallelism 1 to 4, output 32 bytes. The floor is the OWASP minimum, so a server can't make a client save a weaker vault.

## 4. Stored format

```jsonc
{
  "kdf": {
    "name": "Argon2id",
    "memory_kib": 65536,
    "passes": 3,
    "parallelism": 1,
    "salt": "<base64 16 B>"
  },
  "wrapped_key": "<base64 60 B, under KEK₂>",
  "recovery": {                       // optional
    "wrapped_key": "<base64 60 B, under KEKᵣ>",
    "kit_id": "<base64 8 B: first 8 bytes of SHA-256(RK)>",  // lets the UI say "kit created on …" and detect a mismatched kit early
    "created_at": "<ISO time>"
  },
  "data": "<unchanged>",
  "version": 42
}
```

Server changes (one Alembic migration, hand-written):
- add a nullable `recovery` JSON column;
- `Kdf` becomes a tagged union of PBKDF2-SHA256 and Argon2id, with the bounds above;
- `recovery.wrapped_key` must be exactly 60 bytes;
- the column defaults to null, and existing rows are untouched;
- `alembic check` in CI.

## 5. Client algorithms

### 5.1 Unlock (release A and later)

```
unlock(stored, master, uid):
  if stored.kdf.name == "PBKDF2-SHA256": KEK = pbkdf2(master, stored.kdf)          # check iterations ≥ 310,000
  elif stored.kdf.name == "Argon2id":    KEK = argon2id(master, stored.kdf)        # check bounds (§3)
  else: error "This vault was saved by a newer version of Qalaa. Update the app."
  VK = AES-GCM-unwrap(KEK, stored.wrapped_key, AAD key)     # failure → WrongMasterPassword
  doc = AES-GCM-decrypt(VK, stored.data, AAD data)
  remember locally: account uid uses <kdf name>              # §7, downgrade warning
```

### 5.2 Migrate (release B and later; only right after a successful PBKDF2 unlock)

```
migrate(stored, master, VK_extractable_once, uid):
  salt = random(16); KEK₂ = argon2id(master, salt, params)
  wrapped₂ = AES-GCM-wrap(KEK₂, VK, AAD key)
  # Prove the new wrapping opens before sending it:
  assert AES-GCM-unwrap(argon2id(master, salt, params), wrapped₂, AAD key) == VK   (compare by test-decrypting stored.data)
  PUT /vault {kdf: Argon2id…, wrapped_key: wrapped₂, data: stored.data (unchanged), expected_version: stored.version}
  on 409: discard wrapped₂, keep PBKDF2, retry at next unlock
  on network error: keep PBKDF2; nothing is half-applied, because the server stores the row atomically
```

- **Extracting VK:** `VK` must be extractable once, for wrapping only. Unwrap it a second time with `extractable: true` inside `migrate`, use it, and drop the reference. The working key stays non-extractable.
- **Timing:** migration runs only when the person isn't in the middle of an edit, shows "Strengthening your vault's protection…", and can be skipped for the session.
- **Device budget:** if Argon2id with m = 64 MiB fails (out of memory on a low-end phone), stay on PBKDF2 and report it. **Never fall back to weaker Argon2id parameters automatically.**

### 5.3 Change of master password

As today, a new VK and full re-encryption, now always with Argon2id. Any recovery wrapping is removed, because it wraps the old VK. The person is offered a new kit right after.

### 5.4 Recovery kit

- **Creation** (opt-in: offered at vault creation, after migration, and in settings):
  1. RK = 32 random bytes.
  2. KEKᵣ = HKDF-SHA256(RK, salt = empty, info = "qalaa-vault-recovery:1").
  3. Wrap VK under KEKᵣ, then PUT with `expected_version`.
  4. Show the kit once:
     - **text:** `QALAA-RK1-` followed by RK in Crockford base32 (no I, L, O, U), in groups of 4, with a 4-character CRC-32-derived checksum group so typos are caught before any network call;
     - **QR code** of the same text;
     - a printable page that names the account e-mail and the date, never the master password.
  5. Ask the person to type the last group back before closing.
- **Use:**
  1. Sign in to the account.
  2. "Unlock with recovery kit": parse and validate the checksum, derive KEKᵣ, unwrap `recovery.wrapped_key`, and decrypt the document to prove it.
  3. Ask for a new master password.
  4. Do §5.3 (new VK, Argon2id), then issue a new kit. The old kit stops working because its wrapping is deleted.
- **Limits, stated in the interface:**
  - the kit opens the vault without the master password, so it must be stored like a house key;
  - losing both the master password and the kit loses the vault;
  - the server can't help, by design.

## 6. Rollout and rollback

| Release | Web vault | Extension | Writes | Reads |
|---|---|---|---|---|
| current | PBKDF2 | PBKDF2 | PBKDF2 | PBKDF2 |
| **A** | + Argon2id unlock, recovery-kit *use* | same | PBKDF2 only | both |
| **B** (≥ 4 weeks after A, and when ≥ 95 % of extension installs report A or later) | + migration, recovery-kit *creation* | same | Argon2id | both |
| later | — | — | Argon2id | both (PBKDF2 unlock kept indefinitely for vaults never reopened) |

- **Rolling back B to A is safe:** A reads everything B writes.
- **Rolling back A:** nothing has been written in the new format, so it is safe too.
- **No server-side rollback.** The server never converts vaults.
- **Old extensions** (before A) facing an Argon2id vault reach the existing "Unknown key-derivation method" error. Release A changes that wording to "Update the Qalaa extension to open this vault" for anything newer.
- **Kill switch:** a server setting `vault_migration_enabled` (default off) gates the *offer* to migrate in release B. Turning it off stops new migrations at once; already-migrated vaults keep working.

## 7. Threats specific to the migration

| Threat | Mitigation |
|---|---|
| Server serves old PBKDF2 parameters for a migrated vault (downgrade) | The Argon2id wrapping won't unwrap under PBKDF2, so the unlock fails. If the server substitutes an *older PBKDF2 row* (from a backup), the client has remembered locally that this account migrated, and warns "This vault is protected less strongly than last time. Contact your administrator." It still allows unlock, since the data is the person's own. |
| Server lowers Argon2id parameters | Client floor (§3); the client refuses to save below it and warns on unlock below it. |
| Database backups keep the PBKDF2 wrapping | Old backups stay as weak as before. The operator documentation says to expire backups older than the migration window; the audit notes it. |
| Recovery wrapping stolen with the database | Useless without the kit (256-bit key). |
| Kit photographed | Equivalent to the master password; the interface says so. |
| Crash mid-migration | Single atomic PUT; the old wrapping stays valid until the new one is stored. |
| Two devices migrate at once | `expected_version` makes one fail with 409; it keeps the other's result at next load. |

## 8. Tests required before release A and B

- **Argon2id known-answer:** RFC 9106 §5.3 test vector, and the library's own vectors, in the web (vitest) and extension test suites.
- **Round trips:**
  - PBKDF2 vault → unlock (A);
  - PBKDF2 → migrate → unlock with Argon2id (B);
  - migrate → change master → unlock;
  - recovery create → recover → new master → old kit refused.
- **Concurrency:** migration racing a save from another device (simulated 409).
- **Failure injection:** out-of-memory in Argon2id → stays PBKDF2 and the vault opens; network failure mid-PUT → still opens with PBKDF2.
- **Bounds:** the server rejects below-floor parameters (pytest); the client rejects below-floor parameters from the server.
- **Downgrade warning** when a migrated account is served a PBKDF2 row.
- **Kit:** checksum catches every single-character typo and adjacent swap in a generated test set.
- **Performance:** measured unlock time on three reference devices (mid-range Android phone, five-year-old laptop, current desktop). The target is ≤ 1.5 s on the phone, or the parameters are reconsidered with the reviewer, never silently.

## 9. Interface text (EN and AR, both required)

New strings, with Arabic translations reviewed by a native speaker:
- migration progress and skip;
- out-of-memory explanation;
- recovery-kit creation, confirmation and use;
- the downgrade warning;
- "update the extension".

No text may say the vault is "safe" or recovery is "guaranteed".

## 10. Review sign-off (required before any write path merges)

The reviewer confirms, in writing:
1. The key hierarchy (§3) and associated-data strings are sound and domain-separated.
2. Argon2id parameters and bounds are appropriate for the device budget (§8 measurements attached).
3. The migration algorithm (§5.2) can't leave a vault unopenable under any single failure.
4. The recovery-kit derivation, encoding and storage are sound.
5. The rollout (§6) guarantees no client meets a format it can't read.
6. The test list (§8) is complete and passes.

**Approval gates:**
- the owner approves release A after review item 5;
- the owner approves enabling `vault_migration_enabled` after all six items and the A adoption threshold.
