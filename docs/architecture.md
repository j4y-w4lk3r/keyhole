# Keyhole architecture

This is the picture of the system. Update it when the design changes.
GitHub renders the diagrams below.

Keyhole is one age file, unlocked on your machine. A shelf, when you use one, stores that file and a version number. The shelf does not decrypt.

## The machine and the shelf

```mermaid
flowchart TB
  subgraph yours ["Your machine"]
    cli["keyhole CLI"]
    ram["Unlocked vault, RAM only"]
    file["vault.age on disk"]
    cli --> ram
    cli --> file
  end

  subgraph shelf ["Shelf, later a VPS"]
    api["push / pull, or HTTP GET and PUT"]
    disk["vault.N.age plus a version number"]
    api --> disk
  end

  file -->|"push only if --base matches"| api
  api -->|"pull ciphertext and version"| file
```

The operating system stores bytes and carries TCP. It does not know what a password is.
HTTPS, when the shelf is on another computer, is ordinary TLS around those same bytes.

## What sits inside an age file

```mermaid
flowchart LR
  items["Items: name, username, password"]
  json["JSON plaintext, RAM only"]
  filekey["Random file key"]
  wrap["X25519 wrap, one stanza per recipient"]
  body["ChaCha20-Poly1305 ciphertext"]
  items --> json --> filekey --> body
  filekey --> wrap
```

| Piece | Role in Keyhole |
| --- | --- |
| File | The vault. Not a database server. Decrypting it yields a JSON list of items. |
| Cipher | ChaCha20-Poly1305, inside age. Hides the bytes and detects a changed byte. |
| Wrap | X25519. Each recipient gets one stanza in the header. Any one stanza opens the file. |
| KDF | Only if you use an age passphrase. age uses scrypt. A Bio recipient has no password KDF. |
| Account key | The random file key above. Your password or Bio only unwraps it. |
| Second door | WebAuthn on Vaultwarden today. Not part of this file yet. |

## Versioned push

Two laptops must not silently overwrite each other.

```mermaid
sequenceDiagram
  participant A as Laptop A
  participant S as Shelf
  A->>S: pull
  S-->>A: vault.age, version 4
  Note over A: decrypt, edit, encrypt
  A->>S: push --base 4
  alt shelf is still 4
    S-->>A: stored as version 5
  else someone else stored version 5
    S-->>A: conflict
    A->>S: pull version 5 and edit again
  end
```

`keyhole push` implements this against a directory. `keyhole serve` exposes the same rule over HTTP on `/v1/vault`, with `If-Match` as the version you pulled and `X-Keyhole-Version` on the reply.

## Choices we are keeping

- **One encryption format: age.** GPG stays available for signatures. A menu of ciphers creates two ways to lose a vault.
- **X25519 and ChaCha20-Poly1305.** This is the current age design. A later hybrid post-quantum mode should arrive as an age upgrade, not as a second format.
- **The 1Password idea, in age's shape.** A stolen file must not be openable with only a password. Encrypt to the hardware recipients, and keep the identity off the shelf. A software identity sitting next to the vault is the practice setup, not the real one.
- **Argon2id and scrypt are the password KDFs to use.** There is not a stronger everyday replacement. More memory makes guessing harder until the unlock becomes unpleasant.
- **Secrets are typed at a prompt.** They are not command arguments, and they are not log lines. Error text does not include an item, a password, or the identity contents.
- **The process refuses three leaks.** Core dumps are off. `get` on a terminal uses the alternate screen and waits for Enter. The identity file must be mode 600 or 400, owned by you, and not a link.
- **`age` is pinned.** Keyhole runs `/usr/bin/age` only when its SHA-256 matches `age.pin`. That pin is compiled into the binary. An upgrade is `bash scripts/update-age-pin.sh`, which asks for yes, rewrites `age.pin`, and rebuilds.

## Where the shelf runs

The shelf listens on this machine at `127.0.0.1`, or later on a Tailscale address. It has no public port. Tailscale already hides the café address from the VPS. A Mullvad exit node is for browsing the public web. Vault sync stays on the tailnet.

PiKVM stores no vault secrets. The laptop's system disk encryption is a later maintenance window.

## Not built yet

A write token on `serve`. A laptop-side record of the highest shelf version. An OpenPGP signature checked before decrypt, and an explicit `rekey`. A daemon that locks on idle comes later, then a browser extension that can ask for one confirmed origin.
