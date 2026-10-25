# keyhole

A personal secret store. One vault is one [`age`](https://github.com/FiloSottile/age) file.
This program decrypts it on your machine. It does not implement a cipher.

This is **version 0.1, unaudited**. Use it to learn the shape of a password manager.
Keep real accounts in Vaultwarden until this has been used on throwaway secrets for a long time.

License: AGPL-3.0-or-later. See `LICENSE`.

## What is safe to assume

- The file on disk is age ciphertext. A copy on a VPS, a USB stick, or a NAS is still ciphertext.
- Opening it needs an age identity. With a FIDO identity, that means the key and a touch.
- The `age` program must be `/usr/bin/age`, and its SHA-256 must match `age.pin`. `gpg` is pinned the same way in `gpg.pin`. After an upgrade, run `bash scripts/update-age-pin.sh` or `bash scripts/update-age-pin.sh gpg.pin` and type `yes`.
- A vault opens only when a pinned OpenPGP key signed it, and every age recipient is pinned. `rekey` is how recipients change.
- `keyhole` asks for the entry password on the terminal. It will not take that password as a command argument.
- `list` prints names. On a terminal, `get` shows the secret on a screen that is discarded when you press Enter. A pipe still receives the secret, because that program asked for it.

## Try it with a software key

```bash
cargo build --release
age-keygen -o /dev/shm/keyhole-identity.txt
# identity file stays secret. The recipient file is only the public line.
awk '/^# public key: /{print $4}' /dev/shm/keyhole-identity.txt > /dev/shm/keyhole-recipient.txt

mkdir -m 700 /dev/shm/keyhole-gpg /dev/shm/keyhole-state
GNUPGHOME=/dev/shm/keyhole-gpg gpg --batch --pinentry-mode loopback --passphrase '' \
  --quick-gen-key 'keyhole practice <practice@example.com>' ed25519 sign never
fpr=$(GNUPGHOME=/dev/shm/keyhole-gpg gpg --list-secret-keys --with-colons | awk -F: '/^fpr:/ {print $10; exit}')
export KEYHOLE_STATE_DIR=/dev/shm/keyhole-state GNUPGHOME=/dev/shm/keyhole-gpg
./target/release/keyhole trust allow-signer "$fpr"
./target/release/keyhole trust allow-recipient "$(cat /dev/shm/keyhole-recipient.txt)"

./target/release/keyhole init /dev/shm/vault.age -R /dev/shm/keyhole-recipient.txt
./target/release/keyhole add /dev/shm/vault.age -i /dev/shm/keyhole-identity.txt demo
./target/release/keyhole list /dev/shm/vault.age -i /dev/shm/keyhole-identity.txt
./target/release/keyhole get /dev/shm/vault.age -i /dev/shm/keyhole-identity.txt demo
shred -u /dev/shm/keyhole-identity.txt
```

A real vault should be encrypted to every recovery recipient you already have
(daily, backup, root, and the passphrase recipient), not to a single software key.

The picture of the system, including the versioned shelf, is in [docs/architecture.md](docs/architecture.md).
Update that file when the design changes.

## Shelf

A shelf stores age files and a version. It does not decrypt.

```bash
./target/release/keyhole push /tmp/shelf /dev/shm/vault.age --base 0
./target/release/keyhole pull /tmp/shelf /dev/shm/vault-copy.age
./target/release/keyhole serve /tmp/shelf 127.0.0.1:8787
```

A second push must pass the version printed by the first push. `--base 0` again is a conflict. The shelf keeps the newest five `vault.N.age` copies and deletes older ones, because a removed Bio can still open a copy from before rekey. `pull` refuses a version older than this machine has seen, unless you pass `--accept-older`. `bash scripts/protect-highwater.sh` marks that memory append-only. `serve` prints the path of `write.token`. GET is open. PUT needs `Authorization: Bearer` and that token, plus `X-Keyhole-Signature`.

## Idle lock

`daemon` decrypts the vault once and answers on a unix socket owned by you. It does not open a network port. `names` lists entries. `ask` shows one secret the same way `get` does. With no `names` or `ask` for the idle time, the process forgets the plaintext and keeps running. `unlock` reads the file again. `lock` forgets it now.

```bash
./target/release/keyhole daemon /dev/shm/vault.age -i /dev/shm/keyhole-identity.txt --idle 30
./target/release/keyhole names
./target/release/keyhole ask demo
./target/release/keyhole lock
```

The socket is `$XDG_RUNTIME_DIR/keyhole/session.sock`, or `$KEYHOLE_SOCKET` when that is set. A program you run can still talk to it. The secret strings are locked in RAM so they are not written to swap. That does not hide them from your own programs, and it does not cover hibernation.

## Not in this version

No browser extension, no phone app, no server that can decrypt.
