# keyhole

A personal secret store. One vault is one [`age`](https://github.com/FiloSottile/age) file.
This program decrypts it on your machine. It does not implement a cipher.

This is **version 0.1, unaudited**. Use it to learn the shape of a password manager.
Keep real accounts in Vaultwarden until this has been used on throwaway secrets for a long time.

License: AGPL-3.0-or-later. See `LICENSE`.

## What is safe to assume

- The file on disk is age ciphertext. A copy on a VPS, a USB stick, or a NAS is still ciphertext.
- Opening it needs an age identity. With a FIDO identity, that means the key and a touch.
- `keyhole` asks for the entry password on the terminal. It will not take that password as a command argument.
- `list` prints names. `get` prints the secret on stdout.

## Try it with a software key

```bash
cargo build --release
age-keygen -o /dev/shm/keyhole-identity.txt
# identity file stays secret. The recipient file is only the public line.
awk '/^# public key: /{print $4}' /dev/shm/keyhole-identity.txt > /dev/shm/keyhole-recipient.txt

./target/release/keyhole init /dev/shm/vault.age -R /dev/shm/keyhole-recipient.txt
./target/release/keyhole add /dev/shm/vault.age -i /dev/shm/keyhole-identity.txt demo
./target/release/keyhole list /dev/shm/vault.age -i /dev/shm/keyhole-identity.txt
./target/release/keyhole get /dev/shm/vault.age -i /dev/shm/keyhole-identity.txt demo
shred -u /dev/shm/keyhole-identity.txt
```

A real vault should be encrypted to every recovery recipient you already have
(daily, backup, root, and the passphrase recipient), not to a single software key.

## Not in this version

No browser extension, no phone app, no accounts, no server that can decrypt.
Sync, for now, is copying the `.age` file. That is intentional.
