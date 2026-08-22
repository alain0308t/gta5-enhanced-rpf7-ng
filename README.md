# gta5-enhanced-rpf7-ng — write NG-encrypted RPF7 archives (GTA V Enhanced)

> [!IMPORTANT]
> **⚠️ 100% VIBECODED WITH [OPENCODE](https://opencode.ai) ⚠️**
> Every line of this repository was written by an AI coding agent running in
> [opencode](https://opencode.ai) — no human wrote this code. It started as a
> throwaway debugging session ("why does my modified update.rpf crash the game?")
> and ended up solving something nobody had published. The AI did the work; a human
> supervised and tested it on real hardware.
> Manage your expectations accordingly: it works, but treat it like an alien artifact.

First public implementation of the **encryption** direction of Rockstar's NG cipher
used by RPF7 archives in **GTA V Enhanced** (PC). If you got here because your
modified `update.rpf` crashes GTA V Enhanced, or because OpenIV doesn't support
Enhanced yet — this is the missing piece. Existing open-source tooling
([VIRUXE/rpf-rs](https://github.com/VIRUXE/rpf-rs), CodeWalker, etc.) can *decrypt*
NG archives but could not produce one the game accepts. This fork can: modified
archives built with it have been verified to **load in the real game**.

## What was missing and how it was recovered

The game ships only the *decryption* half of the cipher as data tables; the
encryption direction is never materialized anywhere. This repo reconstructs it with a
meet-in-the-middle inversion:

- Each NG round computes four dwords as XORs of four table lookups:
  `out_w = T[a][b0] ^ T[b][b1] ^ T[c][b2] ^ T[d][b3] ^ k[w]`
- For every (table-a, table-b) pair we precompute a 2^16 map from
  `T[a][x] ^ T[b][y] -> (x, y)`
- Given a target dword, brute-force the last two bytes (2^16) and look up the first
  two in the map → unique preimage per word
- Invert round-by-round from plaintext to ciphertext. ~0.04 s per 16-byte block,
  cached maps make subsequent blocks fast.

See `src/crypto/cipher.rs` (`encrypt_ng`) and `src/writer.rs` for integration into
archive building.

## Pitfalls you will hit otherwise (we did)

These cost us several days and seven game crashes. Learn from them:

1. **Key selection uses the archive basename.**
   `key_idx = (jenkins_hash(basename) + uncompressed_len + 61) % num_keys`.
   An archive encrypted as `my_build.rpf` is garbage if the game opens it as
   `update.rpf`. Whatever you build must end up on disk under the exact name whose
   hash selected the keys during encryption.

2. **The cipher leaves the tail unencrypted.**
   Both encrypt and decrypt process only whole 16-byte blocks; the final
   `len % 16` bytes are copied verbatim. That means when you splice a new blob into
   an existing archive slot ("surgical" editing), the game decrypts the *slot size*
   from the TOC — so you must pad your deflate stream to
   `floor(slot_len/16)*16` bytes **before** encrypting, then append the raw tail.
   Padding after encryption corrupts the stream (your plaintext tail gets
   "decrypted").

3. **Free space exists without resizing anything.**
   zlib level 9 beats Rockstar's compressor on many files. Recompressing an edited
   file often yields a *smaller* blob than the original slot, leaving slack for
   content additions without touching offsets or the TOC layout.

## Usage

```bash
# encrypt/decrypt a single entry blob (keys dir supplied by you — NOT included)
ngcrypt enc <keys_dir> plain.deflate out.bin common/data/dlclist.xml <uncompressed_len>
ngcrypt dec <keys_dir> out.bin plain.deflate common/data/dlclist.xml <uncompressed_len>
```

Library-wise, building an NG-encrypted RPF7 is the normal writer flow plus:

```rust
let mut builder = RpfBuilder::new(...);
builder.set_archive_name("update.rpf"); // selects NG key set at write time
// entries marked encrypted are deflated and NG-encrypted automatically
```

## Keys

No key material is included in this repository. `GtaKeys::load_from_path` expects a
directory with the usual key files that modding tools already distribute. If you
have a working setup for reading archives, you already have these files.

## Status / validation

- Round-trip verified against real vanilla blobs (encrypt(decrypt(x)) == x)
- Full-archive rebuild parsed back identically by our reader
- **In-game test passed**: a vanilla `update.rpf` with two entries replaced via the
  surgical technique above booted GTA V Enhanced and ran normally

## Credits

- Base library: [VIRUXE/rpf-rs](https://github.com/VIRUXE/rpf-rs) (public domain /
  MIT) — this fork adds the encryption half and the writer NG path
- Cipher table format and key hashes: prior community reverse-engineering work

## License

Same as upstream: public domain (see LICENSE).
