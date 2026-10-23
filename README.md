# `thc-jennifer`

KeePass `.kdbx` password recovery that actually handles every modern format: `KDBX3` and `KDBX4`, `AES-KDF` and `Argon2d`/`Argon2id`. Parses the database header itself, derives each candidate's composite key in-process with real crypto (`OpenSSL` + `libargon2`), and verifies against the file's own integrity check. No shelling out, no temp files, wordlist streamed so a 10M-entry list doesn't eat your RAM.

```
  ____  _____  _____  _____  ___  _____  _____  _____ 
  \_  \/   __\/  _  \/  _  \/___\/   __\/   __\/  _  \
---|  ||   __||  |  ||  |  ||   ||   __||   __||  _  <
\_____/\_____/\__|__/\__|__/\___/\__/   \_____/\__|\__\

  thc-jennifer v2.1 || Foxcorn Lab
```

## `what it does`

- Cracks `KDBX3` (KeePass 2.x, AES-KDF with transform rounds) and `KDBX4` (AES-KDF / Argon2d / Argon2id)
- Reads the header itself: master seed, transform seed, rounds, Argon2 salt/params, stream-start bytes
- `v3` oracle: decrypts the first payload block with the derived master key, compares `stream start bytes`
- `v4` oracle: `HMAC-SHA256` over the raw header with the block key, same check KeePass itself uses
- Multi-threaded worker pool with a bounded queue, live attempts/min + ETA
- Streams the wordlist (`128KB` chunks) instead of loading it into memory
- Ships a starter wordlist in `src/wordlists.txt` for quick testing

## `build`

```
apt install libssl-dev libargon2-dev -y
make
```

or one line:

```
gcc -O2 -pthread jennifer.c -lssl -lcrypto -largon2 -o jennifer
```

`make install` drops the binary in `/usr/local/bin` and the starter wordlist in `/usr/local/share/jennifer/src/`. After an install you can run it from anywhere: without an explicit wordlist it checks `$JENNIFER_WORDLIST`, then `src/wordlists.txt`, then the installed path.

## `usage`

```
jennifer <db.kdbx> [wordlist] [-v] [-d] [-t <n>] [-T <us>]

  -v       print each candidate as it is tried
  -d       dump parsed header fields (version, KDF, params)
  -t <n>   threads (default 4)
  -T <us>  throttle, microseconds of sleep per attempt per thread
```

Example against a `KDBX4` database:

```
$ jennifer recovery.kdbx test.lst

[*] kdbx v4  kdf=Argon2d  t=37 m=65536KiB p=4
[*] wordlist=test.lst  candidates=6  threads=4

[~] 6/6 (100.0%) | 180/min | ETA 0s
[+] cracked: liverpool
```

Header dump when you just want to see what format you're dealing with:

```
$ jennifer locked.kdbx -d rockyou.txt
```

## `notes`

- Argon2 is deliberately expensive; `t=37 m=65536KiB p=4` style headers (KeePass defaults scale with your CPU) will be slow per attempt. That is the KDF doing its job. Use `-t` to match your core count.
- The `v4` check is the header `HMAC`: the tool only ever reads the file, it never writes to it and never needs the real payload decrypted.
- Cracking your own locked database or one you're explicitly authorised to test. That's the whole point of the tool; keep it that way.

## `thanks to`

- The KeePass authors for a documented, sane file format
- The `OpenSSL` and `libargon2` teams for the crypto plumbing

## `disclaimer`

For educational and authorised security testing use only. Recovering passwords from databases you don't own or aren't authorised to test is illegal in most places. Don't be that person.

> Research by `Vineeth Kumar` (`foxcornlab`). Found a bug or want a feature, open an `issue`.
