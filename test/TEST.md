# `TEST`

Smoke test with a synthetic database. Generates a `KDBX4`/`Argon2id` and a `KDBX3` file with a known password, then cracks them with the bundled wordlist.

```
$ python3 test/mk_kdbx.py
[+] wrote test/v4_argon2id.kdbx (password: liverpool)
[+] wrote test/v3_aeskdf.kdbx (password: P@ssw0rd123)

$ jennifer test/v4_argon2id.kdbx
[*] kdbx v4  kdf=Argon2id  t=2 m=8KiB p=1
[*] wordlist=src/wordlists.txt  candidates=36  threads=4
[+] cracked: liverpool

$ jennifer test/v3_aeskdf.kdbx
[*] kdbx v3  kdf=AES-KDF  rounds=1000
[*] wordlist=src/wordlists.txt  candidates=36  threads=4
[+] cracked: P@ssw0rd123
```

Both files are generated locally by `test/mk_kdbx.py` using the standard KeePass crypto, so the test is a real end-to-end check of the header parse, KDF paths, and both oracles. `mk_kdbx.py` ships in `test/` so anyone can regenerate the fixtures.
