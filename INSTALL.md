# `INSTALL`

## `deps`

```
apt install libssl-dev libargon2-dev -y
```

## `build`

```
make
```

## `install` (optional)

```
sudo make install
```

Installs `jennifer` to `/usr/local/bin` and the starter wordlist to `/usr/local/share/jennifer/src/wordlists.txt`.

## `uninstall`

```
sudo rm /usr/local/bin/jennifer
sudo rm -rf /usr/local/share/jennifer
```

Full usage lives in [`README.md`](README.md) and [`USAGE.md`](USAGE.md).
