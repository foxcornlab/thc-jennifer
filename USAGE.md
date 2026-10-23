# `USAGE`

```
  thc-jennifer v2.1 || Foxcorn Lab

usage: jennifer <db.kdbx> [wordlist] [-v] [-d] [-t <n>] [-T <us>]

  -v       print each candidate
  -d       dump parsed header fields
  -t <n>   threads (default 4)
  -T <us>  throttle microseconds per attempt per thread
```

## `command`

```
jennifer <kdbx-file>
jennifer <kdbx-file> <wordlist>
jennifer <kdbx-file> <wordlist> -v
jennifer <kdbx-file> -d <wordlist>      # header dump + crack
jennifer <kdbx-file> rockyou.txt -t 8   # 8 threads
```

Without a custom wordlist it uses `src/wordlists.txt` (or `$JENNIFER_WORDLIST`, or the installed path). `-v` prints each candidate as it's tried — noisy, useful for watching it work.

## `contact`

For write-ups and real-world use cases see [`README.md`](README.md). Security concerns: open an issue at https://github.com/foxcornlab/thc-jennifer/issues or reach out via https://me.xeea.net.
