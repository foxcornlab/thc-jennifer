#!/usr/bin/env python3
"""Generate synthetic KDBX3 / KDBX4 databases with a known password,
using the standard KeePass crypto, to smoke-test jennifer end-to-end."""
import os, struct, hashlib, hmac
from Crypto.Cipher import AES
from argon2.low_level import hash_secret_raw, Type

OUT = os.path.join(os.path.dirname(os.path.abspath(__file__)))

SIG1 = 0x9AA2D903
SIG2_V3 = 0xB54BFB65
SIG2_V4 = 0xB54BFB67
AES_UUID = bytes.fromhex("31c1f2e6bf714350be5805216a5cf5a8")
ARGON2ID_UUID = bytes.fromhex("9e298b1956db4773b23dfc3e8af005a7")

def composite(pw: bytes) -> bytes:
    return hashlib.sha256(hashlib.sha256(pw).digest()).digest()

def aes_kdf(comp: bytes, seed: bytes, rounds: int) -> bytes:
    blk = comp
    c = AES.new(seed, AES.MODE_ECB)
    for _ in range(rounds):
        blk = c.encrypt(blk)
    return hashlib.sha256(blk).digest()

def tlv3(fid: int, data: bytes) -> bytes:
    return struct.pack("<BH", fid, len(data)) + data

def tlv4(fid: int, data: bytes) -> bytes:
    return struct.pack("<BI", fid, len(data)) + data

def vdict(entries) -> bytes:
    # entries: list of (vtype, key: bytes, value: bytes)
    out = struct.pack("<H", 1)  # VariantDictionary version
    for vtype, key, val in entries:
        out += struct.pack("<B", vtype)
        out += struct.pack("<I", len(key)) + key
        out += struct.pack("<I", len(val)) + val
    out += b"\x00"
    return out

def make_v3(path: str, password: str, rounds: int = 1000):
    master_seed = os.urandom(32)
    tseed = os.urandom(32)
    iv = os.urandom(16)
    stream_start = os.urandom(32)

    xform = aes_kdf(composite(password.encode()), tseed, rounds)
    master = hashlib.sha256(master_seed + xform).digest()
    payload = AES.new(master, AES.MODE_CBC, iv).encrypt(stream_start + b"\x00" * 32)

    hdr = struct.pack("<III", SIG1, SIG2_V3, 0x00030000)
    hdr += tlv3(3, AES_UUID)
    hdr += tlv3(4, master_seed)
    hdr += tlv3(5, tseed)
    hdr += tlv3(6, struct.pack("<Q", rounds))
    hdr += tlv3(7, iv)
    hdr += tlv3(8, os.urandom(32))
    hdr += tlv3(9, stream_start)
    hdr += tlv3(10, struct.pack("<I", 1))
    hdr += tlv3(0, b"\r\n\r\n")

    with open(path, "wb") as f:
        f.write(hdr + payload)
    print(f"[+] wrote {path} (password: {password})")

def make_v4_argon2id(path: str, password: str, t: int = 2, m_kib: int = 8, p: int = 1):
    master_seed = os.urandom(32)
    iv = os.urandom(16)
    salt = os.urandom(16)

    xform = hash_secret_raw(composite(password.encode()), salt,
                            time_cost=t, memory_cost=m_kib,
                            parallelism=p, hash_len=32, type=Type.ID)
    pre_key = hashlib.sha512(master_seed + xform + b"\x01").digest()
    hmac_key = hashlib.sha512(b"\xff" * 8 + pre_key).digest()

    kd = vdict([
        (0x18, b"$UUID", ARGON2ID_UUID),
        (0x18, b"S", salt),
        (0x0C, b"I", struct.pack("<Q", t)),
        (0x0C, b"M", struct.pack("<Q", m_kib * 1024)),
        (0x04, b"P", struct.pack("<I", p)),
    ])

    hdr = struct.pack("<III", SIG1, SIG2_V4, 0x00040000)
    hdr += tlv4(2, AES_UUID)
    hdr += tlv4(3, struct.pack("<I", 0))
    hdr += tlv4(4, master_seed)
    hdr += tlv4(7, iv)
    hdr += tlv4(11, kd)
    hdr += tlv4(0, b"\r\n\r\n")

    hdr_sha = hashlib.sha256(hdr).digest()
    hdr_hmac = hmac.new(hmac_key, hdr, hashlib.sha256).digest()

    with open(path, "wb") as f:
        f.write(hdr + hdr_sha + hdr_hmac)
    print(f"[+] wrote {path} (password: {password})")

if __name__ == "__main__":
    make_v4_argon2id(os.path.join(OUT, "v4_argon2id.kdbx"), "liverpool")
    make_v3(os.path.join(OUT, "v3_aeskdf.kdbx"), "P@ssw0rd123")
