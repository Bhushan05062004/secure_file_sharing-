"""Performance evaluation: AES-256-GCM vs RSA key operations.
Run:  python benchmark.py   (writes benchmark_results.csv)"""
import csv
import os
import time

import crypto_utils as cu

SIZES = [("1 KB", 1024), ("100 KB", 100 * 1024), ("1 MB", 1 << 20),
         ("5 MB", 5 << 20), ("16 MB", 16 << 20)]
REPEAT = 5


def avg(fn):
    t = time.perf_counter()
    for _ in range(REPEAT):
        fn()
    return (time.perf_counter() - t) / REPEAT * 1000


def main():
    t = time.perf_counter()
    priv, pub = cu.generate_rsa_keypair(3072)
    keygen = (time.perf_counter() - t) * 1000
    aes = os.urandom(32)
    wrap_ms = avg(lambda: cu.wrap_key(pub, aes))
    w = cu.wrap_key(pub, aes)
    unwrap_ms = avg(lambda: cu.unwrap_key(priv, w))
    print(f"RSA-3072 keygen {keygen:.0f} ms | wrap {wrap_ms:.2f} ms | unwrap {unwrap_ms:.2f} ms\n")
    print(f"{'Size':<8}{'Encrypt ms':>12}{'Decrypt ms':>12}{'MB/s (enc)':>12}")
    rows = []
    for label, n in SIZES:
        data = os.urandom(n)
        key, blob = cu.encrypt_bytes(data, b"bench")
        enc = avg(lambda: cu.encrypt_bytes(data, b"bench"))
        dec = avg(lambda: cu.decrypt_bytes(key, blob, b"bench"))
        thr = (n / 1048576) / (enc / 1000)
        print(f"{label:<8}{enc:>12.2f}{dec:>12.2f}{thr:>12.1f}")
        rows.append([label, n, round(enc, 3), round(dec, 3), round(thr, 1),
                     round(wrap_ms, 3), round(unwrap_ms, 3)])
    with open("benchmark_results.csv", "w", newline="") as fh:
        w = csv.writer(fh)
        w.writerow(["size", "bytes", "aes_encrypt_ms", "aes_decrypt_ms", "aes_MBps",
                    "rsa_wrap_ms", "rsa_unwrap_ms"])
        w.writerows(rows)
    print("\nSaved benchmark_results.csv")


if __name__ == "__main__":
    main()
