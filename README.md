# he-comparisons

Run:
```
cargo +nightly bench
```

Benchmarks:
```
Additive ElGamal Addition
                        time:   [409.57 ns 413.69 ns 419.27 ns]
Additive ElGamal Encryption
                        time:   [92.820 µs 93.017 µs 93.264 µs]
Additive ElGamal Decryption (range = 100)
                        time:   [57.443 µs 59.885 µs 64.184 µs]
Additive ElGamal Decryption (range = 1000)
                        time:   [281.46 µs 284.23 µs 288.02 µs]
Additive ElGamal Decryption (range = 10000)
                        time:   [2.5094 ms 2.5141 ms 2.5192 ms]

Paillier Addition (1024-bit primes)
                        time:   [15.387 µs 15.441 µs 15.499 µs]
Paillier Encryption (1024-bit primes)
                        time:   [5.6121 ms 5.6172 ms 5.6231 ms]
Paillier Decryption (1024-bit primes)
                        time:   [5.5104 ms 5.5184 ms 5.5296 ms

FHE Addition            time:   [3.3372 µs 3.3590 µs 3.3882 µs]
FHE Encryption          time:   [278.29 µs 281.99 µs 286.18 µs]
FHE Decryption          time:   [2.5861 µs 2.5894 µs 2.5931 µs]
```