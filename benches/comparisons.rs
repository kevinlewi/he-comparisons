#[macro_use]
extern crate criterion;
use criterion::Criterion;

use elgamal_ristretto::private::SecretKey;
use elgamal_ristretto::public::PublicKey;
use rand_core::OsRng;
use std::fs::File;
use std::io::{Read, Write};

use concrete::prelude::*;
use concrete::{generate_keys, set_server_key, ClientKey, ConfigBuilder, FheUint8, ServerKey};

use libpaillier::{unknown_order::BigNumber, *};

lazy_static::lazy_static! {
    /// This is an example for using doc comment attributes
    static ref FHE_KEYS: (ClientKey, ServerKey) = {
        write_keys("client_key.bin", "server_key.bin");
        read_keys("client_key.bin", "server_key.bin")
    };
}

fn elgamal_add(c: &mut Criterion) {
    let label = format!("Additive ElGamal Addition");
    c.bench_function(&label, move |b| {
        let mut csprng = OsRng;
        let sk = SecretKey::new(&mut csprng);
        let pk = PublicKey::from(&sk);

        let c1 = pk.encrypt_additive(100);
        let c2 = pk.encrypt_additive(200);

        b.iter(|| c1 + c2)
    });
}

fn elgamal_encrypt(c: &mut Criterion) {
    let label = format!("Additive ElGamal Encryption");
    c.bench_function(&label, move |b| {
        let mut csprng = OsRng;
        let sk = SecretKey::new(&mut csprng);
        let pk = PublicKey::from(&sk);

        b.iter(|| {
            pk.encrypt_additive(100);
        })
    });
}

fn elgamal_decrypt_100(c: &mut Criterion) {
    let label = format!("Additive ElGamal Decryption (range = 100)");
    c.bench_function(&label, move |b| {
        let mut csprng = OsRng;
        let sk = SecretKey::new(&mut csprng);
        let pk = PublicKey::from(&sk);

        let ctxt = pk.encrypt_additive(100);

        b.iter(|| {
            sk.decrypt_additive(&ctxt, 1000000);
        })
    });
}

fn elgamal_decrypt_1000(c: &mut Criterion) {
    let label = format!("Additive ElGamal Decryption (range = 1000)");
    c.bench_function(&label, move |b| {
        let mut csprng = OsRng;
        let sk = SecretKey::new(&mut csprng);
        let pk = PublicKey::from(&sk);

        let ctxt = pk.encrypt_additive(1000);

        b.iter(|| {
            sk.decrypt_additive(&ctxt, 1000000);
        })
    });
}

fn elgamal_decrypt_10000(c: &mut Criterion) {
    let label = format!("Additive ElGamal Decryption (range = 10000)");
    c.bench_function(&label, move |b| {
        let mut csprng = OsRng;
        let sk = SecretKey::new(&mut csprng);
        let pk = PublicKey::from(&sk);

        let ctxt = pk.encrypt_additive(10000);

        b.iter(|| {
            sk.decrypt_additive(&ctxt, 1000000);
        })
    });
}

fn fhe_add(c: &mut Criterion) {
    let label = format!("FHE Addition");

    let (client_key, server_key) = FHE_KEYS.clone();
    set_server_key(server_key);

    let clear_a = 15_u64;
    let clear_b = 27_u64;

    let c1 = FheUint8::try_encrypt(clear_a, &client_key).unwrap();
    let c2 = FheUint8::try_encrypt(clear_b, &client_key).unwrap();

    c.bench_function(&label, move |b| b.iter(|| &c1 + &c2));
}

fn fhe_encrypt(c: &mut Criterion) {
    let label = format!("FHE Encryption");

    let (client_key, server_key) = FHE_KEYS.clone();
    set_server_key(server_key);

    let clear_a = 15_u64;

    c.bench_function(&label, move |b| {
        b.iter(|| FheUint8::try_encrypt(clear_a, &client_key).unwrap())
    });
}

fn fhe_decrypt(c: &mut Criterion) {
    let label = format!("FHE Decryption");

    let (client_key, server_key) = FHE_KEYS.clone();
    set_server_key(server_key);

    let clear_a = 15_u64;
    let clear_b = 27_u64;

    let a = FheUint8::try_encrypt(clear_a, &client_key).unwrap();
    let b = FheUint8::try_encrypt(clear_b, &client_key).unwrap();
    let d = a + b;

    c.bench_function(&label, move |b| {
        b.iter(|| {
            let result: u64 = d.decrypt(&client_key);
            result
        })
    });
}

// Functions for reading and writing to file for FHE keys

fn write_keys(client_key_file: &str, server_key_file: &str) {
    let config = ConfigBuilder::all_disabled().enable_default_uint8().build();
    let (client_key, server_key) = generate_keys(config);

    // We serialize the keys to bytes:
    let mut encoded_client_key: Vec<u8> = vec![];
    bincode::serialize_into(&mut encoded_client_key, &client_key).unwrap();
    let mut encoded_server_key = vec![];
    bincode::serialize_into(&mut encoded_server_key, &server_key).unwrap();

    // We write the keys to files:
    let mut file = File::create(client_key_file).expect("failed to create client key file");
    file.write_all(encoded_client_key.as_slice())
        .expect("failed to write key to file");
    let mut file = File::create(server_key_file).expect("failed to create server key file");
    file.write_all(encoded_server_key.as_slice())
        .expect("failed to write key to file");
}

fn read_keys(client_key_file: &str, server_key_file: &str) -> (ClientKey, ServerKey) {
    // We retrieve the keys:
    let mut file = File::open(client_key_file).expect("failed to open client key file");
    let mut encoded_client_key: Vec<u8> = Vec::new();
    file.read_to_end(&mut encoded_client_key)
        .expect("failed to read the key");

    let mut file = File::open(server_key_file).expect("failed to open server key file");
    let mut encoded_server_key: Vec<u8> = Vec::new();
    file.read_to_end(&mut encoded_server_key)
        .expect("failed to read the key");

    // We deserialize the keys:
    let loaded_client_key: ClientKey =
        bincode::deserialize(&encoded_client_key[..]).expect("failed to deserialize");
    let loaded_server_key: ServerKey =
        bincode::deserialize(&encoded_server_key[..]).expect("failed to deserialize");

    (loaded_client_key, loaded_server_key)
}

fn paillier_add(c: &mut Criterion) {
    let res = DecryptionKey::random();
    let sk = res.unwrap();
    let pk = EncryptionKey::from(&sk);

    let m1 = BigNumber::random(&BigNumber::from(10000));
    let m2 = BigNumber::random(&BigNumber::from(10000));
    let (c1, _) = pk.encrypt(m1.to_bytes(), None).unwrap();
    let (c2, _) = pk.encrypt(m2.to_bytes(), None).unwrap();

    let label = format!("Paillier Addition (1024-bit primes)");
    c.bench_function(&label, move |b| b.iter(|| pk.add(&c1, &c2).unwrap()));
}

fn paillier_encrypt(c: &mut Criterion) {
    let res = DecryptionKey::random();
    let sk = res.unwrap();
    let pk = EncryptionKey::from(&sk);

    let m1 = BigNumber::random(&BigNumber::from(10000));

    let label = format!("Paillier Encryption (1024-bit primes)");
    c.bench_function(&label, move |b| {
        b.iter(|| {
            pk.encrypt(m1.to_bytes(), None);
        })
    });
}

fn paillier_decrypt(c: &mut Criterion) {
    let res = DecryptionKey::random();
    let sk = res.unwrap();
    let pk = EncryptionKey::from(&sk);

    let m1 = BigNumber::random(&BigNumber::from(10000));
    let res = pk.encrypt(m1.to_bytes(), None).unwrap();
    let (ctxt, _) = res;

    let label = format!("Paillier Decryption (1024-bit primes)");
    c.bench_function(&label, move |b| {
        b.iter(|| {
            sk.decrypt(&ctxt);
        })
    });
}

criterion_group!(
    benches,
    elgamal_add,
    elgamal_encrypt,
    elgamal_decrypt_100,
    elgamal_decrypt_1000,
    elgamal_decrypt_10000,
    paillier_add,
    paillier_encrypt,
    paillier_decrypt,
    fhe_add,
    fhe_encrypt,
    fhe_decrypt,
);
criterion_main!(benches);
