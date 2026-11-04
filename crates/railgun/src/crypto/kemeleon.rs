//! Kemeleon encoding of ML-KEM-768 ciphertexts (draft-irtf-cfrg-kemeleon, rejection-sampling
//! variant `EncodeCtxtR` / `DecodeCtxtR`): a ciphertext becomes 1252 bytes that cannot be told
//! from random bytes without breaking MLWE.
//!
//! [`crate::note::encrypt::hybrid`] needs this to mask the KEM ciphertext with a stream cipher.
//! A raw ciphertext is not uniform (`Compress_10` gives 257 of its 1024 values four preimages
//! mod q and the others three), so whoever tries a candidate mask would recognise the right one
//! by the distribution of what comes out.
//!
//! ```text
//! c_1   768 coefficients mod 2^10: Decompress, uniform preimage mod q, one integer
//!       r = Σ u_i·q^i < q^768. Reject if r ≥ 2^8986, else the 6 spare top bits of its
//!       1124 big-endian bytes are random.
//! c_2   256 coefficients mod 2^4, kept as is (128 bytes). Reject with probability 1/209 per
//!       zero coefficient: 0 has 209 preimages under Compress_4, every other value 208.
//! ```
//!
//! Encoding fails with probability about 0.23 and the caller encapsulates again. Decoding is
//! total: any 1252 bytes decode to some ciphertext, which a wrong key decapsulates to an
//! unrelated secret (implicit rejection). The encoding randomness must stay secret, so it comes
//! from the caller's CSPRNG. Big-integer arithmetic is not constant time; it only ever handles
//! the ciphertext, never a key.

use std::sync::OnceLock;

use num_bigint::BigUint;
use num_integer::Integer;
use rand::{CryptoRng, RngExt};

use crate::crypto::kem::{CIPHERTEXT_SIZE, KemCiphertext};

const Q: u32 = 3329;
const N: usize = 256;
const K: usize = 3;
const DU: u32 = 10;
const DV: u32 = 4;
const C1_COEFFICIENTS: usize = K * N;
const C1_SIZE: usize = 32 * DU as usize * K;
const C2_SIZE: usize = 32 * DV as usize;

/// `bit_length(q^768) - 1`: an accepted integer is below `2^R_BITS`.
const R_BITS: u64 = 8986;
/// `ceil(R_BITS / 8)`.
const R_SIZE: usize = 1124;
/// The top `R_SIZE * 8 - R_BITS` bits of the integer, randomised: the low two bits of byte 0.
const R_TOP_MASK: u8 = 0b0000_0011;

/// Size of an encoded ML-KEM-768 ciphertext.
pub const ENCODED_SIZE: usize = R_SIZE + C2_SIZE;

/// `q^5 < 2^63`: the integer is split in base `q^5` rather than coefficient by coefficient.
const Q64: u64 = Q as u64;
const Q5: u64 = Q64.pow(5);
const CHUNK: usize = 5;
const CHUNKS: usize = C1_COEFFICIENTS.div_ceil(CHUNK);

/// Number of `Compress_4` preimages of 0, one more than of any other value.
const C2_ZERO_PREIMAGES: u32 = 209;

/// `round(2^d·x / q) mod 2^d` (FIPS 203, eq. 4.7). `q` is odd, so there is never a tie.
fn compress(x: u32, d: u32) -> u32 {
    (((x << (d + 1)) + Q) / (2 * Q)) & ((1 << d) - 1)
}

/// `round(q·y / 2^d)` (FIPS 203, eq. 4.8).
fn decompress(y: u32, d: u32) -> u32 {
    (2 * Q * y + (1 << d)) >> (d + 1)
}

/// `ByteDecode_d` (FIPS 203, alg. 6): `d`-bit coefficients, least significant bit first.
fn byte_decode(bytes: &[u8], d: u32) -> Vec<u32> {
    let count = bytes.len() * 8 / d as usize;
    (0..count)
        .map(|i| {
            (0..d as usize).fold(0u32, |acc, j| {
                let bit = i * d as usize + j;
                acc | ((u32::from(bytes[bit / 8] >> (bit % 8)) & 1) << j)
            })
        })
        .collect()
}

/// `ByteEncode_d` (FIPS 203, alg. 5).
fn byte_encode(coefficients: &[u32], d: u32) -> Vec<u8> {
    let mut bytes = vec![0u8; coefficients.len() * d as usize / 8];
    for (i, &c) in coefficients.iter().enumerate() {
        for j in 0..d as usize {
            let bit = i * d as usize + j;
            bytes[bit / 8] |= (((c >> j) & 1) as u8) << (bit % 8);
        }
    }
    bytes
}

/// Every `x mod q` with `Compress_10(x) = c`: three or four values, all within 2 of
/// `Decompress_10(c)`.
fn preimages_10(c: u32) -> ([u32; 4], usize) {
    let u = decompress(c, DU);
    let mut out = [0u32; 4];
    let mut len = 0;
    for delta in [Q - 2, Q - 1, 0, 1, 2] {
        let x = (u + delta) % Q;
        if compress(x, DU) == c {
            out[len] = x;
            len += 1;
        }
    }
    (out, len)
}

/// Kemeleon encoding of `ciphertext`, or `None` (probability about 0.23): encapsulate again.
pub(crate) fn encode(
    ciphertext: &KemCiphertext,
    rng: &mut dyn CryptoRng,
) -> Option<[u8; ENCODED_SIZE]> {
    let bytes = ciphertext.as_bytes();

    let c1 = byte_decode(&bytes[..C1_SIZE], DU);
    let u: Vec<u64> = c1
        .iter()
        .map(|&c| {
            let (candidates, len) = preimages_10(c);
            u64::from(candidates[rng.random_range(0..len)])
        })
        .collect();

    let mut r = BigUint::default();
    for chunk in u.chunks(CHUNK).rev() {
        let value = chunk.iter().rev().fold(0u64, |acc, &x| acc * Q64 + x);
        r = r * Q5 + value;
    }
    if r.bits() > R_BITS {
        return None;
    }

    let c2 = &bytes[C1_SIZE..CIPHERTEXT_SIZE];
    for coefficient in byte_decode(c2, DV) {
        if coefficient == 0 && rng.random_range(0..C2_ZERO_PREIMAGES) == 0 {
            return None;
        }
    }

    let r_bytes = r.to_bytes_be();
    let mut encoded = [0u8; ENCODED_SIZE];
    encoded[R_SIZE - r_bytes.len()..R_SIZE].copy_from_slice(&r_bytes);
    encoded[0] |= rng.random::<u8>() & !R_TOP_MASK;
    encoded[R_SIZE..].copy_from_slice(c2);
    Some(encoded)
}

/// Depth of the decoding tree: `2^TREE_DEPTH ≥ CHUNKS`.
const TREE_DEPTH: usize = 8;

/// `q^5` to the powers `2^0 … 2^(TREE_DEPTH-1)`: the split points of the decoding tree.
fn split_powers() -> &'static [BigUint; TREE_DEPTH] {
    static POWERS: OnceLock<[BigUint; TREE_DEPTH]> = OnceLock::new();
    POWERS.get_or_init(|| {
        let mut power = BigUint::from(Q5);
        std::array::from_fn(|_| {
            let current = power.clone();
            power = &power * &power;
            current
        })
    })
}

/// The base-`q^5` digits of `r` into `out` (`2^level` of them), least significant first, by
/// splitting `r` around `q^(5·2^(level-1))` recursively. Scanning decodes every hybrid note on
/// chain, and this tree is several times faster than peeling one `q^5` digit at a time.
fn split_digits(r: &BigUint, level: usize, out: &mut [u64]) {
    if r.bits() == 0 {
        out.fill(0);
        return;
    }
    if level == 0 {
        out[0] = r.to_u64_digits()[0];
        return;
    }
    let power = &split_powers()[level - 1];
    let (high, low) = r.div_rem(power);
    let (out_low, out_high) = out.split_at_mut(out.len() / 2);
    split_digits(&low, level - 1, out_low);
    split_digits(&high, level - 1, out_high);
}

/// The ciphertext an encoding stands for. Total: any bytes decode.
pub(crate) fn decode(encoded: &[u8; ENCODED_SIZE]) -> KemCiphertext {
    let mut r_bytes = [0u8; R_SIZE];
    r_bytes.copy_from_slice(&encoded[..R_SIZE]);
    r_bytes[0] &= R_TOP_MASK;
    let r = BigUint::from_bytes_be(&r_bytes);

    let mut chunks = [0u64; 1 << TREE_DEPTH];
    split_digits(&r, TREE_DEPTH, &mut chunks);

    let mut c1 = Vec::with_capacity(C1_COEFFICIENTS);
    for (index, &chunk) in chunks[..CHUNKS].iter().enumerate() {
        let mut value = chunk;
        let len = CHUNK.min(C1_COEFFICIENTS - index * CHUNK);
        for _ in 0..len {
            c1.push(compress((value % Q64) as u32, DU));
            value /= Q64;
        }
    }

    let mut bytes = [0u8; CIPHERTEXT_SIZE];
    bytes[..C1_SIZE].copy_from_slice(&byte_encode(&c1, DU));
    bytes[C1_SIZE..].copy_from_slice(&encoded[R_SIZE..]);
    KemCiphertext::from_slice(&bytes).expect("fixed size")
}

#[cfg(test)]
mod tests {
    use rand::SeedableRng;
    use rand_chacha::ChaChaRng;

    use super::*;
    use crate::crypto::kem::KemKeyPair;

    #[test]
    fn parameters() {
        let q768 = BigUint::from(Q).pow(C1_COEFFICIENTS as u32);
        assert_eq!(q768.bits(), R_BITS + 1);
        assert_eq!(R_SIZE as u64, R_BITS.div_ceil(8));
        assert_eq!(R_TOP_MASK, (1u8 << (R_BITS - 8 * (R_SIZE as u64 - 1))) - 1);
        assert_eq!(C1_SIZE + C2_SIZE, CIPHERTEXT_SIZE);
        assert_eq!(ENCODED_SIZE, 1252);
        assert!(Q5 < 1 << 63);
        assert!(CHUNKS <= 1 << TREE_DEPTH && CHUNKS > 1 << (TREE_DEPTH - 1));
    }

    #[test]
    fn compression_matches_fips_203() {
        // Reference: real-valued rounding.
        let round = |num: f64| (num + 0.5).floor() as u32;
        for d in [DU, DV] {
            for x in 0..Q {
                let expected = round((1u32 << d) as f64 * x as f64 / Q as f64) % (1 << d);
                assert_eq!(compress(x, d), expected, "d={d} x={x}");
            }
            for y in 0..1u32 << d {
                assert_eq!(
                    decompress(y, d),
                    round(Q as f64 * y as f64 / (1u32 << d) as f64)
                );
            }
        }
    }

    #[test]
    fn preimages_are_exhaustive() {
        let mut all = vec![Vec::new(); 1 << DU];
        for x in 0..Q {
            all[compress(x, DU) as usize].push(x);
        }
        for (c, expected) in all.iter().enumerate() {
            let (candidates, len) = preimages_10(c as u32);
            let mut found = candidates[..len].to_vec();
            found.sort();
            let mut expected = expected.clone();
            expected.sort();
            assert_eq!(found, expected, "c={c}");
        }
        assert_eq!(all.iter().filter(|p| p.len() == 4).count(), 257);
        assert_eq!(all.iter().filter(|p| p.len() == 3).count(), 767);

        let mut counts = [0u32; 1 << DV];
        for x in 0..Q {
            counts[compress(x, DV) as usize] += 1;
        }
        assert_eq!(counts[0], C2_ZERO_PREIMAGES);
        assert!(counts[1..].iter().all(|&n| n == C2_ZERO_PREIMAGES - 1));
    }

    #[test]
    fn byte_codec_round_trips() {
        let mut rng = ChaChaRng::seed_from_u64(3);
        for d in [DU, DV] {
            let coefficients: Vec<u32> = (0..N).map(|_| rng.random_range(0..1u32 << d)).collect();
            assert_eq!(byte_decode(&byte_encode(&coefficients, d), d), coefficients);
        }
    }

    #[test]
    fn decode_inverts_encode_and_decapsulates() {
        let mut rng = ChaChaRng::seed_from_u64(4);
        let kem = KemKeyPair::derive(b"kemeleon");
        let mut failures = 0;
        let trials = 400;
        for _ in 0..trials {
            let (ciphertext, secret) = kem.encapsulation_key().encapsulate(rng.random());
            match encode(&ciphertext, &mut rng) {
                Some(encoded) => {
                    let decoded = decode(&encoded);
                    assert_eq!(decoded, ciphertext);
                    assert_eq!(kem.decapsulate(&decoded), secret);
                }
                None => failures += 1,
            }
        }
        // Draft: success probability 0.77 for ML-KEM-768.
        let rate = failures as f64 / trials as f64;
        assert!((0.15..0.32).contains(&rate), "failure rate {rate}");
    }

    /// The decoding tree against peeling one `q^5` digit at a time.
    #[test]
    fn split_digits_matches_sequential_division() {
        let sequential = |mut r: BigUint| -> Vec<u64> {
            (0..1 << TREE_DEPTH)
                .map(|_| {
                    let digit = (&r % Q5).to_u64_digits().first().copied().unwrap_or(0);
                    r /= Q5;
                    digit
                })
                .collect()
        };
        let mut rng = ChaChaRng::seed_from_u64(14);
        let top = (BigUint::from(1u8) << R_BITS) - 1u8;
        let mut values = vec![
            BigUint::default(),
            BigUint::from(Q5 - 1),
            BigUint::from(Q5),
            top,
        ];
        for _ in 0..20 {
            let mut bytes = [0u8; R_SIZE];
            rng.fill(&mut bytes[..]);
            bytes[0] &= R_TOP_MASK;
            values.push(BigUint::from_bytes_be(&bytes));
        }
        for r in values {
            let mut tree = [0u64; 1 << TREE_DEPTH];
            split_digits(&r, TREE_DEPTH, &mut tree);
            assert_eq!(tree.to_vec(), sequential(r));
        }
    }

    #[test]
    fn any_bytes_decode() {
        let mut rng = ChaChaRng::seed_from_u64(5);
        for _ in 0..20 {
            let mut bytes = [0u8; ENCODED_SIZE];
            rng.fill(&mut bytes[..]);
            decode(&bytes);
        }
        decode(&[0xff; ENCODED_SIZE]);
        decode(&[0; ENCODED_SIZE]);
    }

    fn chi_square(counts: &[u64]) -> f64 {
        let total: u64 = counts.iter().sum();
        let expected = total as f64 / counts.len() as f64;
        counts
            .iter()
            .map(|&n| (n as f64 - expected).powi(2) / expected)
            .sum()
    }

    /// The reason for this module: raw ciphertext coefficients are visibly skewed, encoded
    /// bytes are not. Thresholds sit about 12 standard deviations above the mean of a uniform
    /// sample (1023 and 255 degrees of freedom).
    #[test]
    fn encoding_removes_the_compression_bias() {
        let mut rng = ChaChaRng::seed_from_u64(6);
        let kem = KemKeyPair::derive(b"kemeleon");
        let mut raw = vec![0u64; 1 << DU];
        let mut encoded_10 = vec![0u64; 1 << DU];
        let mut encoded_bytes = vec![0u64; 256];
        let mut samples = 0;
        while samples < 200 {
            let (ciphertext, _) = kem.encapsulation_key().encapsulate(rng.random());
            let Some(encoded) = encode(&ciphertext, &mut rng) else {
                continue;
            };
            samples += 1;
            for c in byte_decode(&ciphertext.as_bytes()[..C1_SIZE], DU) {
                raw[c as usize] += 1;
            }
            // The same number of 10-bit values, read from the encoded integer.
            for c in byte_decode(&encoded[1..C1_SIZE + 1], DU) {
                encoded_10[c as usize] += 1;
            }
            for &b in encoded.iter() {
                encoded_bytes[b as usize] += 1;
            }
        }
        let raw = chi_square(&raw);
        let encoded_10 = chi_square(&encoded_10);
        let encoded_bytes = chi_square(&encoded_bytes);
        assert!(raw > 2_000.0, "raw coefficients look uniform: {raw}");
        assert!(
            encoded_10 < 1_600.0,
            "encoded 10-bit values skewed: {encoded_10}"
        );
        assert!(
            encoded_bytes < 530.0,
            "encoded bytes skewed: {encoded_bytes}"
        );
    }
}
