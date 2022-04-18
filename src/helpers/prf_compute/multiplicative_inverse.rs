use std::cmp;

use num_bigint::{BigInt, BigUint, ToBigInt};
use num_integer::Integer;
use num_traits::{identities::Zero, One, Signed};

fn extended_binary_gcd(m: &BigUint, n: &BigUint) -> (BigInt, BigInt, BigUint) {
    #[inline]
    fn count_twos_multiple(x: &BigUint) -> u64 {
        x.trailing_zeros().unwrap_or(0)
    }

    // Assume non zero
    assert!(!m.is_zero());
    assert!(!n.is_zero());

    let mut x_ebgcd = m.clone();
    let mut y_ebgcd = n.clone();
    let mut g_ebgcd = BigUint::one();

    // find common factors of 2
    let shift = cmp::min(count_twos_multiple(&x_ebgcd), count_twos_multiple(&y_ebgcd));

    x_ebgcd >>= shift;
    y_ebgcd >>= shift;
    g_ebgcd <<= shift;

    let mut u_ebgcd = x_ebgcd.clone();
    let mut v_ebgcd = y_ebgcd.clone();

    let mut a_ebgcd = BigInt::one();
    let mut b_ebgcd = BigInt::zero();
    let mut c_ebgcd = BigInt::zero();
    let mut d_ebgcd = BigInt::one();

    loop {
        while u_ebgcd.is_even() {
            u_ebgcd >>= 1;

            if a_ebgcd.is_even() && b_ebgcd.is_even() {
                a_ebgcd >>= 1;
                b_ebgcd >>= 1;
            } else {
                a_ebgcd = (a_ebgcd + y_ebgcd.to_bigint().unwrap()) >> 1;
                b_ebgcd = (b_ebgcd - x_ebgcd.to_bigint().unwrap()) >> 1;
            }
        }

        while v_ebgcd.is_even() {
            v_ebgcd >>= 1;

            if c_ebgcd.is_even() && d_ebgcd.is_even() {
                c_ebgcd >>= 1;
                d_ebgcd >>= 1;
            } else {
                c_ebgcd = (c_ebgcd + y_ebgcd.to_bigint().unwrap()) >> 1;
                d_ebgcd = (d_ebgcd - x_ebgcd.to_bigint().unwrap()) >> 1;
            }
        }

        if u_ebgcd >= v_ebgcd {
            u_ebgcd -= &v_ebgcd;
            a_ebgcd -= &c_ebgcd;
            b_ebgcd -= &d_ebgcd;
        } else {
            v_ebgcd -= &u_ebgcd;
            c_ebgcd -= &a_ebgcd;
            d_ebgcd -= &b_ebgcd;
        }

        if u_ebgcd.is_zero() {
            return (c_ebgcd.clone(), d_ebgcd.clone(), v_ebgcd << shift);
        }
    }
}

/// Implementation of Extended Euclidean Algorithm to compute multiplicative inverse of a number
/// i.e given m and n it computes t such that (m * t) % n = 1
///
/// # Panics
///
/// This may return None when converting from f32 or f64,
/// and will always succeed when converting from any integer or unsigned primitive, or ``BigUint``.
#[must_use]
pub fn mod_inverse(m: &BigUint, n: &BigUint) -> Option<BigInt> {
    let (mut a, _, g) = extended_binary_gcd(m, n);

    if !g.is_one() {
        return None;
    }

    let to_add = n.to_bigint().unwrap();

    if a.is_negative() {
        while a.is_negative() {
            a += &to_add;
        }
        assert!(a.is_positive());
        assert!(a < to_add);
        Some(a)
    } else {
        Some(a % to_add)
    }
}

#[cfg(test)]
mod tests {
    use num_bigint::{RandBigInt, ToBigInt, ToBigUint};
    use num_integer::Integer;
    use num_traits::One;
    use std::mem;

    use crate::helpers::prf_compute::multiplicative_inverse::{extended_binary_gcd, mod_inverse};

    #[test]
    fn check_mod_inv() {
        // These numbers are prime
        let num = 638_204_786_i32.to_biguint().unwrap();
        let modulo = 2_147_483_647_i32.to_biguint().unwrap();

        let inv = mod_inverse(&num, &modulo);
        assert_eq!(inv.clone().unwrap(), 1_237_888_327_i32.to_bigint().unwrap());

        let result = (num.to_bigint().unwrap() * inv.unwrap()) % modulo.to_bigint().unwrap();
        assert!(result.is_one());
    }

    #[test]
    fn check_extended_gcd() {
        let num = 638_204_786_i32.to_biguint().unwrap();
        let modulo = 2_147_483_647_i32.to_biguint().unwrap();

        let (a, b, g) = extended_binary_gcd(&num, &modulo);

        assert_eq!(g, num.gcd(&modulo));
        assert_eq!(
            a * num.to_bigint().unwrap() + b * modulo.to_bigint().unwrap(),
            g.to_bigint().unwrap()
        );
    }

    #[test]
    fn check_many_mod_inv_extended_gcd() {
        let mut rng = rand::thread_rng();

        for _ in 0..1000 {
            let mut num = rng.gen_biguint(2048);
            let mut modulo = rng.gen_biguint(2048);

            if modulo > num {
                mem::swap(&mut num, &mut modulo);
            }

            let (a, b, g) = extended_binary_gcd(&num, &modulo);
            assert_eq!(g, num.gcd(&modulo));
            assert_eq!(
                a * num.to_bigint().unwrap() + b * modulo.to_bigint().unwrap(),
                g.to_bigint().unwrap()
            );

            let inv = mod_inverse(&num, &modulo);

            if inv.is_some() {
                let v =
                    (num.to_bigint().unwrap() * inv.clone().unwrap()) % modulo.to_bigint().unwrap();
                assert!(v.is_one());
            }
        }
    }
}
