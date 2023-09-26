use std::{
    fmt::Debug,
    ops::{Mul, Neg},
};

use super::SharedValue;
use crate::ff::{GaloisField, LocalArithmeticOps, LocalAssignOps};

/// Secret sharing scheme i.e. Replicated secret sharing
pub trait SecretSharing<V: SharedValue>: Clone + Debug + Sized + Send + Sync {
    const ZERO: Self;
}

/// Secret share of a secret that has additive and multiplicative properties.
pub trait Linear<V: SharedValue>:
    SecretSharing<V>
    + LocalArithmeticOps
    + LocalAssignOps
    + for<'r> LocalArithmeticOps<&'r Self>
    + for<'r> LocalAssignOps<&'r Self>
    + Mul<V, Output = Self>
    + for<'r> Mul<&'r V, Output = Self>
    + Neg<Output = Self>
{
}

/// Secret share of a secret in bits. It has additive and multiplicative properties.
pub trait Bitwise<V: GaloisField>: SecretSharing<V> + Linear<V> {}
