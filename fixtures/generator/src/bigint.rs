//! Just enough big integer arithmetic to prepare RSA witnesses.
//!
//! The circuits take a modulus as 120 bit limbs alongside a Barrett
//! reduction parameter, which is `floor(2^(2 * MOD_BITS + 6) / modulus)`.
//! Computing that needs a division no shell tool exposes, so it is done here
//! with schoolbook long division over 32 bit limbs. The result is a hint: a
//! wrong one cannot make a bad signature verify, because the backend
//! constrains every multiplication against it.

/// Little endian 32 bit limbs.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BigUint {
    limbs: Vec<u32>,
}

impl BigUint {
    pub fn zero() -> Self {
        Self { limbs: vec![0] }
    }

    pub fn from_be_bytes(bytes: &[u8]) -> Self {
        let mut limbs = Vec::new();

        let mut position = bytes.len();

        while position > 0 {
            let start = position.saturating_sub(4);

            let mut chunk = [0u8; 4];

            chunk[4 - (position - start)..].copy_from_slice(&bytes[start..position]);

            limbs.push(u32::from_be_bytes(chunk));

            position = start;
        }

        if limbs.is_empty() {
            limbs.push(0);
        }

        let mut value = Self { limbs };

        value.trim();

        value
    }

    /// The value 2 raised to `exponent`.
    pub fn power_of_two(exponent: usize) -> Self {
        let limb_count = exponent / 32 + 1;

        let mut limbs = vec![0u32; limb_count];

        limbs[exponent / 32] = 1 << (exponent % 32);

        Self { limbs }
    }

    fn trim(&mut self) {
        while self.limbs.len() > 1 && *self.limbs.last().unwrap() == 0 {
            self.limbs.pop();
        }
    }

    pub fn bit_length(&self) -> usize {
        let top = self.limbs.len() - 1;

        if self.limbs[top] == 0 && self.limbs.len() == 1 {
            return 0;
        }

        top * 32 + (32 - self.limbs[top].leading_zeros() as usize)
    }

    fn bit(&self, index: usize) -> bool {
        let limb = index / 32;

        limb < self.limbs.len() && (self.limbs[limb] >> (index % 32)) & 1 == 1
    }

    fn set_bit(&mut self, index: usize) {
        let limb = index / 32;

        if limb >= self.limbs.len() {
            self.limbs.resize(limb + 1, 0);
        }

        self.limbs[limb] |= 1 << (index % 32);
    }

    fn shift_left_one(&mut self) {
        let mut carry = 0u32;

        for limb in self.limbs.iter_mut() {
            let next = *limb >> 31;

            *limb = (*limb << 1) | carry;

            carry = next;
        }

        if carry != 0 {
            self.limbs.push(carry);
        }
    }

    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        use std::cmp::Ordering;

        let mut index = self.limbs.len().max(other.limbs.len());

        while index > 0 {
            index -= 1;

            let left = self.limbs.get(index).copied().unwrap_or(0);

            let right = other.limbs.get(index).copied().unwrap_or(0);

            if left != right {
                return if left > right {
                    Ordering::Greater
                } else {
                    Ordering::Less
                };
            }
        }

        Ordering::Equal
    }

    fn subtract_assign(&mut self, other: &Self) {
        let mut borrow = 0i64;

        for index in 0..self.limbs.len() {
            let right = other.limbs.get(index).copied().unwrap_or(0) as i64;

            let mut difference = self.limbs[index] as i64 - right - borrow;

            if difference < 0 {
                difference += 1i64 << 32;

                borrow = 1;
            } else {
                borrow = 0;
            }

            self.limbs[index] = difference as u32;
        }

        assert_eq!(borrow, 0, "bigint: subtraction underflowed");

        self.trim();
    }

    /// Long division, one bit of the quotient at a time.
    pub fn divide(&self, divisor: &Self) -> Self {
        assert!(divisor.bit_length() > 0, "bigint: division by zero");

        let mut quotient = Self::zero();

        let mut remainder = Self::zero();

        let mut index = self.bit_length();

        while index > 0 {
            index -= 1;

            remainder.shift_left_one();

            if self.bit(index) {
                remainder.set_bit(0);
            }

            if remainder.cmp(divisor) != std::cmp::Ordering::Less {
                remainder.subtract_assign(divisor);

                quotient.set_bit(index);
            }
        }

        quotient.trim();

        quotient
    }

    /// Splits into `count` limbs of 120 bits, least significant first, which
    /// is how the circuits take a big number.
    pub fn to_limbs_120(&self, count: usize) -> Vec<u128> {
        assert!(
            self.bit_length() <= count * 120,
            "bigint: {} bits do not fit {count} limbs of 120",
            self.bit_length()
        );

        let mut out = vec![0u128; count];

        for index in 0..count * 120 {
            if self.bit(index) {
                out[index / 120] |= 1u128 << (index % 120);
            }
        }

        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_big_endian_bytes() {
        let value = BigUint::from_be_bytes(&[0x01, 0x00, 0x00, 0x00, 0x00]);

        assert_eq!(value.bit_length(), 33);

        assert_eq!(value, BigUint::power_of_two(32));
    }

    #[test]
    fn divides_exactly() {
        let sixteen = BigUint::power_of_two(4);

        let four = BigUint::power_of_two(2);

        assert_eq!(sixteen.divide(&four), four);
    }

    #[test]
    fn divides_with_a_remainder() {
        // floor(2^8 / 7) = 36
        let quotient = BigUint::power_of_two(8).divide(&BigUint::from_be_bytes(&[7]));

        assert_eq!(quotient.to_limbs_120(1), vec![36]);
    }

    #[test]
    fn splits_into_limbs_of_120_bits() {
        let value = BigUint::power_of_two(120);

        assert_eq!(value.to_limbs_120(2), vec![0, 1]);

        let small = BigUint::from_be_bytes(&[0xff]);

        assert_eq!(small.to_limbs_120(2), vec![255, 0]);
    }

    // The value the circuits need for a 2048 bit modulus, checked against a
    // case whose answer is known exactly: dividing by a power of two is a
    // shift, so floor(2^4102 / 2^2047) is 2^2055.
    #[test]
    fn computes_a_barrett_parameter_shape() {
        let numerator = BigUint::power_of_two(4102);

        let modulus = BigUint::power_of_two(2047);

        let redc = numerator.divide(&modulus);

        assert_eq!(redc.bit_length(), 2056);

        assert_eq!(redc, BigUint::power_of_two(2055));
    }
}
