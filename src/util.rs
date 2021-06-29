use ff::PrimeField;

pub fn bytes_to_field<F: PrimeField>(bytes: &[u8]) -> Option<F> {
    let mut s_repr = F::Repr::default();
    s_repr.as_mut().copy_from_slice(bytes);

    F::from_repr(s_repr)
}
