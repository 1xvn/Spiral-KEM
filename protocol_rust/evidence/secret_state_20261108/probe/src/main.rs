// Public compile-only feature control; no secret material.
fn require<T: zeroize::ZeroizeOnDrop>() {}
fn main() {
    require::<sha2::Sha256>();
    require::<sha2::Sha512>();
}
