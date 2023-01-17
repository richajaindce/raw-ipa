use crate::ff::{Fp32BitPrime};
use crate::protocol::context::Context;
use crate::protocol::modulus_conversion::{convert_all_bits, convert_all_bits_local};
use crate::protocol::sort::generate_permutation_opt::generate_permutation_opt;
use crate::secret_sharing::{XorReplicated};
use crate::test_fixture::{TestWorld, join3};
use rand::Rng;

/// Creates an arithmetic circuit with the given width and depth.
///
/// # Panics
/// panics when circuits did not produce the expected value.
pub async fn sort(batchsize: usize, num_multi_bits: u32) {
    let world = TestWorld::new().await;
    let [ctx0, ctx1, ctx2] = world.contexts::<Fp32BitPrime>();
    let num_bits = 64;
    let mut rng = rand::thread_rng();

    let mut match_keys: Vec<u64> = Vec::new();
    for _ in 0..batchsize {
        match_keys.push(rng.gen::<u64>());
    }

    let input_len = match_keys.len();
    let mut shares = [
        Vec::with_capacity(input_len),
        Vec::with_capacity(input_len),
        Vec::with_capacity(input_len),
    ];
    for match_key in match_keys.clone() {
        let share_0 = rng.gen::<u64>();
        let share_1 = rng.gen::<u64>();
        let share_2 = match_key ^ share_0 ^ share_1;

        shares[0].push(XorReplicated::new(share_0, share_1));
        shares[1].push(XorReplicated::new(share_1, share_2));
        shares[2].push(XorReplicated::new(share_2, share_0));
    }

    let converted_shares = join3(
        convert_all_bits(
            &ctx0,
            &convert_all_bits_local(ctx0.role(), &shares[0], num_bits),
        ),
        convert_all_bits(
            &ctx1,
            &convert_all_bits_local(ctx1.role(), &shares[1], num_bits),
        ),
        convert_all_bits(
            &ctx2,
            &convert_all_bits_local(ctx2.role(), &shares[2], num_bits),
        ),
    )
    .await;

    let result = join3(
        generate_permutation_opt(ctx0, &converted_shares[0], num_bits, num_multi_bits),
        generate_permutation_opt(ctx1, &converted_shares[1], num_bits, num_multi_bits),
        generate_permutation_opt(ctx2, &converted_shares[2], num_bits, num_multi_bits),
    )
    .await;

    assert_eq!(result[0].len(), input_len);
    assert_eq!(result[1].len(), input_len);
    assert_eq!(result[2].len(), input_len);
}
