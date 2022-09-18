use crate::field::Field;
use crate::protocol::{QueryId, RecordId};
use crate::replicated_secret_sharing::ReplicatedSecretSharing;
use crate::test_fixture::{
    make_contexts, make_world, share, validate_and_reconstruct, TestStep, TestWorld,
};
use futures_util::future::join_all;
use rand::thread_rng;

/// Creates an arithmetic circuit with the given width and depth.
///
/// # Panics
/// panics when circuits did not produce the expected value.
pub async fn arithmetic<F: Field>(width: u32, depth: u8) {
    let world = make_world(QueryId);

    let mut multiplications = Vec::new();
    for record in 0..width {
        let circuit_result = circuit::<F>(&world, RecordId::from(record), depth);
        multiplications.push(circuit_result);
    }

    let results = join_all(multiplications).await;
    let mut sum = 0;
    for line in results {
        sum += validate_and_reconstruct((line[0], line[1], line[2])).as_u128();
    }

    assert_eq!(sum, u128::from(width));
}

async fn circuit<F: Field>(
    world: &TestWorld<TestStep>,
    record_id: RecordId,
    depth: u8,
) -> [ReplicatedSecretSharing<F>; 3] {
    let c = make_contexts(world);
    let mut a = share(F::ONE, &mut thread_rng());

    for bit in 0..depth {
        let b = share(F::ONE, &mut thread_rng());
        let c = &c;
        a = async move {
            let mut coll = Vec::new();
            for (i, ctx) in c.iter().enumerate() {
                let mul = ctx.multiply(record_id, TestStep::Mul1(bit)).await;
                coll.push(mul.execute(a[i], b[i]));
            }

            join_all(coll)
                .await
                .into_iter()
                .collect::<Result<Vec<_>, _>>()
                .unwrap()
                .try_into()
                .unwrap()
        }
        .await;
    }

    a
}