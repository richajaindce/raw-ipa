use super::ipa::assert_stream_send;
use crate::{
    error::Error,
    ff::{GaloisField, Gf2, Gf8Bit, PrimeField, Serializable, Field},
    helpers::{query::QuerySize, BodyStream, RecordsStream},
    hpke::{KeyPair, KeyRegistry},
    protocol::{
        basics::{Reshare, ShareKnownValue},
        context::{
            Context, UpgradableContext, UpgradeContext, UpgradeToMalicious, UpgradedContext,
            Validator,
        },
        ipa::{ArithmeticallySharedIPAInputs, IPAInputRow, Step},
        modulus_conversion::{convert_bits, BitConversionTriple},
        sort::generate_permutation::ShuffledPermutationWrapper,
        BasicProtocols, BreakdownKey, MatchKey, RecordId,
    },
    secret_sharing::{
        replicated::{
            malicious::{DowngradeMalicious, ExtendableField},
            semi_honest::AdditiveShare as Replicated,
        },
        BitDecomposed, Linear as LinearSecretSharing,
    },
    sync::Arc,
};
use futures::stream::iter as stream_iter;
use futures::TryStreamExt;
use std::marker::PhantomData;
pub struct AggregateQuery<F, C, S> {
    _key_registry: Arc<KeyRegistry<KeyPair>>,
    phantom_data: PhantomData<(F, C, S)>,
}
struct BinarySharedAggregateInputs<T: LinearSecretSharing<Gf2>> {
    pub breakdown_key: BitDecomposed<T>,
}

impl<T: LinearSecretSharing<Gf2>> BinarySharedAggregateInputs<T> {
    #[must_use]
    pub fn new(breakdown_key: BitDecomposed<T>) -> Self {
        Self { breakdown_key }
    }
}

impl<F, C, S> AggregateQuery<F, C, S> {
    pub fn new(key_registry: Arc<KeyRegistry<KeyPair>>) -> Self {
        Self {
            _key_registry: key_registry,
            phantom_data: PhantomData,
        }
    }
}

impl<F, C, S, SB> AggregateQuery<F, C, S>
where
    C: UpgradableContext<UpgradedContext<F> = C> + Send,
    C::UpgradedContext<F>: UpgradedContext<F, Share = S>,
    S: LinearSecretSharing<F>
        + BasicProtocols<C::UpgradedContext<F>, F>
        + Reshare<C::UpgradedContext<F>, RecordId>
        + Serializable
        + DowngradeMalicious<Target = Replicated<F>>
        + 'static,
    C::UpgradedContext<Gf2>: UpgradedContext<Gf2, Share = SB>,
    SB: LinearSecretSharing<Gf2>
        + BasicProtocols<C::UpgradedContext<Gf2>, Gf2>
        + DowngradeMalicious<Target = Replicated<Gf2>>
        + 'static,
    F: PrimeField,
    Replicated<F>: Serializable + ShareKnownValue<C, F>,
    IPAInputRow<F, MatchKey, BreakdownKey>: Serializable,
    ShuffledPermutationWrapper<S, C::UpgradedContext<F>>: DowngradeMalicious<Target = Vec<u32>>,
    for<'u> UpgradeContext<'u, C::UpgradedContext<F>, F, RecordId>: UpgradeToMalicious<'u, BitConversionTriple<Replicated<F>>, BitConversionTriple<S>>
        + UpgradeToMalicious<
            'u,
            ArithmeticallySharedIPAInputs<F, Replicated<F>>,
            ArithmeticallySharedIPAInputs<F, S>,
        >,
{
    #[tracing::instrument("aggregate_query", skip_all, fields(sz=%query_size))]
    pub async fn execute<'a>(
        self,
        ctx: C,
        query_size: QuerySize,
        input_stream: BodyStream,
    ) -> Result<(), Error> {
        let Self {
            _key_registry,
            phantom_data: _,
        } = self;
        let sz = usize::from(query_size);

        let input: Vec<Gf8Bit> = {
            let mut v = assert_stream_send(RecordsStream::<BreakdownKey, _>::new(input_stream))
                .try_concat()
                .await?;
            v.truncate(sz);
            v
        };

        Self::aggregate_protocol(ctx, input.as_slice()).await?;
        Ok(())
        // validator.validate(mod_converted)
    }

    pub async fn aggregate_protocol<'a>(
        sh_ctx: C,
        input_rows: &[BreakdownKey],
    ) -> Result<Vec<Replicated<F>>, Error>
    where
        C: UpgradableContext,
        C::UpgradedContext<F>: UpgradedContext<F, Share = S>,
        S: LinearSecretSharing<F>
            + BasicProtocols<C::UpgradedContext<F>, F>
            + Reshare<C::UpgradedContext<F>, RecordId>
            + Serializable
            + DowngradeMalicious<Target = Replicated<F>>
            + 'static,
        C::UpgradedContext<Gf2>: UpgradedContext<Gf2, Share = SB>,
        SB: LinearSecretSharing<Gf2>
            + BasicProtocols<C::UpgradedContext<Gf2>, Gf2>
            + DowngradeMalicious<Target = Replicated<Gf2>>
            + 'static,
        F: PrimeField + ExtendableField,
        ShuffledPermutationWrapper<S, C::UpgradedContext<F>>: DowngradeMalicious<Target = Vec<u32>>,
        for<'u> UpgradeContext<'u, C::UpgradedContext<F>, F, RecordId>: UpgradeToMalicious<'u, BitConversionTriple<Replicated<F>>, BitConversionTriple<S>>
            + UpgradeToMalicious<
                'u,
                ArithmeticallySharedIPAInputs<F, Replicated<F>>,
                ArithmeticallySharedIPAInputs<F, S>,
            >,
    {
        let binary_validator = sh_ctx.narrow(&Step::BinaryValidator).validator::<Gf2>();
        let binary_m_ctx = binary_validator.context();

        // let input_rows = input_rows
        // .iter()
        // .map(|row| {
        //     BitDecomposed::decompose(BK::BITS, |i| {
        //         Replicated::new(
        //             Gf2::truncate_from(row.breakdown_key.left()[i]),
        //             Gf2::truncate_from(row.breakdown_key.right()[i]),
        //         )
        //     })
        // })
        // .collect::<Vec<_>>();
        let upgraded_gf2_breakdown_key_bits = binary_m_ctx
            .narrow(&Step::UpgradeBreakdownKeyBits)
            .upgrade(input_rows)
            .await?;

        let binary_shared_values = upgraded_gf2_breakdown_key_bits.iter()
            .map(|(breakdown_key)| BinarySharedAggregateInputs::new(breakdown_key))
            .collect::<Vec<_>>();

        Self::run_protocol(binary_validator, binary_shared_values).await
    }

    async fn run_protocol<IC, IB, V>(
        validator: V,
        breakdown_keys: IB,
    ) -> Result<Vec<BitDecomposed<S>>, Error>
    where
        F: PrimeField,
        IB: IntoIterator<Item = BitDecomposed<Replicated<Gf2>>> + ExactSizeIterator + Send,
        IB::IntoIter: Send,
        IC: IntoIterator<Item = S> + ExactSizeIterator + Send,
        IC::IntoIter: Send,
        C: UpgradedContext<F, Share = S>,
        S: LinearSecretSharing<F> + BasicProtocols<C, F> + Serializable + 'static,
        V: Validator<C, F>,
    {
        let m_ctx = validator.context();

        convert_bits(m_ctx, stream_iter(breakdown_keys), 0..8)
            .try_collect::<Vec<_>>()
            .await
    }
}
