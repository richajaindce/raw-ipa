use std::marker::PhantomData;

use futures::TryStreamExt;

use crate::{
    error::Error,
    ff::{
        boolean::Boolean,
        boolean_array::{BA20, BA3, BA4, BA5, BA6, BA7, BA8},
        PrimeField, Serializable,
    },
    helpers::{
        query::{IpaQueryConfig, QuerySize},
        BodyStream, RecordsStream,
    },
    protocol::{
        basics::ShareKnownValue,
        context::{UpgradableContext, UpgradedContext},
        ipa_prf::oprf_ipa,
    },
    report::OprfReport,
    secret_sharing::replicated::{
        malicious::ExtendableField, semi_honest::AdditiveShare as Replicated,
    },
};

pub struct OprfIpaQuery<C, F> {
    config: IpaQueryConfig,
    phantom_data: PhantomData<(C, F)>,
}

impl<C, F> OprfIpaQuery<C, F> {
    pub fn new(config: IpaQueryConfig) -> Self {
        Self {
            config,
            phantom_data: PhantomData,
        }
    }
}

#[allow(clippy::too_many_lines)]
impl<C, F> OprfIpaQuery<C, F>
where
    C: UpgradableContext,
    C::UpgradedContext<F>: UpgradedContext<F, Share = Replicated<F>>,
    C::UpgradedContext<Boolean>: UpgradedContext<Boolean, Share = Replicated<Boolean>>,
    F: PrimeField + ExtendableField,
    Replicated<F>: Serializable + ShareKnownValue<C, F>,
    Replicated<Boolean>: Serializable + ShareKnownValue<C, Boolean>,
{
    #[tracing::instrument("oprf_ipa_query", skip_all, fields(sz=%query_size))]
    pub async fn execute<'a>(
        self,
        ctx: C,
        query_size: QuerySize,
        input_stream: BodyStream,
    ) -> Result<Vec<Replicated<F>>, Error> {
        let Self {
            config,
            phantom_data: _,
        } = self;
        tracing::info!("New query: {config:?}");
        let sz = usize::from(query_size);

        let input = if config.plaintext_match_keys {
            let mut v = RecordsStream::<OprfReport<BA8, BA3, BA20>, _>::new(input_stream)
                .try_concat()
                .await?;
            v.truncate(sz);
            v
        } else {
            panic!("Encrypted match key handling is not handled for OPRF flow as yet");
        };

        // TODO: Compute OPRFs and shuffle and add dummies and stuff (Daniel's code will be called here)
        let sharded_inputs = input
            .into_iter()
            .map(|single_row| OprfReport {
                match_key: single_row.match_key,
                is_trigger: single_row.is_trigger,
                breakdown_key: single_row.breakdown_key,
                trigger_value: single_row.trigger_value,
                timestamp: single_row.timestamp,
            })
            .collect::<Vec<_>>();
        // Until then, we convert the output to something next function is happy about.
        match config.per_user_credit_cap {
            8 => oprf_ipa::<C, BA8, BA3, BA20, BA3, F>(ctx, sharded_inputs, config).await,
            16 => oprf_ipa::<C, BA8, BA3, BA20, BA4, F>(ctx, sharded_inputs, config).await,
            32 => oprf_ipa::<C, BA8, BA3, BA20, BA5, F>(ctx, sharded_inputs, config).await,
            64 => oprf_ipa::<C, BA8, BA3, BA20, BA6, F>(ctx, sharded_inputs, config).await,
            128 => oprf_ipa::<C, BA8, BA3, BA20, BA7, F>(ctx, sharded_inputs, config).await,
            _ => panic!(
                "Invalid value specified for per-user cap: {:?}. Must be one of 8, 16, 32, 64, or 128.",
                config.per_user_credit_cap
            ),
        }
    }
}
