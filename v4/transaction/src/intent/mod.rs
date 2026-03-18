#[cfg(feature = "intents")]
use crate::Argument;
#[cfg(feature = "intents")]
use crate::TransactionBuilder;

mod coin_with_balance;
#[cfg(feature = "intents")]
pub use coin_with_balance::CoinWithBalance;

#[cfg(feature = "intents")]
const MAX_GAS_OBJECTS: usize = 250; // 256
#[allow(unused)]
#[cfg(feature = "intents")]
const MAX_COMMANDS: usize = 1000; // 1024
#[allow(unused)]
#[cfg(feature = "intents")]
const MAX_INPUT_OBJECTS: usize = 2000; // 2048
#[cfg(feature = "intents")]
const MAX_ARGUMENTS: usize = 500; // 512

pub(crate) type BoxError = Box<dyn std::error::Error + Send + Sync + 'static>;

/// A transaction intent: a high-level description of a desired input or set of
/// commands that will be resolved into concrete builder calls, either offline
/// (via [`TransactionBuilder::try_build`]) or online (via
/// [`TransactionBuilder::build`] with an RPC client).
#[cfg(feature = "intents")]
pub(crate) trait Intent {
    fn register(self, builder: &mut TransactionBuilder) -> Argument;
}

#[cfg(feature = "intents")]
#[async_trait::async_trait]
pub(crate) trait IntentResolver: std::any::Any + std::fmt::Debug + Send + Sync {
    async fn resolve(
        &self,
        builder: &mut TransactionBuilder,
        client: &mut sui_rpc::Client,
    ) -> Result<(), BoxError>;
}

// Stub for builds where the "intents" feature is disabled.
#[cfg(not(feature = "intents"))]
pub(crate) trait IntentResolver: std::any::Any + std::fmt::Debug + Send + Sync {}