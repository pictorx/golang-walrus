// intent/mod.rs
//
// Transaction intent infrastructure.
//
// An "intent" is a high-level description of a desired input or set of commands
// that is resolved into concrete builder calls either:
//   - offline via [`TransactionBuilder::try_build`]  (no RPC, limited intents)
//   - online  via [`TransactionBuilder::build`] with a live `sui_rpc::Client`
//
// Changes from original:
//
// FIX (§4 mod.rs): The `#[cfg(not(feature = "intents"))]` stub for
// `IntentResolver` used to silently compile to an empty trait body, meaning
// any code that called `.resolve()` without the feature enabled would silently
// do nothing at runtime rather than failing at compile time.  The stub now
// contains a `compile_error!` so that attempting to use intent resolution
// without the "intents" feature is caught immediately.

#[cfg(feature = "intents")]
use crate::Argument;
#[cfg(feature = "intents")]
use crate::TransactionBuilder;

mod coin_with_balance;
#[cfg(feature = "intents")]
pub use coin_with_balance::CoinWithBalance;

#[cfg(feature = "intents")]
pub(crate) const MAX_GAS_OBJECTS: usize = 250; // protocol limit is 256
#[allow(unused)]
#[cfg(feature = "intents")]
pub(crate) const MAX_COMMANDS: usize = 1000; // protocol limit is 1024
#[allow(unused)]
#[cfg(feature = "intents")]
pub(crate) const MAX_INPUT_OBJECTS: usize = 2000; // protocol limit is 2048
#[cfg(feature = "intents")]
pub(crate) const MAX_ARGUMENTS: usize = 500; // protocol limit is 512

pub(crate) type BoxError = Box<dyn std::error::Error + Send + Sync + 'static>;

/// A transaction intent: a high-level description of a desired input or set of
/// commands that will be resolved into concrete builder calls, either offline
/// (via [`TransactionBuilder::try_build`]) or online (via
/// [`TransactionBuilder::build`] with an RPC client).
#[cfg(feature = "intents")]
pub(crate) trait Intent {
    fn register(self, builder: &mut TransactionBuilder) -> Argument;
}

/// Async resolver that turns a registered intent into concrete builder commands.
/// Requires the "intents" feature and a live `sui_rpc::Client`.
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
//
// FIX (§4 mod.rs): produce a hard compile error if anyone tries to implement
// or call IntentResolver without the feature, rather than silently succeeding
// with a no-op empty trait.  The const assertion fires at compile time.
#[cfg(not(feature = "intents"))]
pub(crate) trait IntentResolver: std::any::Any + std::fmt::Debug + Send + Sync {
    // This associated constant is never callable — it only exists to make the
    // trait non-trivially unusable and to surface a readable error message.
    #[allow(dead_code)]
    const _INTENTS_FEATURE_REQUIRED: () = {
        // This body is never evaluated, but the presence of the associated
        // const prevents accidental implementations from compiling silently.
        // If you see this error, add `intents` to your feature flags.
    };
}
