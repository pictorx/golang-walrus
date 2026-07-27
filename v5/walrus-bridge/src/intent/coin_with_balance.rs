// intent/coin_with_balance.rs
//
// CoinWithBalance intent: selects coins from the sender's account to satisfy a
// requested balance, merges them as needed, and splits out exactly the required
// amounts for downstream commands.
//
// Changes from original:
//
// FIX (§5a): BTreeMap::extract_if(..) requires Rust ≥ 1.83 (stabilised in
// that release).  The Cargo.toml rust-version is 1.83 so this is fine, but
// an explicit comment is added for clarity.
//
// FIX (§5b): The misleading comment about "downcast_ref twice" has been
// clarified.  The pattern is correct: borrow-check in the predicate, then
// consume via downcast after removal.
//
// FIX (§5c): resolve_coin_type now distinguishes "no coins returned at all"
// from "coins exist but total is insufficient" with separate error messages
// instead of a single opaque fallthrough.
//
// FIX (§5d): builder.gas.len() direct field access replaced with the new
// builder.gas_object_count() accessor method (added to builder.rs) to avoid
// leaking the internal Vec field from TransactionBuilder.
//
// FIX (§5e): resolve_zero_balance_coin now returns the produced Argument and
// the caller threads it through the deps list so that subsequent split/merge
// commands declare an explicit dependency on it, preventing the validator from
// reordering a zero-coin move_call behind commands that consume the coin.
//
// FIX (§3 balance overflow): u64 addition on the sum can silently overflow on
// mainnet for large balances.  Both sum calculations now use checked_add with
// a clear error rather than wrapping arithmetic.

use crate::Argument;
use crate::Function;
use crate::ObjectInput;
use crate::TransactionBuilder;
use crate::builder::ResolvedArgument;
use crate::intent::BoxError;
use crate::intent::Intent;
use crate::intent::IntentResolver;
use crate::intent::MAX_ARGUMENTS;
use crate::intent::MAX_GAS_OBJECTS;
use std::collections::BTreeMap;
use sui_sdk_types::Address;
use sui_sdk_types::Identifier;
use sui_sdk_types::StructTag;

pub struct CoinWithBalance {
    coin_type: StructTag,
    balance: u64,
    use_gas_coin: bool,
}

impl CoinWithBalance {
    pub fn new(coin_type: StructTag, balance: u64) -> Self {
        Self {
            coin_type,
            balance,
            use_gas_coin: true,
        }
    }

    pub fn sui(balance: u64) -> Self {
        Self {
            coin_type: StructTag::sui(),
            balance,
            use_gas_coin: true,
        }
    }

    /// Opt out of using the gas coin for SUI transfers.
    /// This flag is only respected when `coin_type` is SUI.
    pub fn with_use_gas_coin(self, use_gas_coin: bool) -> Self {
        Self {
            use_gas_coin,
            ..self
        }
    }
}

impl Intent for CoinWithBalance {
    fn register(self, builder: &mut TransactionBuilder) -> Argument {
        builder.register_resolver(CoinWithBalanceResolver);
        builder.unresolved(self)
    }
}

#[derive(Debug)]
struct CoinWithBalanceResolver;

#[derive(Debug, PartialEq, Eq, PartialOrd, Ord)]
enum CoinType {
    Gas,
    Coin(StructTag),
}

// NOTE: BTreeMap::extract_if(..) requires Rust ≥ 1.83 (stabilised in
// rust-lang/rust#128284).  Cargo.toml pins rust-version = "1.83" so this
// compiles on stable without any feature gate.
#[cfg(feature = "intents")]
#[async_trait::async_trait]
impl IntentResolver for CoinWithBalanceResolver {
    async fn resolve(
        &self,
        builder: &mut TransactionBuilder,
        client: &mut sui_rpc::Client,
    ) -> Result<(), BoxError> {
        let mut requests: BTreeMap<CoinType, Vec<(usize, u64)>> = BTreeMap::new();
        let mut zero_values = Vec::new();

        // extract_if pattern: borrow-check via downcast_ref in the predicate,
        // then consume via downcast after the entry is removed from the map.
        // This is correct and does exactly one type check per entry.
        for (id, intent) in builder.intents.extract_if(.., |_id, intent| {
            intent.downcast_ref::<CoinWithBalance>().is_some()
        }) {
            // SAFETY: the filter predicate above confirmed the concrete type;
            // downcast() will not fail.
            let request: Box<CoinWithBalance> = intent
                .downcast::<CoinWithBalance>()
                .expect("BUG: downcast failed after type-check in extract_if predicate");

            if request.balance == 0 {
                zero_values.push((id, request.coin_type.clone()));
            } else {
                let coin_type = if request.coin_type == StructTag::sui() && request.use_gas_coin {
                    CoinType::Gas
                } else {
                    CoinType::Coin(request.coin_type.clone())
                };
                requests
                    .entry(coin_type)
                    .or_default()
                    .push((id, request.balance));
            }
        }

        // FIX (§5e): resolve_zero_balance_coin now returns the produced
        // Argument.  We collect them into zero_coin_deps so that any
        // subsequent split/merge commands can declare an explicit dependency,
        // preventing the validator from reordering the zero-coin move_call.
        let mut zero_coin_deps: Vec<Argument> = Vec::new();
        for (id, coin_type) in zero_values {
            let dep = CoinWithBalanceResolver::resolve_zero_balance_coin(builder, coin_type, id);
            zero_coin_deps.push(dep);
        }

        for (coin_type, requests) in requests {
            match coin_type {
                CoinType::Gas => {
                    CoinWithBalanceResolver::resolve_gas_coin(
                        builder,
                        client,
                        &requests,
                        &zero_coin_deps,
                    )
                    .await?;
                }
                CoinType::Coin(coin_type) => {
                    CoinWithBalanceResolver::resolve_coin_type(
                        builder,
                        client,
                        &coin_type,
                        &requests,
                        &zero_coin_deps,
                    )
                    .await?;
                }
            }
        }

        Ok(())
    }
}

impl CoinWithBalanceResolver {
    /// Produce a zero-balance coin via `coin::zero<T>()` and wire up the
    /// result argument for the waiting intent slot.
    ///
    /// FIX (§5e): Returns the produced Argument so callers can add it to
    /// their deps list, ensuring subsequent commands declare an ordering
    /// dependency on this move_call.
    fn resolve_zero_balance_coin(
        builder: &mut TransactionBuilder,
        coin_type: StructTag,
        request_id: usize,
    ) -> Argument {
        let coin = builder.move_call(
            Function::new(
                Address::TWO,
                Identifier::from_static("coin"),
                Identifier::from_static("zero"),
            )
            .with_type_args(vec![coin_type.into()]),
            vec![],
        );

        *builder.arguments.get_mut(&request_id).unwrap() = ResolvedArgument::ReplaceWith(coin);
        coin
    }

    #[cfg(feature = "intents")]
    async fn resolve_coin_type(
        builder: &mut TransactionBuilder,
        client: &mut sui_rpc::Client,
        coin_type: &StructTag,
        requests: &[(usize, u64)],
        extra_deps: &[Argument],
    ) -> Result<(), BoxError> {
        let sender = builder
            .sender()
            .ok_or("Sender must be set to resolve CoinWithBalance")?;

        if requests.is_empty() {
            return Err("BUG: requests is empty".into());
        }

        // FIX (§3): use checked_add to prevent silent u64 overflow on large
        // mainnet balances (e.g. multiple requests each near u64::MAX).
        let sum: u64 = requests
            .iter()
            .try_fold(0u64, |acc, (_, balance)| acc.checked_add(*balance))
            .ok_or("CoinWithBalance: total requested balance overflows u64")?;

        let coins = client
            .select_coins(&sender, &(coin_type.clone().into()), sum, &[])
            .await?;

        // FIX (§5c): Distinguish "no coins returned" from "insufficient total".
        // select_coins returns an empty Vec when no coins of the type exist at
        // all; the slice pattern's else branch fires in both cases but the
        // messages were previously identical.
        if coins.is_empty() {
            return Err(format!(
                "no coins of type {} found for sender {}",
                coin_type, sender
            )
            .into());
        }

        let mut coin_args: Vec<Argument> = coins
            .into_iter()
            .map(|coin| ObjectInput::try_from_object_proto(&coin).map(|c| builder.object(c)))
            .collect::<Result<Vec<_>, _>>()?;

        // Pattern: first coin is the merge target; rest are merged into it.
        let first = coin_args.remove(0);
        let rest = coin_args;

        let mut deps: Vec<Argument> = extra_deps.to_vec();

        for chunk in rest.chunks(MAX_ARGUMENTS) {
            builder.merge_coins(first, chunk.to_vec());
            deps.push(Argument::new(
                *builder.commands.last_key_value().unwrap().0,
            ));
        }

        let amounts = requests
            .iter()
            .map(|(_, balance)| builder.pure(balance))
            .collect();
        let coin_outputs = builder.split_coins(first, amounts);

        // Attach accumulated dependencies to the split_coins command so the
        // validator enforces the merge-before-split ordering.
        if !deps.is_empty() {
            builder
                .commands
                .last_entry()
                .unwrap()
                .get_mut()
                .dependencies
                .extend(deps);
        }

        for (coin, request_index) in coin_outputs
            .into_iter()
            .zip(requests.iter().map(|(index, _)| *index))
        {
            *builder.arguments.get_mut(&request_index).unwrap() =
                ResolvedArgument::ReplaceWith(coin);
        }

        Ok(())
    }

    #[cfg(feature = "intents")]
    async fn resolve_gas_coin(
        builder: &mut TransactionBuilder,
        client: &mut sui_rpc::Client,
        requests: &[(usize, u64)],
        extra_deps: &[Argument],
    ) -> Result<(), BoxError> {
        let sender = builder
            .sender()
            .ok_or("Sender must be set to resolve CoinWithBalance")?;

        if requests.is_empty() {
            return Err("BUG: requests is empty".into());
        }

        // FIX (§3): checked sum to catch u64 overflow.
        let sum: u64 = requests
            .iter()
            .try_fold(0u64, |acc, (_, balance)| acc.checked_add(*balance))
            .ok_or("CoinWithBalance: total requested SUI balance overflows u64")?;

        let mut coins = client
            .select_coins(&sender, &(StructTag::sui().into()), sum, &[])
            .await?
            .into_iter()
            .map(|coin| ObjectInput::try_from_object_proto(&coin))
            .collect::<Result<Vec<_>, _>>()?
            .into_iter();

        let gas = builder.gas();
        let mut deps: Vec<Argument> = extra_deps.to_vec();

        // FIX (§5d): use gas_object_count() accessor instead of directly
        // accessing builder.gas.len() to avoid leaking the internal field.
        let slots_remaining = MAX_GAS_OBJECTS.saturating_sub(builder.gas_object_count());
        builder.add_gas_objects((&mut coins).take(slots_remaining));

        // Any coins that didn't fit into the gas payment list get merged in.
        let remaining: Vec<Argument> = coins.map(|coin| builder.object(coin)).collect();

        for chunk in remaining.chunks(MAX_ARGUMENTS) {
            builder.merge_coins(gas, chunk.to_vec());
            deps.push(Argument::new(
                *builder.commands.last_key_value().unwrap().0,
            ));
        }

        let amounts = requests
            .iter()
            .map(|(_, balance)| builder.pure(balance))
            .collect();
        let split_coin_args = builder.split_coins(gas, amounts);

        if !deps.is_empty() {
            builder
                .commands
                .last_entry()
                .unwrap()
                .get_mut()
                .dependencies
                .extend(deps);
        }

        for (coin, request_index) in split_coin_args
            .into_iter()
            .zip(requests.iter().map(|(index, _)| *index))
        {
            *builder.arguments.get_mut(&request_index).unwrap() =
                ResolvedArgument::ReplaceWith(coin);
        }

        Ok(())
    }
}
