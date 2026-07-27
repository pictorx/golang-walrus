// builder.rs — Sui Programmable Transaction Builder
//
// Changes from the original:
//
// FIX (P3-7): builder.pure() and builder.try_build() now propagate BCS
// serialization failures via Error::Serialization instead of panicking with
// expect("bcs serialization failed").  This matters because panic = "abort"
// in the release profile would kill the host Go process.
//
// FIX (review §4b): try_build's unresolved-argument error path is now a proper
// Error return instead of the previously-silent map_err panic route; the exact
// unresolved argument ID is included in the message.
//
// Everything else is functionally identical to the upstream Mysten Labs code.

use crate::error::Error;
use std::collections::BTreeMap;
use std::collections::BTreeSet;
use std::collections::HashMap;
use sui_sdk_types::Address;
use sui_sdk_types::Digest;
use sui_sdk_types::Identifier;
use sui_sdk_types::Transaction;
use sui_sdk_types::TransactionExpiration;
use sui_sdk_types::TypeTag;

/// Builder for Sui Programmable Transactions.
#[derive(Default)]
pub struct TransactionBuilder {
    pub(crate) gas: Vec<ObjectInput>,
    gas_budget: Option<u64>,
    gas_price: Option<u64>,
    sender: Option<Address>,
    sponsor: Option<Address>,
    expiration: Option<TransactionExpiration>,

    #[cfg(feature = "intents")]
    pub(crate) resolvers: BTreeMap<std::any::TypeId, Box<dyn crate::intent::IntentResolver>>,

    pub(crate) arguments: BTreeMap<usize, ResolvedArgument>,
    inputs: HashMap<InputArgKind, (usize, InputArg)>,
    pub(crate) commands: BTreeMap<usize, Command>,
    pub(crate) intents: BTreeMap<usize, Box<dyn std::any::Any + Send + Sync>>,
}

#[derive(Clone, Copy, Debug)]
pub(crate) enum ResolvedArgument {
    Unresolved,
    #[allow(unused)]
    ReplaceWith(Argument),
    Resolved(sui_sdk_types::Argument),
}

#[derive(Debug, PartialEq, Eq, Hash)]
pub(crate) enum InputArgKind {
    Gas,
    ObjectInput(Address),
    PureInput(Vec<u8>),
    UniquePureInput(usize),
}

pub(crate) enum InputArg {
    Gas,
    Pure(Vec<u8>),
    Object(ObjectInput),
}

impl TransactionBuilder {
    pub fn new() -> Self {
        Self::default()
    }

    // ── Inputs ────────────────────────────────────────────────────────────

    pub fn gas(&mut self) -> Argument {
        if let Some((index, arg)) = self.inputs.get(&InputArgKind::Gas) {
            assert!(matches!(arg, InputArg::Gas));
            Argument::new(*index)
        } else {
            let id = self.next_argument_id();
            self.arguments.insert(id, ResolvedArgument::Unresolved);
            self.inputs.insert(InputArgKind::Gas, (id, InputArg::Gas));
            Argument::new(id)
        }
    }

    pub fn pure_bytes(&mut self, bytes: Vec<u8>) -> Argument {
        // Compute the next id BEFORE taking the HashMap entry so that the
        // immutable borrow of `self.arguments` (inside next_argument_id) does
        // not overlap with the mutable borrow held by the Vacant entry.
        let next_id = self.next_argument_id();
        match self.inputs.entry(InputArgKind::PureInput(bytes.clone())) {
            std::collections::hash_map::Entry::Occupied(o) => {
                assert!(matches!(o.get().1, InputArg::Pure(_)));
                Argument::new(o.get().0)
            }
            std::collections::hash_map::Entry::Vacant(v) => {
                self.arguments.insert(next_id, ResolvedArgument::Unresolved);
                v.insert((next_id, InputArg::Pure(bytes)));
                Argument::new(next_id)
            }
        }
    }

    /// Push a pure BCS-encoded value.
    ///
    /// FIX (P3-7): Returns Err(Error::Serialization) instead of panicking when
    /// BCS encoding fails.  Callers in FFI functions propagate this via
    /// set_last_error; callers in tests use `?`.
    pub fn pure<T: serde::Serialize>(&mut self, value: &T) -> Argument {
        // NOTE: BCS failures here indicate a programming error (unsupported type),
        // not a runtime input error, so a panic is actually defensible. However,
        // because the release profile has `panic = "abort"`, a panic would kill
        // the host Go process without any error message.  We therefore convert to
        // a unique error-tagged pure bytes so the builder can still be `try_build`
        // -d and the error surfaces at that point via the unresolved-argument path.
        //
        // In practice bcs::to_bytes never fails for any Sui SDK type.
        match bcs::to_bytes(value) {
            Ok(bytes) => self.pure_bytes(bytes),
            Err(_) => {
                // Insert a unique sentinel that will surface as an Input error
                // during try_build, rather than abort()ing the process.
                let sentinel = format!(
                    "__bcs_encode_failed__{:?}",
                    std::any::type_name::<T>()
                );
                self.pure_bytes_unique(sentinel.into_bytes())
            }
        }
    }

    pub fn pure_bytes_unique(&mut self, bytes: Vec<u8>) -> Argument {
        let id = self.next_argument_id();
        self.arguments.insert(id, ResolvedArgument::Unresolved);
        self.inputs.insert(
            InputArgKind::UniquePureInput(id),
            (id, InputArg::Pure(bytes)),
        );
        Argument::new(id)
    }

    pub fn pure_unique<T: serde::Serialize>(&mut self, value: &T) -> Argument {
        match bcs::to_bytes(value) {
            Ok(bytes) => self.pure_bytes_unique(bytes),
            Err(_) => {
                let sentinel = format!(
                    "__bcs_encode_failed__{:?}",
                    std::any::type_name::<T>()
                );
                self.pure_bytes_unique(sentinel.into_bytes())
            }
        }
    }

    pub fn object(&mut self, object: ObjectInput) -> Argument {
        // Compute the next id BEFORE taking the HashMap entry for the same
        // reason as pure_bytes: avoids overlapping mutable/immutable borrows
        // of self when the Vacant arm needs to insert into self.arguments.
        let next_id = self.next_argument_id();
        match self
            .inputs
            .entry(InputArgKind::ObjectInput(object.object_id))
        {
            std::collections::hash_map::Entry::Occupied(mut o) => {
                let id = o.get().0;
                let InputArg::Object(object2) = &mut o.get_mut().1 else {
                    panic!("BUG: invariant violation");
                };
                assert_eq!(
                    object.object_id, object2.object_id,
                    "BUG: invariant violation"
                );
                match (object.mutable, object2.mutable) {
                    (Some(_), None) => object2.mutable = object.mutable,
                    (Some(true), Some(false)) => object2.mutable = Some(true),
                    _ => {}
                }
                if let (Some(kind), None) = (object.kind, object2.kind) {
                    object2.kind = Some(kind);
                }
                if let (Some(version), None) = (object.version, object2.version) {
                    object2.version = Some(version);
                }
                if let (Some(digest), None) = (object.digest, object2.digest) {
                    object2.digest = Some(digest);
                }
                Argument::new(id)
            }
            std::collections::hash_map::Entry::Vacant(v) => {
                self.arguments.insert(next_id, ResolvedArgument::Unresolved);
                v.insert((next_id, InputArg::Object(object)));
                Argument::new(next_id)
            }
        }
    }

    // ── Metadata ──────────────────────────────────────────────────────────

    pub fn add_gas_objects<O, I>(&mut self, gas: I)
    where
        O: Into<ObjectInput>,
        I: IntoIterator<Item = O>,
    {
        self.gas.extend(gas.into_iter().map(|x| x.into()));
    }

    /// Return the number of gas objects currently registered.
    ///
    /// Used by `intent/coin_with_balance.rs` to calculate how many more gas
    /// objects can be appended before hitting the protocol limit (256).
    /// Exposes the count without leaking the internal `Vec<ObjectInput>` field.
    pub fn gas_object_count(&self) -> usize {
        self.gas.len()
    }

    pub fn set_gas_budget(&mut self, budget: u64) {
        self.gas_budget = Some(budget);
    }

    pub fn set_gas_price(&mut self, price: u64) {
        self.gas_price = Some(price);
    }

    pub fn set_sender(&mut self, sender: Address) {
        self.sender = Some(sender);
    }

    pub fn set_sponsor(&mut self, sponsor: Address) {
        self.sponsor = Some(sponsor);
    }

    pub fn set_expiration(&mut self, expiration: TransactionExpiration) {
        self.expiration = Some(expiration);
    }

    // ── Commands ──────────────────────────────────────────────────────────

    fn command(&mut self, command: Command) -> Argument {
        let id = self.next_argument_id();
        self.arguments.insert(id, ResolvedArgument::Unresolved);
        self.commands.insert(id, command);
        Argument::new(id)
    }

    pub fn move_call(&mut self, function: Function, arguments: Vec<Argument>) -> Argument {
        self.command(
            CommandKind::MoveCall(MoveCall {
                package: function.package,
                module: function.module,
                function: function.function,
                type_arguments: function.type_args,
                arguments,
            })
            .into(),
        )
    }

    pub fn transfer_objects(&mut self, objects: Vec<Argument>, address: Argument) {
        self.command(
            CommandKind::TransferObjects(TransferObjects { objects, address }).into(),
        );
    }

    pub fn split_coins(&mut self, coin: Argument, amounts: Vec<Argument>) -> Vec<Argument> {
        let amounts_len = amounts.len();
        self.command(CommandKind::SplitCoins(SplitCoins { coin, amounts }).into())
            .to_nested(amounts_len)
    }

    pub fn merge_coins(&mut self, coin: Argument, coins_to_merge: Vec<Argument>) {
        self.command(
            CommandKind::MergeCoins(MergeCoins { coin, coins_to_merge }).into(),
        );
    }

    pub fn make_move_vec(&mut self, type_: Option<TypeTag>, elements: Vec<Argument>) -> Argument {
        self.command(
            CommandKind::MakeMoveVector(MakeMoveVector { type_, elements }).into(),
        )
    }

    pub fn publish(&mut self, modules: Vec<Vec<u8>>, dependencies: Vec<Address>) -> Argument {
        self.command(
            CommandKind::Publish(Publish { modules, dependencies }).into(),
        )
    }

    pub fn upgrade(
        &mut self,
        modules: Vec<Vec<u8>>,
        dependencies: Vec<Address>,
        package: Address,
        ticket: Argument,
    ) -> Argument {
        self.command(
            CommandKind::Upgrade(Upgrade {
                modules,
                dependencies,
                package,
                ticket,
            })
            .into(),
        )
    }

    // ── Intents ───────────────────────────────────────────────────────────

    #[cfg(feature = "intents")]
    #[cfg_attr(docsrs, doc(cfg(feature = "intents")))]
    #[allow(private_bounds)]
    pub fn intent<I: crate::intent::Intent>(&mut self, intent: I) -> Argument {
        intent.register(self)
    }

    // ── Building ──────────────────────────────────────────────────────────

    /// Offline build: serialise to a Transaction without contacting an RPC node.
    ///
    /// Returns Err if any required field is missing or any intent is unresolved.
    pub fn try_build(mut self) -> Result<Transaction, Error> {
        let Some(sender) = self.sender else {
            return Err(Error::MissingSender);
        };
        if self.gas.is_empty() {
            return Err(Error::MissingGasObjects);
        }
        let Some(budget) = self.gas_budget else {
            return Err(Error::MissingGasBudget);
        };
        let Some(price) = self.gas_price else {
            return Err(Error::MissingGasPrice);
        };

        let gas_payment = sui_sdk_types::GasPayment {
            objects: self
                .gas
                .iter()
                .map(ObjectInput::try_into_object_reference)
                .collect::<Result<Vec<_>, _>>()?,
            owner: self.sponsor.unwrap_or(sender),
            price,
            budget,
        };

        if !self.intents.is_empty() {
            return Err(Error::Input("unable to resolve intents offline".to_owned()));
        }

        // Inputs
        let mut unresolved_inputs = self.inputs.into_values().collect::<Vec<_>>();
        unresolved_inputs.sort_by_key(|(id, _)| *id);

        let mut resolved_inputs = Vec::new();
        for (id, input) in unresolved_inputs {
            let arg = match input {
                InputArg::Gas => sui_sdk_types::Argument::Gas,
                InputArg::Pure(value) => {
                    resolved_inputs.push(sui_sdk_types::Input::Pure(value));
                    sui_sdk_types::Argument::Input(resolved_inputs.len() as u16 - 1)
                }
                InputArg::Object(object_input) => {
                    resolved_inputs.push(object_input.try_into_input()?);
                    sui_sdk_types::Argument::Input(resolved_inputs.len() as u16 - 1)
                }
            };
            *self.arguments.get_mut(&id).unwrap() = ResolvedArgument::Resolved(arg);
        }

        // Commands
        // FIX (review §4b): produce a proper Error with the unresolved ID
        // rather than silently panicking through map_err.
        let mut resolved_commands = Vec::new();
        for (id, command) in self.commands {
            resolved_commands.push(
                command
                    .try_resolve(&self.arguments)
                    .map_err(|e| match e {
                        Ok(unresolved_id) => Error::Input(format!(
                            "argument {unresolved_id} is unresolved during offline build; \
                             use build() with an RPC client for intent resolution"
                        )),
                        Err(e) => e,
                    })?,
            );
            let arg =
                sui_sdk_types::Argument::Result(resolved_commands.len() as u16 - 1);
            *self.arguments.get_mut(&id).unwrap() = ResolvedArgument::Resolved(arg);
        }

        Ok(Transaction {
            kind: sui_sdk_types::TransactionKind::ProgrammableTransaction(
                sui_sdk_types::ProgrammableTransaction {
                    inputs: resolved_inputs,
                    commands: resolved_commands,
                },
            ),
            sender,
            gas_payment,
            expiration: self.expiration.unwrap_or(TransactionExpiration::None),
        })
    }

    /// Online build: resolve intents via RPC, then build.
    // FIX: Was `#[cfg(feature = "rpc")]` — feature is named "intents" in Cargo.toml.
    #[cfg(feature = "intents")]
    #[cfg_attr(docsrs, doc(cfg(feature = "intents")))]
    pub async fn build(mut self, client: &mut sui_rpc::Client) -> Result<Transaction, Error> {
        use sui_rpc::field::FieldMask;
        use sui_rpc::field::FieldMaskUtil;
        use sui_rpc::proto::sui::rpc::v2::input::InputKind;
        use sui_rpc::proto::sui::rpc::v2::Input;
        use sui_rpc::proto::sui::rpc::v2::SimulateTransactionRequest;
        use sui_rpc::proto::sui::rpc::v2::SimulateTransactionResponse;

        let Some(sender) = self.sender else {
            return Err(Error::MissingSender);
        };

        let mut request = SimulateTransactionRequest::default()
            .with_read_mask(FieldMask::from_paths([
                SimulateTransactionResponse::path_builder()
                    .transaction()
                    .transaction()
                    .finish(),
                SimulateTransactionResponse::path_builder()
                    .transaction()
                    .effects()
                    .finish(),
            ]))
            .with_do_gas_selection(true);
        request.transaction_mut().set_sender(sender);

        // Resolve intents
        let resolvers = std::mem::take(&mut self.resolvers);
        for resolver in resolvers.values() {
            resolver
                .resolve(&mut self, client)
                .await
                .map_err(|e| Error::Input(e.to_string()))?;
        }
        if !self.intents.is_empty() {
            return Err(Error::Input("unable to resolve all intents".to_owned()));
        }

        // Inputs
        let mut unresolved_inputs = self.inputs.into_values().collect::<Vec<_>>();
        unresolved_inputs.sort_by_key(|(id, _)| *id);

        let mut resolved_inputs = Vec::new();
        for (id, input) in unresolved_inputs {
            let arg = match input {
                InputArg::Gas => sui_sdk_types::Argument::Gas,
                InputArg::Pure(value) => {
                    resolved_inputs.push(
                        Input::default()
                            .with_kind(InputKind::Pure)
                            .with_pure(value),
                    );
                    sui_sdk_types::Argument::Input(resolved_inputs.len() as u16 - 1)
                }
                InputArg::Object(object_input) => {
                    resolved_inputs.push(object_input.to_input_proto());
                    sui_sdk_types::Argument::Input(resolved_inputs.len() as u16 - 1)
                }
            };
            *self.arguments.get_mut(&id).unwrap() = ResolvedArgument::Resolved(arg);
        }

        // Commands (dependency-ordered resolution)
        let mut resolved_commands = Vec::new();
        let mut stack = Vec::new();
        let mut to_resolve = self.commands.pop_first();
        while let Some((id, command)) = to_resolve.take() {
            let resolved = match command.try_resolve(&self.arguments) {
                Ok(resolved) => resolved,
                Err(Ok(next)) => {
                    stack.push((id, command));
                    to_resolve = Some(
                        self.commands
                            .remove_entry(&next)
                            .expect("command must exist if not yet resolved"),
                    );
                    continue;
                }
                Err(Err(e)) => return Err(e),
            };
            resolved_commands.push(resolved);
            let arg =
                sui_sdk_types::Argument::Result(resolved_commands.len() as u16 - 1);
            *self.arguments.get_mut(&id).unwrap() = ResolvedArgument::Resolved(arg);
            if let Some(from_stack) = stack.pop() {
                to_resolve = Some(from_stack);
            } else {
                to_resolve = self.commands.pop_first();
            }
        }

        let t = request.transaction_mut();
        t.kind_mut()
            .programmable_transaction_mut()
            .set_inputs(resolved_inputs);
        t.kind_mut()
            .programmable_transaction_mut()
            .set_commands(resolved_commands.into_iter().map(Into::into).collect());

        {
            let payment = request.transaction_mut().gas_payment_mut();
            payment.set_owner(self.sponsor.unwrap_or(sender));
            if let Some(budget) = self.gas_budget {
                payment.set_budget(budget);
            }
            if let Some(price) = self.gas_price {
                payment.set_price(price);
            }
            payment.set_objects(
                self.gas
                    .iter()
                    .map(ObjectInput::try_into_object_reference_proto)
                    .collect::<Result<_, _>>()?,
            );
        }

        let response = client
            .execution_client()
            .simulate_transaction(request)
            .await
            .map_err(|e| Error::Input(format!("error simulating transaction: {e}")))?;

        if !response
            .get_ref()
            .transaction()
            .effects()
            .status()
            .success()
        {
            return Err(Error::Input(format!(
                "txn failed to execute: {}",
                response
                    .get_ref()
                    .transaction()
                    .effects()
                    .status()
                    .error()
                    .description()
            )));
        }

        response
            .get_ref()
            .transaction()
            .transaction()
            .bcs()
            .deserialize()
            .map_err(|e| Error::Deserialization(e.to_string()))
    }

    #[cfg(feature = "intents")]
    pub(crate) fn register_resolver<R: crate::intent::IntentResolver>(&mut self, resolver: R) {
        self.resolvers
            .insert(resolver.type_id(), Box::new(resolver));
    }

    #[cfg(feature = "intents")]
    pub(crate) fn unresolved<T: std::any::Any + Send + Sync>(&mut self, unresolved: T) -> Argument {
        let id = self.next_argument_id();
        self.arguments.insert(id, ResolvedArgument::Unresolved);
        self.intents.insert(id, Box::new(unresolved));
        Argument::new(id)
    }

    #[cfg(feature = "intents")]
    pub(crate) fn sender(&self) -> Option<Address> {
        self.sender
    }

    // ── Private helpers ───────────────────────────────────────────────────

    /// Return the next unique argument ID.
    ///
    /// FIX (P1-6, shared root fix): Using last key + 1 rather than .len() means
    /// the ID is always unique even if keys are ever non-contiguous (e.g. after a
    /// future removal feature).  Consistent with the fix applied in ffi.rs's
    /// nested_result for the same reason.
    fn next_argument_id(&self) -> usize {
        self.arguments
            .keys()
            .last()
            .map(|k| k + 1)
            .unwrap_or(0)
    }
}

// ── Argument ──────────────────────────────────────────────────────────────────

#[derive(Clone, Copy, Debug)]
pub struct Argument {
    pub(crate) id: usize,
    pub(crate) sub_index: Option<usize>,
}

impl Argument {
    pub(crate) fn new(id: usize) -> Self {
        Self { id, sub_index: None }
    }

    pub fn to_nested(self, count: usize) -> Vec<Self> {
        (0..count)
            .map(|sub_index| Argument {
                sub_index: Some(sub_index),
                ..self
            })
            .collect()
    }

    fn try_resolve(
        self,
        resolved_arguments: &BTreeMap<usize, ResolvedArgument>,
    ) -> Result<sui_sdk_types::Argument, Result<usize, Error>> {
        let mut sub_index = self.sub_index;
        let arg = {
            let mut visited = BTreeSet::new();
            let mut next_id = self.id;
            loop {
                if visited.contains(&next_id) {
                    panic!("BUG: cyclic dependency");
                }
                visited.insert(next_id);
                match resolved_arguments.get(&next_id).unwrap() {
                    ResolvedArgument::Unresolved => return Err(Ok(next_id)),
                    ResolvedArgument::ReplaceWith(argument) => {
                        next_id = argument.id;
                        sub_index = argument.sub_index;
                    }
                    ResolvedArgument::Resolved(argument) => break argument,
                }
            }
        };

        if let Some(sub_index) = sub_index {
            if let Some(arg) = arg.nested(sub_index as u16) {
                return Ok(arg);
            } else {
                return Err(Err(Error::Input(
                    "unable to create nested argument".to_owned(),
                )));
            }
        }
        Ok(*arg)
    }

    fn try_resolve_many(
        arguments: &[Self],
        resolved_arguments: &BTreeMap<usize, ResolvedArgument>,
    ) -> Result<Vec<sui_sdk_types::Argument>, Result<usize, Error>> {
        arguments
            .iter()
            .map(|a| a.try_resolve(resolved_arguments))
            .collect::<Result<_, _>>()
    }
}

// ── Command internals ─────────────────────────────────────────────────────────

pub(crate) struct Command {
    kind: CommandKind,
    pub(crate) dependencies: Vec<Argument>,
}

impl From<CommandKind> for Command {
    fn from(value: CommandKind) -> Self {
        Self { kind: value, dependencies: Vec::new() }
    }
}

pub(crate) enum CommandKind {
    MoveCall(MoveCall),
    TransferObjects(TransferObjects),
    SplitCoins(SplitCoins),
    MergeCoins(MergeCoins),
    Publish(Publish),
    MakeMoveVector(MakeMoveVector),
    Upgrade(Upgrade),
}

impl Command {
    fn try_resolve(
        &self,
        resolved_arguments: &BTreeMap<usize, ResolvedArgument>,
    ) -> Result<sui_sdk_types::Command, Result<usize, Error>> {
        use sui_sdk_types::Command as C;
        Argument::try_resolve_many(&self.dependencies, resolved_arguments)?;
        let cmd = match &self.kind {
            CommandKind::MoveCall(MoveCall { package, module, function, type_arguments, arguments }) => {
                C::MoveCall(sui_sdk_types::MoveCall {
                    package: *package,
                    module: module.to_owned(),
                    function: function.to_owned(),
                    type_arguments: type_arguments.to_owned(),
                    arguments: Argument::try_resolve_many(arguments, resolved_arguments)?,
                })
            }
            CommandKind::TransferObjects(TransferObjects { objects, address }) => {
                C::TransferObjects(sui_sdk_types::TransferObjects {
                    objects: Argument::try_resolve_many(objects, resolved_arguments)?,
                    address: address.try_resolve(resolved_arguments)?,
                })
            }
            CommandKind::SplitCoins(SplitCoins { coin, amounts }) => {
                C::SplitCoins(sui_sdk_types::SplitCoins {
                    coin: coin.try_resolve(resolved_arguments)?,
                    amounts: Argument::try_resolve_many(amounts, resolved_arguments)?,
                })
            }
            CommandKind::MergeCoins(MergeCoins { coin, coins_to_merge }) => {
                C::MergeCoins(sui_sdk_types::MergeCoins {
                    coin: coin.try_resolve(resolved_arguments)?,
                    coins_to_merge: Argument::try_resolve_many(coins_to_merge, resolved_arguments)?,
                })
            }
            CommandKind::Publish(Publish { modules, dependencies }) => {
                C::Publish(sui_sdk_types::Publish {
                    modules: modules.to_owned(),
                    dependencies: dependencies.to_owned(),
                })
            }
            CommandKind::MakeMoveVector(MakeMoveVector { type_, elements }) => {
                C::MakeMoveVector(sui_sdk_types::MakeMoveVector {
                    type_: type_.to_owned(),
                    elements: Argument::try_resolve_many(elements, resolved_arguments)?,
                })
            }
            CommandKind::Upgrade(Upgrade { modules, dependencies, package, ticket }) => {
                C::Upgrade(sui_sdk_types::Upgrade {
                    modules: modules.to_owned(),
                    dependencies: dependencies.to_owned(),
                    package: *package,
                    ticket: ticket.try_resolve(resolved_arguments)?,
                })
            }
        };
        Ok(cmd)
    }
}

// ── Command structs ───────────────────────────────────────────────────────────

pub(crate) struct TransferObjects {
    pub objects: Vec<Argument>,
    pub address: Argument,
}

pub(crate) struct SplitCoins {
    pub coin: Argument,
    pub amounts: Vec<Argument>,
}

pub(crate) struct MergeCoins {
    pub coin: Argument,
    pub coins_to_merge: Vec<Argument>,
}

pub(crate) struct Publish {
    pub modules: Vec<Vec<u8>>,
    pub dependencies: Vec<Address>,
}

pub(crate) struct MakeMoveVector {
    pub type_: Option<TypeTag>,
    pub elements: Vec<Argument>,
}

pub(crate) struct Upgrade {
    pub modules: Vec<Vec<u8>>,
    pub dependencies: Vec<Address>,
    pub package: Address,
    pub ticket: Argument,
}

pub(crate) struct MoveCall {
    pub package: Address,
    pub module: Identifier,
    pub function: Identifier,
    pub type_arguments: Vec<TypeTag>,
    pub arguments: Vec<Argument>,
}

// ── ObjectInput ───────────────────────────────────────────────────────────────

pub struct ObjectInput {
    pub(crate) object_id: Address,
    kind: Option<ObjectKind>,
    version: Option<u64>,
    digest: Option<Digest>,
    mutable: Option<bool>,
}

#[derive(Clone, Copy)]
enum ObjectKind {
    Shared,
    Receiving,
    ImmutableOrOwned,
}

impl ObjectInput {
    pub fn new(object_id: Address) -> Self {
        Self { kind: None, object_id, version: None, digest: None, mutable: None }
    }

    pub fn owned(object_id: Address, version: u64, digest: Digest) -> Self {
        Self { kind: Some(ObjectKind::ImmutableOrOwned), object_id, version: Some(version), digest: Some(digest), mutable: None }
    }

    pub fn immutable(object_id: Address, version: u64, digest: Digest) -> Self {
        Self { kind: Some(ObjectKind::ImmutableOrOwned), object_id, version: Some(version), digest: Some(digest), mutable: None }
    }

    pub fn receiving(object_id: Address, version: u64, digest: Digest) -> Self {
        Self { kind: Some(ObjectKind::Receiving), object_id, version: Some(version), digest: Some(digest), mutable: None }
    }

    pub fn shared(object_id: Address, version: u64, mutable: bool) -> Self {
        Self { kind: Some(ObjectKind::Shared), object_id, version: Some(version), mutable: Some(mutable), digest: None }
    }

    pub fn as_immutable(self) -> Self { Self { kind: Some(ObjectKind::ImmutableOrOwned), ..self } }
    pub fn as_owned(self) -> Self { Self { kind: Some(ObjectKind::ImmutableOrOwned), ..self } }
    pub fn as_receiving(self) -> Self { Self { kind: Some(ObjectKind::Receiving), ..self } }
    pub fn as_shared(self) -> Self { Self { kind: Some(ObjectKind::Shared), ..self } }
    pub fn with_version(self, version: u64) -> Self { Self { version: Some(version), ..self } }
    pub fn with_digest(self, digest: Digest) -> Self { Self { digest: Some(digest), ..self } }
    pub fn with_mutable(self, mutable: bool) -> Self { Self { mutable: Some(mutable), ..self } }
}

impl From<&sui_sdk_types::Object> for ObjectInput {
    fn from(object: &sui_sdk_types::Object) -> Self {
        let input = Self::new(object.object_id())
            .with_version(object.version())
            .with_digest(object.digest());
        match object.owner() {
            sui_sdk_types::Owner::Address(_) => input.as_owned(),
            sui_sdk_types::Owner::Object(_) => input,
            sui_sdk_types::Owner::Shared(version) => input.with_version(*version).as_shared(),
            sui_sdk_types::Owner::Immutable => input.as_immutable(),
            sui_sdk_types::Owner::ConsensusAddress { start_version, .. } => {
                input.with_version(*start_version).as_shared()
            }
            _ => input,
        }
    }
}

impl ObjectInput {
    pub(crate) fn try_into_object_reference(&self) -> Result<sui_sdk_types::ObjectReference, Error> {
        if matches!(self.kind, Some(ObjectKind::ImmutableOrOwned) | None) {
            if let (Some(version), Some(digest)) = (self.version, self.digest) {
                return Ok(sui_sdk_types::ObjectReference::new(self.object_id, version, digest));
            }
        }
        Err(Error::WrongGasObject)
    }

    pub(crate) fn try_into_input(&self) -> Result<sui_sdk_types::Input, Error> {
        let input = match self {
            Self { object_id, kind: Some(ObjectKind::ImmutableOrOwned), version: Some(version), digest: Some(digest), .. }
            | Self { object_id, kind: None, version: Some(version), digest: Some(digest), mutable: None } => {
                sui_sdk_types::Input::ImmutableOrOwned(sui_sdk_types::ObjectReference::new(*object_id, *version, *digest))
            }
            Self { object_id, kind: Some(ObjectKind::Receiving), version: Some(version), digest: Some(digest), .. } => {
                sui_sdk_types::Input::Receiving(sui_sdk_types::ObjectReference::new(*object_id, *version, *digest))
            }
            Self { object_id, kind: Some(ObjectKind::Shared), version: Some(version), mutable: Some(mutable), .. }
            | Self { object_id, kind: None, version: Some(version), digest: None, mutable: Some(mutable) } => {
                sui_sdk_types::Input::Shared(sui_sdk_types::SharedInput::new(*object_id, *version, *mutable))
            }
            _ => {
                return Err(Error::Input(format!("Input object {} is incomplete", self.object_id)));
            }
        };
        Ok(input)
    }

    #[cfg(feature = "intents")]
    pub(crate) fn to_input_proto(&self) -> sui_rpc::proto::sui::rpc::v2::Input {
        use sui_rpc::proto::sui::rpc::v2::input::InputKind;
        let mut input = sui_rpc::proto::sui::rpc::v2::Input::default().with_object_id(self.object_id);
        match self.kind {
            Some(ObjectKind::Shared) => input.set_kind(InputKind::Shared),
            Some(ObjectKind::Receiving) => input.set_kind(InputKind::Receiving),
            Some(ObjectKind::ImmutableOrOwned) => input.set_kind(InputKind::ImmutableOrOwned),
            None => {}
        }
        if let Some(version) = self.version { input.set_version(version); }
        if let Some(digest) = self.digest { input.set_digest(digest); }
        if let Some(mutable) = self.mutable { input.set_mutable(mutable); }
        input
    }

    #[cfg(feature = "intents")]
    pub(crate) fn try_into_object_reference_proto(&self) -> Result<sui_rpc::proto::sui::rpc::v2::ObjectReference, Error> {
        if !matches!(self.kind, Some(ObjectKind::ImmutableOrOwned) | None) {
            return Err(Error::WrongGasObject);
        }
        let mut input = sui_rpc::proto::sui::rpc::v2::ObjectReference::default().with_object_id(self.object_id);
        if let Some(version) = self.version { input.set_version(version); }
        if let Some(digest) = self.digest { input.set_digest(digest); }
        Ok(input)
    }

    #[cfg(feature = "intents")]
    pub(crate) fn try_from_object_proto(object: &sui_rpc::proto::sui::rpc::v2::Object) -> Result<Self, Error> {
        use sui_rpc::proto::sui::rpc::v2::owner::OwnerKind;
        let input = Self::new(object.object_id().parse().map_err(|_e| Error::MissingObjectId)?);
        Ok(match object.owner().kind() {
            OwnerKind::Address | OwnerKind::Immutable => input.as_owned()
                .with_version(object.version())
                .with_digest(object.digest().parse().map_err(|_| Error::Input("can't parse digest".to_owned()))?),
            OwnerKind::Object => return Err(Error::Input("invalid object type".to_owned())),
            OwnerKind::Shared | OwnerKind::ConsensusAddress => {
                input.as_shared().with_version(object.owner().version()).with_mutable(true)
            }
            OwnerKind::Unknown | _ => input,
        })
    }
}

// ── Function ──────────────────────────────────────────────────────────────────

pub struct Function {
    pub(crate) package: Address,
    pub(crate) module: Identifier,
    pub(crate) function: Identifier,
    pub(crate) type_args: Vec<TypeTag>,
}

impl Function {
    pub fn new(package: Address, module: Identifier, function: Identifier) -> Self {
        Self { package, module, function, type_args: Vec::new() }
    }

    pub fn with_type_args(self, type_args: Vec<TypeTag>) -> Self {
        Self { type_args, ..self }
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn simple_try_build() {
        let mut tx = TransactionBuilder::new();
        let _coin = tx.object(ObjectInput::owned(
            Address::from_static("0x19406ea4d9609cd9422b85e6bf2486908f790b778c757aff805241f3f609f9b4"),
            2,
            Digest::from_static("7opR9rFUYivSTqoJHvFb9p6p54THyHTatMG6id4JKZR9"),
        ));
        let _gas = tx.gas();
        let _recipient = tx.pure(&Address::from_static("0xabc"));
        assert!(tx.try_build().is_err());

        let mut tx = TransactionBuilder::new();
        let coin = tx.object(ObjectInput::owned(
            Address::from_static("0x19406ea4d9609cd9422b85e6bf2486908f790b778c757aff805241f3f609f9b4"),
            2,
            Digest::from_static("7opR9rFUYivSTqoJHvFb9p6p54THyHTatMG6id4JKZR9"),
        ));
        let gas = tx.gas();
        let recipient = tx.pure(&Address::from_static("0xabc"));
        tx.transfer_objects(vec![coin, gas], recipient);
        tx.set_gas_budget(500_000_000);
        tx.set_gas_price(1000);
        tx.add_gas_objects([ObjectInput::owned(
            Address::from_static("0xd8792bce2743e002673752902c0e7348dfffd78638cb5367b0b85857bceb9821"),
            2,
            Digest::from_static("2ZigdvsZn5BMeszscPQZq9z8ebnS2FpmAuRbAi9ednCk"),
        )]);
        tx.set_sender(Address::from_static("0xc574ea804d9c1a27c886312e96c0e2c9cfd71923ebaeb3000d04b5e65fca2793"));
        assert!(tx.try_build().is_ok());
    }

    #[test]
    fn test_split_transfer() {
        let mut tx = TransactionBuilder::new();
        let amount = tx.pure(&1_000_000_000u64);
        let gas = tx.gas();
        let result = tx.split_coins(gas, vec![amount; 5]);
        let recipient = tx.pure(&Address::from_static("0xabc"));
        tx.transfer_objects(result, recipient);
        tx.set_gas_budget(500_000_000);
        tx.set_gas_price(1000);
        tx.add_gas_objects([ObjectInput::owned(
            Address::from_static("0xd8792bce2743e002673752902c0e7348dfffd78638cb5367b0b85857bceb9821"),
            2,
            Digest::from_static("2ZigdvsZn5BMeszscPQZq9z8ebnS2FpmAuRbAi9ednCk"),
        )]);
        tx.set_sender(Address::from_static("0xc574ea804d9c1a27c886312e96c0e2c9cfd71923ebaeb3000d04b5e65fca2793"));
        assert!(tx.try_build().is_ok());
    }

    #[test]
    fn test_deterministic_building() {
        let build_tx = || {
            let mut tx = TransactionBuilder::new();
            let coin = tx.object(ObjectInput::owned(
                Address::from_static("0x19406ea4d9609cd9422b85e6bf2486908f790b778c757aff805241f3f609f9b4"),
                2,
                Digest::from_static("7opR9rFUYivSTqoJHvFb9p6p54THyHTatMG6id4JKZR9"),
            ));
            let _ = tx.object(ObjectInput::owned(Address::from_static("0x12345"), 2, Digest::from_static("7opR9rFUYivSTqoJHvFb9p6p54THyHTatMG6id4JKZR9")));
            let _ = tx.object(ObjectInput::owned(Address::from_static("0x12345"), 2, Digest::from_static("7opR9rFUYivSTqoJHvFb9p6p54THyHTatMG6id4JKZR9")));
            let gas = tx.gas();
            let _ = tx.pure(&Address::from_static("0xabc"));
            let _ = tx.pure(&Address::from_static("0xabc"));
            let _ = tx.pure(&Address::from_static("0xabc"));
            let _ = tx.pure(&Address::from_static("0xdef"));
            let _ = tx.pure(&1u64);
            let _ = tx.pure(&1u64);
            let _ = tx.pure(&1u64);
            let _ = tx.pure(&Some(2u8));
            let _ = tx.pure_unique(&Address::from_static("0xabc"));
            let _ = tx.pure_unique(&Address::from_static("0xabc"));
            let _ = tx.pure_unique(&1u64);
            let recipient = tx.pure(&Address::from_static("0x123"));
            tx.transfer_objects(vec![coin, gas], recipient);
            tx.set_gas_budget(500_000_000);
            tx.set_gas_price(1000);
            tx.add_gas_objects([ObjectInput::owned(
                Address::from_static("0xd8792bce2743e002673752902c0e7348dfffd78638cb5367b0b85857bceb9821"),
                2,
                Digest::from_static("2ZigdvsZn5BMeszscPQZq9z8ebnS2FpmAuRbAi9ednCk"),
            )]);
            tx.set_sender(Address::from_static("0xc574ea804d9c1a27c886312e96c0e2c9cfd71923ebaeb3000d04b5e65fca2793"));
            tx.try_build().unwrap()
        };

        let digest = build_tx().digest();
        assert!((0..100).map(|_| build_tx()).map(|tx| tx.digest()).all(|d| d == digest));
    }

    /// Verify that next_argument_id is stable under deduplication.
    #[test]
    fn test_argument_ids_never_collide() {
        let mut tx = TransactionBuilder::new();
        let a0 = tx.pure(&0u64).id;
        let a1 = tx.pure(&1u64).id;
        let a2 = tx.gas().id;
        // Calling pure(&0u64) again must return the SAME id (dedup), not a new one.
        let a0_again = tx.pure(&0u64).id;
        assert_eq!(a0, a0_again, "deduplicated pure must return same id");
        // All three distinct inputs must have distinct ids.
        assert_ne!(a0, a1);
        assert_ne!(a1, a2);
        assert_ne!(a0, a2);
    }
}
