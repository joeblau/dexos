//! Immutable decision-market definition and its validated construction.
//!
//! A [`DecisionMarketDefinition`] fixes the actions, outcomes, immutable utility
//! function, decision rule, time windows, and the counterfactual policy for
//! unselected actions. It also provides a panic-free binary codec so arbitrary
//! bytes can be decoded and validated (or rejected) without ever panicking.

use crypto::{Validator, ValidatorSet, MAX_VALIDATORS};
use serde::{Deserialize, Serialize};
use types::{Amount, MarketId, MarketType, Ratio, RATIO_SCALE};

use crate::error::DecisionMarketError;
use crate::twap::TimeWindow;

/// Maximum number of actions (contingent markets) in one decision market.
pub const MAX_ACTIONS: usize = 64;
/// Maximum number of outcomes per market.
pub const MAX_OUTCOMES: usize = types::MAX_OUTCOMES;
/// Maximum label length in bytes.
pub const MAX_LABEL_BYTES: usize = 64;

/// A candidate action the decision market can select.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Action {
    /// Human-readable label (non-empty, at most [`MAX_LABEL_BYTES`] bytes).
    pub label: String,
}

impl Action {
    /// Construct an action with the given label.
    pub fn new(label: impl Into<String>) -> Self {
        Self {
            label: label.into(),
        }
    }
}

/// A mutually-exclusive outcome shared across every contingent market.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Outcome {
    /// Human-readable label (non-empty, at most [`MAX_LABEL_BYTES`] bytes).
    pub label: String,
}

impl Outcome {
    /// Construct an outcome with the given label.
    pub fn new(label: impl Into<String>) -> Self {
        Self {
            label: label.into(),
        }
    }
}

/// An immutable fixed-point mapping from outcome index to a utility value.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UtilityFunction {
    utilities: Vec<Amount>,
}

impl UtilityFunction {
    /// Construct, rejecting empty or over-large utility vectors.
    pub fn new(utilities: Vec<Amount>) -> Result<Self, DecisionMarketError> {
        if utilities.is_empty() {
            return Err(DecisionMarketError::NoOutcomes);
        }
        if utilities.len() > MAX_OUTCOMES {
            return Err(DecisionMarketError::TooManyOutcomes { max: MAX_OUTCOMES });
        }
        Ok(Self { utilities })
    }

    /// The number of outcomes this utility function covers.
    #[inline]
    pub fn len(&self) -> usize {
        self.utilities.len()
    }

    /// Whether the utility function is empty (never true once constructed).
    #[inline]
    pub fn is_empty(&self) -> bool {
        self.utilities.is_empty()
    }

    /// The utility of a single outcome by index.
    #[inline]
    pub fn utility(&self, outcome: usize) -> Option<Amount> {
        self.utilities.get(outcome).copied()
    }

    /// The utility values by outcome index (immutable view).
    #[inline]
    pub fn values(&self) -> &[Amount] {
        &self.utilities
    }
}

/// How the winning action is chosen from time-weighted expected utility.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DecisionRule {
    /// Pick the action with the greatest time-weighted expected utility.
    MaximizeExpectedUtility,
    /// Pick the action with the least time-weighted expected utility.
    MinimizeExpectedUtility,
}

impl DecisionRule {
    fn to_u8(self) -> u8 {
        match self {
            DecisionRule::MaximizeExpectedUtility => 0,
            DecisionRule::MinimizeExpectedUtility => 1,
        }
    }

    fn from_u8(b: u8) -> Result<Self, DecisionMarketError> {
        match b {
            0 => Ok(DecisionRule::MaximizeExpectedUtility),
            1 => Ok(DecisionRule::MinimizeExpectedUtility),
            _ => Err(DecisionMarketError::MalformedDefinition),
        }
    }
}

/// Counterfactual settlement policy for actions that were NOT selected.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum UnselectedActionPolicy {
    /// Refund each depositor the collateral they contributed (unwind the market).
    Refund,
    /// Void: distribute the market's collateral to current holders pro-rata by
    /// total shares held (a complete set redeems at par regardless of outcome).
    Void,
}

impl UnselectedActionPolicy {
    fn to_u8(self) -> u8 {
        match self {
            UnselectedActionPolicy::Refund => 0,
            UnselectedActionPolicy::Void => 1,
        }
    }

    fn from_u8(b: u8) -> Result<Self, DecisionMarketError> {
        match b {
            0 => Ok(UnselectedActionPolicy::Refund),
            1 => Ok(UnselectedActionPolicy::Void),
            _ => Err(DecisionMarketError::MalformedDefinition),
        }
    }
}

/// Minimum-liquidity and concentration guards committed in the immutable
/// definition.
///
/// Because the guards live in the definition they cannot be varied at selection
/// time, and their ranges are validated once at construction via
/// [`DecisionGuards::validate`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct DecisionGuards {
    /// Minimum collateral each contingent market must hold to be decided
    /// (must be non-negative).
    pub min_liquidity: Amount,
    /// Maximum share of a single market a single account may hold: a
    /// dimensionless fraction in `(0, 1]` (`RATIO_SCALE` == 1.0).
    pub max_concentration: Ratio,
}

impl DecisionGuards {
    /// Construct guards. Range validity is enforced by [`Self::validate`], which
    /// the definition validator invokes; construction itself is total.
    #[inline]
    pub const fn new(min_liquidity: Amount, max_concentration: Ratio) -> Self {
        Self {
            min_liquidity,
            max_concentration,
        }
    }

    /// Validate the committed ranges: a non-negative liquidity floor and a
    /// concentration limit that is a fraction in `(0, 1]`. A zero (or negative)
    /// concentration limit could never be met; one above `1.0` is meaningless.
    pub fn validate(&self) -> Result<(), DecisionMarketError> {
        if self.min_liquidity.raw() < 0 {
            return Err(DecisionMarketError::InvalidGuards);
        }
        let c = self.max_concentration.raw();
        if !(1..=RATIO_SCALE).contains(&c) {
            return Err(DecisionMarketError::InvalidGuards);
        }
        Ok(())
    }
}

/// The complete, immutable specification of a decision market.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DecisionMarketDefinition {
    /// One contingent market is spawned per action.
    pub actions: Vec<Action>,
    /// The shared mutually-exclusive outcome set.
    pub outcomes: Vec<Outcome>,
    /// Immutable outcome -> utility mapping.
    pub utility_function: UtilityFunction,
    /// How the winning action is chosen.
    pub decision_rule: DecisionRule,
    /// Window over which the time-weighted decision price is measured.
    pub selection_window: TimeWindow,
    /// Window over which the selected action's outcome is evaluated.
    pub evaluation_window: TimeWindow,
    /// Settlement policy for the actions that were not selected.
    pub unselected_action_policy: UnselectedActionPolicy,
    /// Collateral (par) value backing one complete set of outcome shares.
    pub collateral_per_set: Amount,
    /// The market this definition is for; every confirmation must name it.
    pub market_id: MarketId,
    /// The network this market lives on; every confirmation must name it (so a
    /// confirmation minted for another network is rejected).
    pub network_id: u64,
    /// Committed liquidity/concentration guards; immutable at selection time.
    pub guards: DecisionGuards,
    /// Minimum fraction of the selection window that observed (inter-tick)
    /// decision-price intervals must cover for a valid decision. A `Ratio` in
    /// `(0, 1]`; a positive floor makes a single final tick undecidable.
    pub min_twap_coverage: Ratio,
    /// The authority set whose threshold signature confirms actions and
    /// outcomes. Committing the keys here rejects wrong-authority confirmations.
    pub authority_set: ValidatorSet,
}

impl DecisionMarketDefinition {
    /// Construct and validate a definition.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        actions: Vec<Action>,
        outcomes: Vec<Outcome>,
        utility_function: UtilityFunction,
        decision_rule: DecisionRule,
        selection_window: TimeWindow,
        evaluation_window: TimeWindow,
        unselected_action_policy: UnselectedActionPolicy,
        collateral_per_set: Amount,
        market_id: MarketId,
        network_id: u64,
        guards: DecisionGuards,
        min_twap_coverage: Ratio,
        authority_set: ValidatorSet,
    ) -> Result<Self, DecisionMarketError> {
        let def = Self {
            actions,
            outcomes,
            utility_function,
            decision_rule,
            selection_window,
            evaluation_window,
            unselected_action_policy,
            collateral_per_set,
            market_id,
            network_id,
            guards,
            min_twap_coverage,
            authority_set,
        };
        def.validate()?;
        Ok(def)
    }

    /// Validate all structural invariants. Returns a typed error, never panics.
    pub fn validate(&self) -> Result<(), DecisionMarketError> {
        if self.actions.is_empty() {
            return Err(DecisionMarketError::NoActions);
        }
        if self.actions.len() > MAX_ACTIONS {
            return Err(DecisionMarketError::TooManyActions { max: MAX_ACTIONS });
        }
        if self.outcomes.is_empty() {
            return Err(DecisionMarketError::NoOutcomes);
        }
        if self.outcomes.len() > MAX_OUTCOMES {
            return Err(DecisionMarketError::TooManyOutcomes { max: MAX_OUTCOMES });
        }
        if self.utility_function.len() != self.outcomes.len() {
            return Err(DecisionMarketError::UtilityLengthMismatch {
                expected: self.outcomes.len(),
                got: self.utility_function.len(),
            });
        }
        for label in self
            .actions
            .iter()
            .map(|a| &a.label)
            .chain(self.outcomes.iter().map(|o| &o.label))
        {
            if label.is_empty() || label.len() > MAX_LABEL_BYTES {
                return Err(DecisionMarketError::InvalidLabel {
                    max: MAX_LABEL_BYTES,
                });
            }
        }
        // Windows are already positive-duration by construction; enforce ordering.
        if self.evaluation_window.start < self.selection_window.end {
            return Err(DecisionMarketError::WindowOrdering);
        }
        if self.collateral_per_set.raw() <= 0 {
            return Err(DecisionMarketError::NonPositiveCollateral);
        }
        // Committed guards must carry valid ranges (see `DecisionGuards`).
        self.guards.validate()?;
        // The minimum window coverage is a fraction in `(0, 1]`; a positive floor
        // is what makes a single, non-time-weighting final tick undecidable.
        let coverage = self.min_twap_coverage.raw();
        if !(1..=RATIO_SCALE).contains(&coverage) {
            return Err(DecisionMarketError::InvalidCoverageThreshold);
        }
        // The authority set's canonical invariants (nonempty, unique keys,
        // positive weights, in-range threshold) hold by its own construction.
        Ok(())
    }

    /// The number of actions (contingent markets).
    #[inline]
    pub fn num_actions(&self) -> usize {
        self.actions.len()
    }

    /// The number of outcomes.
    #[inline]
    pub fn num_outcomes(&self) -> usize {
        self.outcomes.len()
    }

    /// The market type registry tag for a decision market.
    #[inline]
    pub const fn market_type(&self) -> MarketType {
        MarketType::Decision
    }

    /// Serialize to a compact, deterministic binary form.
    ///
    /// The format is length-prefixed and self-describing so [`Self::decode`] can
    /// reject truncated or malformed input without panicking.
    pub fn encode(&self) -> Result<Vec<u8>, DecisionMarketError> {
        let mut out = Vec::new();
        let na = u8::try_from(self.actions.len()).map_err(|_| DecisionMarketError::Truncation)?;
        out.push(na);
        for a in &self.actions {
            write_label(&mut out, &a.label)?;
        }
        let no = u16::try_from(self.outcomes.len()).map_err(|_| DecisionMarketError::Truncation)?;
        out.extend_from_slice(&no.to_le_bytes());
        for o in &self.outcomes {
            write_label(&mut out, &o.label)?;
        }
        for u in self.utility_function.values() {
            out.extend_from_slice(&u.raw().to_le_bytes());
        }
        out.push(self.decision_rule.to_u8());
        out.push(self.unselected_action_policy.to_u8());
        out.extend_from_slice(&self.selection_window.start.to_le_bytes());
        out.extend_from_slice(&self.selection_window.end.to_le_bytes());
        out.extend_from_slice(&self.evaluation_window.start.to_le_bytes());
        out.extend_from_slice(&self.evaluation_window.end.to_le_bytes());
        out.extend_from_slice(&self.collateral_per_set.raw().to_le_bytes());
        out.extend_from_slice(&self.market_id.get().to_le_bytes());
        out.extend_from_slice(&self.network_id.to_le_bytes());
        out.extend_from_slice(&self.guards.min_liquidity.raw().to_le_bytes());
        out.extend_from_slice(&self.guards.max_concentration.raw().to_le_bytes());
        out.extend_from_slice(&self.min_twap_coverage.raw().to_le_bytes());
        let nv =
            u8::try_from(self.authority_set.len()).map_err(|_| DecisionMarketError::Truncation)?;
        out.push(nv);
        for v in self.authority_set.validators() {
            out.extend_from_slice(&v.public_key);
            out.extend_from_slice(&v.weight.to_le_bytes());
        }
        out.extend_from_slice(&self.authority_set.threshold().to_le_bytes());
        Ok(out)
    }

    /// Decode from bytes produced by [`Self::encode`], validating the result.
    ///
    /// Any malformed / truncated input yields a typed error; this never panics
    /// on arbitrary bytes.
    pub fn decode(bytes: &[u8]) -> Result<Self, DecisionMarketError> {
        let mut r = Reader::new(bytes);
        let na = usize::from(r.u8()?);
        if na == 0 || na > MAX_ACTIONS {
            return Err(DecisionMarketError::MalformedDefinition);
        }
        let mut actions = Vec::with_capacity(na);
        for _ in 0..na {
            actions.push(Action::new(read_label(&mut r)?));
        }
        let no = usize::from(r.u16()?);
        if no == 0 || no > MAX_OUTCOMES {
            return Err(DecisionMarketError::MalformedDefinition);
        }
        let mut outcomes = Vec::with_capacity(no);
        for _ in 0..no {
            outcomes.push(Outcome::new(read_label(&mut r)?));
        }
        let mut utils = Vec::with_capacity(no);
        for _ in 0..no {
            utils.push(Amount::from_raw(r.i128()?));
        }
        let utility_function =
            UtilityFunction::new(utils).map_err(|_| DecisionMarketError::MalformedDefinition)?;
        let decision_rule = DecisionRule::from_u8(r.u8()?)?;
        let policy = UnselectedActionPolicy::from_u8(r.u8()?)?;
        let sel_start = r.u64()?;
        let sel_end = r.u64()?;
        let eval_start = r.u64()?;
        let eval_end = r.u64()?;
        let collateral = Amount::from_raw(r.i128()?);
        let market_id = MarketId::new(r.u32()?);
        let network_id = r.u64()?;
        let min_liquidity = Amount::from_raw(r.i128()?);
        let max_concentration = Ratio::from_raw(r.i64()?);
        let min_twap_coverage = Ratio::from_raw(r.i64()?);
        let nv = usize::from(r.u8()?);
        if nv == 0 || nv > MAX_VALIDATORS {
            return Err(DecisionMarketError::MalformedDefinition);
        }
        let mut validators = Vec::with_capacity(nv);
        for _ in 0..nv {
            let public_key = r.key32()?;
            let weight = r.u64()?;
            validators.push(Validator { public_key, weight });
        }
        let threshold = r.u64()?;
        if !r.is_empty() {
            return Err(DecisionMarketError::MalformedDefinition);
        }
        let selection_window = TimeWindow::new(sel_start, sel_end)
            .map_err(|_| DecisionMarketError::MalformedDefinition)?;
        let evaluation_window = TimeWindow::new(eval_start, eval_end)
            .map_err(|_| DecisionMarketError::MalformedDefinition)?;
        let authority_set = ValidatorSet::try_with_threshold(validators, threshold)
            .map_err(|_| DecisionMarketError::MalformedDefinition)?;
        let def = Self {
            actions,
            outcomes,
            utility_function,
            decision_rule,
            selection_window,
            evaluation_window,
            unselected_action_policy: policy,
            collateral_per_set: collateral,
            market_id,
            network_id,
            guards: DecisionGuards::new(min_liquidity, max_concentration),
            min_twap_coverage,
            authority_set,
        };
        def.validate()?;
        Ok(def)
    }
}

fn write_label(out: &mut Vec<u8>, label: &str) -> Result<(), DecisionMarketError> {
    let len = u8::try_from(label.len()).map_err(|_| DecisionMarketError::Truncation)?;
    out.push(len);
    out.extend_from_slice(label.as_bytes());
    Ok(())
}

fn read_label(r: &mut Reader<'_>) -> Result<String, DecisionMarketError> {
    let len = usize::from(r.u8()?);
    if len > MAX_LABEL_BYTES {
        return Err(DecisionMarketError::MalformedDefinition);
    }
    let bytes = r.take(len)?;
    String::from_utf8(bytes.to_vec()).map_err(|_| DecisionMarketError::MalformedDefinition)
}

/// A panic-free forward byte cursor.
struct Reader<'a> {
    bytes: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, pos: 0 }
    }

    fn is_empty(&self) -> bool {
        self.pos >= self.bytes.len()
    }

    fn take(&mut self, n: usize) -> Result<&'a [u8], DecisionMarketError> {
        let end = self
            .pos
            .checked_add(n)
            .ok_or(DecisionMarketError::MalformedDefinition)?;
        let slice = self
            .bytes
            .get(self.pos..end)
            .ok_or(DecisionMarketError::MalformedDefinition)?;
        self.pos = end;
        Ok(slice)
    }

    fn u8(&mut self) -> Result<u8, DecisionMarketError> {
        Ok(self.take(1)?[0])
    }

    fn u16(&mut self) -> Result<u16, DecisionMarketError> {
        let b = self.take(2)?;
        let arr = <[u8; 2]>::try_from(b).map_err(|_| DecisionMarketError::MalformedDefinition)?;
        Ok(u16::from_le_bytes(arr))
    }

    fn u32(&mut self) -> Result<u32, DecisionMarketError> {
        let b = self.take(4)?;
        let arr = <[u8; 4]>::try_from(b).map_err(|_| DecisionMarketError::MalformedDefinition)?;
        Ok(u32::from_le_bytes(arr))
    }

    fn u64(&mut self) -> Result<u64, DecisionMarketError> {
        let b = self.take(8)?;
        let arr = <[u8; 8]>::try_from(b).map_err(|_| DecisionMarketError::MalformedDefinition)?;
        Ok(u64::from_le_bytes(arr))
    }

    fn i64(&mut self) -> Result<i64, DecisionMarketError> {
        let b = self.take(8)?;
        let arr = <[u8; 8]>::try_from(b).map_err(|_| DecisionMarketError::MalformedDefinition)?;
        Ok(i64::from_le_bytes(arr))
    }

    fn i128(&mut self) -> Result<i128, DecisionMarketError> {
        let b = self.take(16)?;
        let arr = <[u8; 16]>::try_from(b).map_err(|_| DecisionMarketError::MalformedDefinition)?;
        Ok(i128::from_le_bytes(arr))
    }

    fn key32(&mut self) -> Result<[u8; 32], DecisionMarketError> {
        let b = self.take(32)?;
        <[u8; 32]>::try_from(b).map_err(|_| DecisionMarketError::MalformedDefinition)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crypto::ThresholdSigners;

    pub(crate) fn authority_set() -> ValidatorSet {
        let seeds: Vec<[u8; 32]> = (0..4).map(|i| [u8::try_from(i).unwrap(); 32]).collect();
        ThresholdSigners::from_seeds(&seeds, 3).validator_set()
    }

    pub(crate) fn sample_definition() -> DecisionMarketDefinition {
        DecisionMarketDefinition::new(
            vec![Action::new("ship"), Action::new("hold")],
            vec![Outcome::new("up"), Outcome::new("down")],
            UtilityFunction::new(vec![Amount::from_raw(10_000_000), Amount::ZERO]).unwrap(),
            DecisionRule::MaximizeExpectedUtility,
            TimeWindow::new(0, 100).unwrap(),
            TimeWindow::new(100, 200).unwrap(),
            UnselectedActionPolicy::Refund,
            Amount::from_raw(1_000_000),
            MarketId::new(5),
            7,
            DecisionGuards::new(Amount::ZERO, Ratio::ONE),
            Ratio::from_raw(500_000),
            authority_set(),
        )
        .unwrap()
    }

    #[test]
    fn valid_definition_constructs_and_is_decision_type() {
        let def = sample_definition();
        assert_eq!(def.num_actions(), 2);
        assert_eq!(def.num_outcomes(), 2);
        assert_eq!(def.market_type(), MarketType::Decision);
    }

    #[test]
    fn utility_length_mismatch_rejected() {
        let err = DecisionMarketDefinition::new(
            vec![Action::new("a")],
            vec![Outcome::new("x"), Outcome::new("y")],
            UtilityFunction::new(vec![Amount::ONE]).unwrap(),
            DecisionRule::MaximizeExpectedUtility,
            TimeWindow::new(0, 10).unwrap(),
            TimeWindow::new(10, 20).unwrap(),
            UnselectedActionPolicy::Void,
            Amount::ONE,
            MarketId::new(1),
            1,
            DecisionGuards::new(Amount::ZERO, Ratio::ONE),
            Ratio::from_raw(500_000),
            authority_set(),
        )
        .unwrap_err();
        assert_eq!(
            err,
            DecisionMarketError::UtilityLengthMismatch {
                expected: 2,
                got: 1
            }
        );
    }

    #[test]
    fn window_ordering_and_collateral_validated() {
        // Evaluation starts before selection ends.
        let err = DecisionMarketDefinition::new(
            vec![Action::new("a")],
            vec![Outcome::new("x")],
            UtilityFunction::new(vec![Amount::ONE]).unwrap(),
            DecisionRule::MaximizeExpectedUtility,
            TimeWindow::new(0, 100).unwrap(),
            TimeWindow::new(50, 200).unwrap(),
            UnselectedActionPolicy::Void,
            Amount::ONE,
            MarketId::new(1),
            1,
            DecisionGuards::new(Amount::ZERO, Ratio::ONE),
            Ratio::from_raw(500_000),
            authority_set(),
        )
        .unwrap_err();
        assert_eq!(err, DecisionMarketError::WindowOrdering);
    }

    fn definition_with(
        guards: DecisionGuards,
        coverage: Ratio,
    ) -> Result<DecisionMarketDefinition, DecisionMarketError> {
        DecisionMarketDefinition::new(
            vec![Action::new("a")],
            vec![Outcome::new("x")],
            UtilityFunction::new(vec![Amount::ONE]).unwrap(),
            DecisionRule::MaximizeExpectedUtility,
            TimeWindow::new(0, 100).unwrap(),
            TimeWindow::new(100, 200).unwrap(),
            UnselectedActionPolicy::Void,
            Amount::ONE,
            MarketId::new(1),
            1,
            guards,
            coverage,
            authority_set(),
        )
    }

    #[test]
    fn invalid_guard_ranges_rejected() {
        // Negative liquidity floor.
        assert_eq!(
            definition_with(
                DecisionGuards::new(Amount::from_raw(-1), Ratio::ONE),
                Ratio::from_raw(500_000)
            ),
            Err(DecisionMarketError::InvalidGuards)
        );
        // Zero concentration limit can never be met.
        assert_eq!(
            definition_with(
                DecisionGuards::new(Amount::ZERO, Ratio::ZERO),
                Ratio::from_raw(500_000)
            ),
            Err(DecisionMarketError::InvalidGuards)
        );
        // Concentration above 1.0 is meaningless.
        assert_eq!(
            definition_with(
                DecisionGuards::new(Amount::ZERO, Ratio::from_raw(RATIO_SCALE + 1)),
                Ratio::from_raw(500_000)
            ),
            Err(DecisionMarketError::InvalidGuards)
        );
        // Boundaries: exactly 1 micro and exactly 1.0 are both valid.
        assert!(definition_with(
            DecisionGuards::new(Amount::ZERO, Ratio::from_raw(1)),
            Ratio::ONE
        )
        .is_ok());
    }

    #[test]
    fn invalid_coverage_threshold_rejected() {
        assert_eq!(
            definition_with(DecisionGuards::new(Amount::ZERO, Ratio::ONE), Ratio::ZERO),
            Err(DecisionMarketError::InvalidCoverageThreshold)
        );
        assert_eq!(
            definition_with(
                DecisionGuards::new(Amount::ZERO, Ratio::ONE),
                Ratio::from_raw(RATIO_SCALE + 1)
            ),
            Err(DecisionMarketError::InvalidCoverageThreshold)
        );
        // Exactly 1.0 coverage is valid.
        assert!(definition_with(DecisionGuards::new(Amount::ZERO, Ratio::ONE), Ratio::ONE).is_ok());
    }

    #[test]
    fn encode_decode_round_trips() {
        let def = sample_definition();
        let bytes = def.encode().unwrap();
        let back = DecisionMarketDefinition::decode(&bytes).unwrap();
        assert_eq!(def, back);
    }

    // LCG-driven fuzz: arbitrary bytes either decode+validate or error, never panic.
    struct Lcg(u64);
    impl Lcg {
        fn next(&mut self) -> u64 {
            self.0 = self
                .0
                .wrapping_mul(6364136223846793005)
                .wrapping_add(1442695040888963407);
            self.0
        }
    }

    #[test]
    fn decode_never_panics_on_arbitrary_bytes() {
        let mut r = Lcg(0xDEC151);
        for _ in 0..20_000 {
            let len = usize::try_from(r.next() % 96).unwrap();
            let mut bytes = Vec::with_capacity(len);
            for _ in 0..len {
                bytes.push(u8::try_from(r.next() & 0xff).unwrap());
            }
            let _ = DecisionMarketDefinition::decode(&bytes);
        }
        // Explicit edge cases.
        for bytes in [vec![], vec![0], vec![255], vec![1, 3, b'a', b'b', b'c']] {
            let _ = DecisionMarketDefinition::decode(&bytes);
        }
    }
}
