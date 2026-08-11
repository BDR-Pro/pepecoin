# Pepecoin Adversarial Consensus Security Audit

**Audit type:** Authorized adversarial consensus / monetary-integrity review
**Scope:** Consensus-critical code paths governing money creation, transfer, and
validation. Emphasis on inflation, coinbase overpayment, value-conservation,
double-spend, UTXO/reorg accounting, AuxPoW/merged-mining validation, PoW /
difficulty, serialization ambiguity, and consensus splits.
**Method:** Static source analysis, upstream differential analysis against
Dogecoin Core, a compiled build, the existing unit + functional test suites,
new adversarial unit tests, and local regtest experiments. No public
infrastructure, mainnet, or third-party nodes were touched.

---

## Repository Commit Audited

```
$ git rev-parse HEAD
4fb5a0cd930c0df82c88292e973a7b7cfa06c4e8

$ git branch --show-current
claude/pepecoin-consensus-audit-cs8e6i

$ git status --short           # (before adding audit artifacts)
(clean working tree at audit start; artifacts added by this audit listed below)
```

Client identity: **Pepecoin Core v1.1.0.0** (`configure.ac`:
`_CLIENT_VERSION_MAJOR.MINOR.REVISION = 1.1.0`).

### Artifacts added by this audit

| Path | Purpose |
|------|---------|
| `src/test/pepecoin_consensus_tests.cpp` | Adversarial monetary-invariant unit tests (subsidy/coinbase/fees/duplicate-inputs/maturity/amount-range). |
| `src/test/pepecoin_auxpow_adversarial_tests.cpp` | Adversarial AuxPoW tests (chain index, branch length, version encoding, serialization round-trip). |
| `src/test/pepecoin_timedata_tests.cpp` | Regression test for the network-time clamp (PEP-001). |
| `qa/rpc-tests/pepecoin_timewarp_poc.py` | Network-facing PoC shape for PEP-001 (regtest only). |
| `src/timedata.cpp` | **Fix applied** for PEP-001 (see finding). |
| `src/Makefile.test.include` | Registers the new unit-test files. |

Build: `./autogen.sh && ./configure --with-incompatible-bdb && make` — clean
build, `test_pepecoin` passes **268/268** suites (253 upstream + 15 new
adversarial cases). The single applied source fix (`timedata.cpp`) makes the
new regression test pass and is functionally identical to upstream Dogecoin
1.14.8+.

---

## Executive Summary

Pepecoin Core 1.1.0 is a near-verbatim rename-fork of **Dogecoin Core
1.14.x** (which is itself Bitcoin Core ~0.14/0.15 with scrypt PoW, AuxPoW
merged mining, the legacy `CCoins` UTXO model, and SegWit disabled). The
consensus-critical files differ from upstream almost exclusively by renames
(`dogecoin`→`pepecoin`, `DOGE`→`PEPE`), a handful of Pepecoin chain parameters,
and three deliberately-changed difficulty magic numbers. This makes a
**semantic differential audit against Dogecoin** the highest-signal technique,
and it is the backbone of this report.

**No inflation, coinbase-overpayment, double-spend, or value-conservation
vulnerability was found.** Every monetary invariant traced through to an
enforcing check, and the two fundamental invariants

* per transaction: `sum(outputs) ≤ sum(inputs)`, `fee = in − out ≥ 0`
* per block: `coinbase_out ≤ subsidy(height) + Σ fees`

are enforced on every consensus path examined. These were confirmed both by
source tracing and by adversarial unit tests that attempt to violate them (all
correctly rejected), and by a live regtest UTXO-conservation / reorg
round-trip (supply returns exactly to baseline after invalidate/reconsider).

The audit did find **one confirmed remotely-triggerable defect (MEDIUM)**: the
network-adjusted-time clamp in `timedata.cpp` uses `abs64()`, which is
undefined behavior on `INT64_MIN` and lets hostile peers push the node's time
offset past the `±maxtimeadjustment` clamp it is designed to enforce. This is
the reintroduction of a bug that upstream Dogecoin explicitly fixed in 1.14.8.
A regression test and the upstream-equivalent fix are included.

A small number of lower-severity observations (missing upstream diagnostic
improvements, latent-but-unreachable arithmetic) are documented, along with an
extensive **proof-of-absence** section recording the hypotheses that were
investigated and refuted, with the exact enforcing code for each.

### Findings at a glance

| ID | Severity | Confidence | Status | Title |
|----|----------|-----------|--------|-------|
| PEP-001 | MEDIUM | CONFIRMED | Fixed in this branch | `abs64(INT64_MIN)` UB lets peers bypass the network-time clamp |
| PEP-002 | LOW | CONFIRMED | Open | Upstream difficulty-error “masking” fix (`c4e76a369`) not ported (diagnostic only) |
| PEP-003 | LOW/INFO | CONFIRMED | Open | `MAX_MONEY` is not a supply bound; total emission exceeds `MAX_MONEY` and `INT64_MAX` (handled where it matters) |
| PEP-004 | INFO | CONFIRMED | Open | Dead / stale consensus code and `//PEPE TODO` magic numbers |

---

## Monetary Invariants — how PEPE supply is protected

PEPE is denominated in **koinu** (1 PEPE = `COIN` = 10⁸ koinu). `CAmount` is
`int64_t`. The sanity ceiling is:

```c
// src/amount.h:32
static const CAmount MAX_MONEY = 10000000000 * COIN; // 1e18 koinu
inline bool MoneyRange(const CAmount& nValue) { return (nValue >= 0 && nValue <= MAX_MONEY); }
```

Supply is created only in the coinbase output of each block. The subsidy
schedule (`src/pepecoin.cpp:127`, `GetPepecoinBlockSubsidy`) with
`fSimplifiedRewards = true` (true on **all** reachable params objects, verified
below) is:

```
subsidy(h) = (500000 * COIN) >> (h / 100000)      for h < 6*100000 = 600000
           = 10000 * COIN                          for h >= 600000   (tail emission)
```

i.e. 500,000 PEPE initial reward, halving every 100,000 blocks for six eras,
then a constant 10,000 PEPE tail forever.

### The enforcement chain (money-creation call graph)

```
ProcessNewBlock
  └─ AcceptBlock
       ├─ AcceptBlockHeader
       │    ├─ CheckBlockHeader → CheckAuxPowProofOfWork      (PoW / AuxPoW)   pepecoin.cpp:89
       │    ├─ CheckIndexAgainstCheckpoint                     validation.cpp:3002
       │    └─ ContextualCheckBlockHeader                      validation.cpp:3080
       │         ├─ legacy/auxpow activation gate
       │         ├─ nBits == GetNextWorkRequired               (difficulty)     pow.cpp:30
       │         ├─ timestamp > MedianTimePast, ≤ nAdjustedTime+2h
       │         └─ version/BIP66/BIP65 height gate
       ├─ CheckBlock                                           validation.cpp:2939
       │    ├─ merkle root + CVE-2012-2459 mutation check
       │    ├─ first-tx-is-coinbase / single-coinbase
       │    └─ for each tx: CheckTransaction(tx, state, true)  validation.cpp:527
       │         ├─ vout value < 0            → bad-txns-vout-negative
       │         ├─ vout value > MAX_MONEY    → bad-txns-vout-toolarge
       │         ├─ Σvout MoneyRange          → bad-txns-txouttotal-toolarge
       │         └─ duplicate inputs (set)    → bad-txns-inputs-duplicate   (CVE-2018-17144)
       └─ ContextualCheckBlock                                 validation.cpp:3124
            └─ BIP34 height-in-coinbase, finality, weight
  ...then ConnectTip → ConnectBlock                            validation.cpp:1783
       ├─ CheckBlock (again)
       ├─ BIP30 duplicate-txid guard                           validation.cpp:1881
       ├─ for each non-coinbase tx:
       │    ├─ view.HaveInputs(tx)                             coins.cpp:284
       │    ├─ CheckInputs → Consensus::CheckTxInputs          validation.cpp:1415
       │    │    ├─ coinbase maturity                          → bad-txns-premature-spend-of-coinbase
       │    │    ├─ per-input MoneyRange(nValueIn)             → bad-txns-inputvalues-outofrange
       │    │    ├─ nValueIn < GetValueOut                     → bad-txns-in-belowout
       │    │    ├─ nTxFee < 0                                 → bad-txns-fee-negative
       │    │    └─ MoneyRange(nFees)                          → bad-txns-fee-outofrange
       │    ├─ script verification (P2SH/DERSIG/CLTV/CSV flags)
       │    ├─ nFees += GetValueIn(tx) - GetValueOut(tx)
       │    └─ UpdateCoins → Spend inputs / add outputs        validation.cpp:1366
       └─ blockReward = nFees + GetPepecoinBlockSubsidy(height,...)   validation.cpp:1996
            └─ if coinbase.GetValueOut() > blockReward → bad-cb-amount  ← THE supply cap
```

The **single consensus condition that caps money creation** is
`validation.cpp:1997`:

```c
CAmount blockReward = nFees + GetPepecoinBlockSubsidy(pindex->nHeight, chainparams.GetConsensus(pindex->nHeight), hashPrevBlock);
if (block.vtx[0]->GetValueOut() > blockReward)
    return state.DoS(100, error("ConnectBlock(): coinbase pays too much ..."), REJECT_INVALID, "bad-cb-amount");
```

Because `nFees` is the sum of `(GetValueIn − GetValueOut)` over transactions
each already validated by `CheckTxInputs` to have `in ≥ out` and
`MoneyRange(fee)`, and `subsidy` is bounded and non-negative, the coinbase can
never legitimately claim more than the network created. This condition, plus
`CheckTransaction`’s output-range checks and `CheckTxInputs`’ input/fee-range
checks, is the whole of the supply protection. All three were exercised
adversarially (finding PEP-INV tests) and hold.

---

## Consensus Attack Surface Map

| Subsystem | Files | Pepecoin delta vs Dogecoin 1.14.9 | Verdict |
|-----------|-------|-----------------------------------|---------|
| Amounts / MoneyRange | `amount.h` | rename + copyright only | identical logic |
| Tx checks | `validation.cpp CheckTransaction` | rename only | identical |
| Input/fee checks | `validation.cpp Consensus::CheckTxInputs` | rename only | identical |
| Coinbase/subsidy | `pepecoin.cpp`, `validation.cpp ConnectBlock` | subsidy schedule constants; difficulty magic numbers `157500→1250`, `145000→1000` | see PoW analysis |
| UTXO / coins | `coins.cpp/.h`, `undo.h`, `txdb.cpp`, `compressor.cpp` | **byte-identical** | identical |
| Merkle | `consensus/merkle.cpp` | **byte-identical** | CVE-2012-2459 defense present |
| Script | `script/interpreter.cpp` | **byte-identical** | identical |
| AuxPoW | `auxpow.cpp` | **byte-identical**; `auxpow.h` rename-only | identical (upstream fixes present) |
| PoW / difficulty | `pow.cpp`, `pepecoin.cpp` | difficulty magic numbers only | see PEP-002 analysis |
| Headers / versions | `primitives/pureheader.h`, `block.h` | rename/copyright only | identical |
| Serialization | `serialize.h`, `streams.h` | **byte-identical** | identical |
| Difficulty math | `arith_uint256.cpp` | **byte-identical** | identical |
| Checkpoints | `checkpoints.cpp` | **byte-identical**; call-site reordered | see PEP-002 |
| Versionbits | `versionbits.cpp` | **byte-identical** | identical |
| Compact blocks | `blockencodings.cpp/.h` | **byte-identical** | assert-hardening (b5dec9637) present |
| Chain params | `chainparams.cpp` | heavily Pepecoin-specific | audited; consistent |
| Network time | `timedata.cpp` | **older pre-1.14.8 variant with `abs64`** | **PEP-001** |
| Fees / policy | `pepecoin-fees.cpp`, `policy/policy.*` | rename only | identical logic |

---

## Dogecoin Differential Analysis

**Baseline:** Pepecoin 1.1.0’s consensus tree matches **Dogecoin Core
1.14.7 / 1.14.9** most closely (measured by minimal semantic diff across
`src/`). The following files are **byte-for-byte identical** to Dogecoin
1.14.9 and therefore inherit its consensus behavior exactly:

```
src/auxpow.cpp        src/coins.cpp          src/coins.h
src/undo.h            src/txdb.cpp           src/compressor.cpp
src/consensus/merkle.cpp   src/primitives/pureheader.cpp
src/script/interpreter.cpp  src/versionbits.cpp
src/checkpoints.cpp   src/serialize.h        src/arith_uint256.cpp
src/blockencodings.cpp/.h   src/dbwrapper.cpp
```

The **only** semantic (non-rename) deltas in consensus-critical code are:

1. **Subsidy schedule** (`pepecoin.cpp` `GetPepecoinBlockSubsidy`): Pepecoin’s
   own reward curve. Logic structure identical to Dogecoin’s; only the
   constants differ. Verified safe (see PEP-INV-8).

2. **Difficulty magic numbers** (`pow.cpp`, `pepecoin.cpp`):
   `157500 → 1250` and `145000 → 1000`. Analyzed in PEP-002 / proof-of-absence;
   benign because mainnet `nPowTargetTimespan == nPowTargetSpacing == 60` makes
   the retarget interval 1 regardless.

3. **Checkpoint-check placement** (`validation.cpp`): Pepecoin retains the
   **pre-`c4e76a369`** ordering (checkpoint check in `AcceptBlockHeader` /
   `TestBlockValidity`, not after the `nBits` check in
   `ContextualCheckBlockHeader`). Diagnostic-only; PEP-002.

4. **`timedata.cpp`**: Pepecoin ships the **pre-1.14.8** version using
   `abs64()`. Dogecoin replaced this in commit *“Avoid the use of abs64 in
   timedata”* (1.14.8). This is **PEP-001**.

**Upstream security-relevant fixes checked for presence:**

| Upstream commit | Description | Status in Pepecoin |
|-----------------|-------------|--------------------|
| `b85849d0d` | Check auxpow PoW *before* the auxpow structure | **PRESENT** (`pepecoin.cpp:118` PoW then `:121` structure; and `auxpow.cpp:105` `vin.empty()` guard) |
| `b5dec9637` | cmpctblk asserts → handled failures | **PRESENT** (`blockencodings.cpp` byte-identical to 1.14.9) |
| CVE-2012-2459 | merkle mutation | **PRESENT** (`CheckBlock` `mutated` guard, `validation.cpp:2961`) |
| CVE-2018-17144 | duplicate-input inflation | **NOT APPLICABLE / FIX PRESENT** — `CheckBlock` calls `CheckTransaction(*tx, state, true)` and the header default is `true` (`validation.h:394`); no path validates block txs with the check disabled |
| CVE-2010-5139 | output-sum overflow | **FIX PRESENT** (`CheckTransaction` per-output `MoneyRange` + running-sum `MoneyRange`) |
| *“avoid masking difficulty errors”* `c4e76a369` | 1.14.9 diagnostic | **ABSENT** → PEP-002 (diagnostic only) |
| *“avoid abs64 in timedata”* | 1.14.8 | **ABSENT** → PEP-001 |

---

## Findings

### Finding PEP-001 — `abs64(INT64_MIN)` lets hostile peers bypass the network-time clamp

**Severity:** MEDIUM &nbsp;•&nbsp; **Confidence:** CONFIRMED &nbsp;•&nbsp;
**Status:** Fixed in this branch (upstream-equivalent patch applied)

**File / Function / Lines:** `src/timedata.cpp` — `abs64()` (pre-fix line 41)
and `AddTimeData()` (pre-fix line 85). Reached from
`net_processing.cpp:1546` (`AddTimeData(pfrom->addr, nTimeOffset)`), where
`nTimeOffset = nTime − GetTime()` and `nTime` is the peer-supplied `version`
timestamp read at `net_processing.cpp:1416`.

**Invariant violated:** *No set of peers may move this node’s network-adjusted
time by more than `±maxtimeadjustment` (default 70 minutes).* This clamp is the
sole defense bounding peer influence over `GetAdjustedTime()`.

**Technical explanation.** The clamp was written as:

```c
static int64_t abs64(int64_t n) { return (n >= 0 ? n : -n); }
...
if (abs64(nMedian) <= std::max<int64_t>(0, GetArg("-maxtimeadjustment", DEFAULT_MAX_TIME_ADJUSTMENT)))
    nTimeOffset = nMedian;
```

`abs64(INT64_MIN)` computes `-INT64_MIN`, which overflows a signed 64-bit
integer — **undefined behavior**. In practice it evaluates back to `INT64_MIN`
(a *negative* number), so the guard `abs64(nMedian) <= max_adjustment` is
satisfied (negative ≤ positive) and the node accepts
`nTimeOffset = INT64_MIN`, wildly outside the intended `±70min` bound.

**Attacker-controlled input.** A peer’s `version` message carries an
attacker-chosen `int64_t nTime`. Setting `nTime` such that the derived offset
is `INT64_MIN` (or near it) makes that peer contribute an `INT64_MIN` sample.
`AddTimeData` de-duplicates samples **by source IP** (`static std::set<CNetAddr>
setKnown`), so an attacker needs enough *distinct-IP* inbound peers to own the
**median** of the offset filter (which seeds with one `0` sample and updates
when the sample count is odd and ≥ 5). A handful-to-dozens of distinct inbound
addresses — a routine Sybil posture — suffices to place `INT64_MIN` at the
median early, before honest samples accumulate.

**Consensus path / impact.** `GetAdjustedTime() = GetTime() + nTimeOffset`.
Driving `nTimeOffset` to `INT64_MIN` makes `GetAdjustedTime()` a garbage
(extremely negative / wrapped) value. That value is used in
`ContextualCheckBlockHeader` (`validation.cpp:3110`):

```c
if (block.GetBlockTime() > nAdjustedTime + 2 * 60 * 60)
    return state.Invalid(..., "time-too-new", ...);
```

With `nAdjustedTime` hugely negative, **every** newly received block’s
timestamp exceeds `nAdjustedTime + 2h`, so the node rejects all new blocks as
`time-too-new` and stops following the chain — a remotely-triggerable
availability / consensus-isolation DoS, and a useful primitive for eclipse
attacks. `GetAdjustedTime()` also feeds the miner’s block `nTime`.

**Why existing validation doesn’t stop it.** The clamp *is* the validation; the
`abs64` UB is precisely what defeats it. The median-filter quirk (issue #4521,
the filter stops updating past 200 samples) offers only partial, incidental
protection and does not prevent early poisoning.

**Local reproduction (deterministic).** `src/test/pepecoin_timedata_tests.cpp`
feeds four distinct addresses an `INT64_MIN` offset:

```
maxtimeadjustment = 4200
resulting nTimeOffset = -9223372036854775808          ← escaped the ±4200 clamp
GetAdjustedTime() = -9223372035068340509              ← garbage adjusted time
```

The network-facing shape is documented in
`qa/rpc-tests/pepecoin_timewarp_poc.py` (regtest only; note the loopback
`setKnown`-by-IP dedup means the *deterministic* confirmation is the unit test).

**Observed result:** the clamp is bypassed exactly as predicted; after the fix
(below) the same test yields `nTimeOffset = 0` and a sane `GetAdjustedTime()`.

**Recommended patch (applied).** Remove `abs64` and compare against the signed
bounds directly, matching upstream Dogecoin 1.14.8+:

```c
int64_t max_adjustment = std::max<int64_t>(0, GetArg("-maxtimeadjustment", DEFAULT_MAX_TIME_ADJUSTMENT));
if (nMedian >= -max_adjustment && nMedian <= max_adjustment) {
    nTimeOffset = nMedian;
}
```

(The two other `abs64` uses in the warning path were likewise replaced with the
signed-range form; `abs64` and the `boost/foreach.hpp` include were removed.
Post-fix `timedata.cpp` is functionally identical to Dogecoin 1.14.9.)

**Regression test:** `src/test/pepecoin_timedata_tests.cpp`
(`time_offset_must_stay_clamped`) — fails on the vulnerable code, passes after
the fix.

**Upstream Dogecoin comparison:** Dogecoin removed `abs64` from `timedata.cpp`
in the 1.14.8 cycle (*“Avoid the use of abs64 in timedata”* / commit
`0cc85e45f`). Pepecoin forked the pre-1.14.8 file and did not carry the fix.

---

### Finding PEP-002 — Upstream difficulty-error “masking” fix not ported (diagnostic-only)

**Severity:** LOW &nbsp;•&nbsp; **Confidence:** CONFIRMED &nbsp;•&nbsp;
**Status:** Open (no security impact; recommend porting for parity)

**File / Function / Lines:** `src/validation.cpp` —
`ContextualCheckBlockHeader` (~3100) and `AcceptBlockHeader` (~3240),
`TestBlockValidity` (~3418).

**Explanation.** Upstream Dogecoin commit `c4e76a369` (*“validation: avoid
masking of difficulty adjustment errors”*, cherry-picked from Bitcoin
`215fc33d`) moved the pre-checkpoint fork rejection to run **after** the
`nBits` difficulty check inside `ContextualCheckBlockHeader`, so that difficulty
violations on chains branching before the last checkpoint are still reported as
`bad-diffbits` rather than masked by `bad-fork-prior-to-checkpoint`. Pepecoin
retains the **older ordering** (`CheckIndexAgainstCheckpoint` invoked from
`AcceptBlockHeader`/`TestBlockValidity`, before the difficulty check).

**Why this is only LOW.** In **both** orderings the offending block is
**rejected** — no invalid block is accepted, and no consensus split results.
The only observable difference is *which* rejection reason is reported for
pre-checkpoint forks (and the `REJECT_CHECKPOINT` reject code is not surfaced).
This is a diagnostics/parity issue, not an exploitable weakness.

**Recommended patch:** port `c4e76a369` verbatim (move the checkpoint block into
`ContextualCheckBlockHeader` after the `nBits` check and drop the calls in
`AcceptBlockHeader`/`TestBlockValidity`).

---

### Finding PEP-003 — `MAX_MONEY` is a per-value sanity cap, not a supply bound

**Severity:** LOW / INFO &nbsp;•&nbsp; **Confidence:** CONFIRMED &nbsp;•&nbsp;
**Status:** Open (informational; the one place it matters is already handled)

**File / Lines:** `src/amount.h:32` (`MAX_MONEY = 1e18 koinu = 10,000,000,000
PEPE`); emission schedule `src/pepecoin.cpp:127`.

**Explanation.** Pepecoin’s emission is unbounded (500,000-PEPE initial reward,
six halvings, then a **perpetual 10,000-PEPE tail**). The cumulative supply
therefore:

* crosses `MAX_MONEY` (10 billion PEPE) at **height ≈ 20,001** (~14 days at
  1-minute blocks), and
* crosses **`INT64_MAX` koinu** (9.223e18) at **height ≈ 375,740**
  (~261 days).

So `MAX_MONEY` is roughly **10× smaller than the circulating supply** and does
**not** function as a total-supply ceiling — it is only a per-output /
per-transaction / per-fee sanity bound, which is correct and consistent with
Dogecoin’s design (Dogecoin has the same `MAX_MONEY`). This is safe for
consensus because **no consensus code sums the whole supply into a `CAmount`**;
individual amounts and per-block rewards remain far below `MAX_MONEY`.

**Where it could have bitten (and doesn’t):** `gettxoutsetinfo` /
`GetUTXOStats` sums the entire UTXO set. Pepecoin (via Dogecoin) already
accumulates this into an **`arith_uint256`**, not a `CAmount`
(`rpc/blockchain.cpp:916,947`), and formats it through a dedicated
`ValueFromAmount(const arith_uint256&)` overload
(`rpc/server.cpp:146`). So the RPC does **not** overflow. **Proof of absence
confirmed.**

**Latent (non-exploitable) note.** The block-fee accumulator in `ConnectBlock`
(`nFees += ...`, `validation.cpp:1974`) is an `int64_t` with no per-iteration
`MoneyRange` guard (identical to Bitcoin/Dogecoin). Overflowing it would
require a single block whose fees sum past `INT64_MAX` (≈ 92 billion PEPE of
fees in one block) — not reachable in practice, and even if it were, a positive
overflow *reduces* the computed `blockReward`, making the `bad-cb-amount` check
**stricter**, not weaker (no inflation). Documented for completeness in the
`block_fee_accumulator_headroom` unit test. Recommend adding a
`MoneyRange(nFees)` guard in `ConnectBlock` as defense-in-depth given the
unbounded supply.

---

### Finding PEP-004 — Stale consensus scaffolding and undocumented magic numbers

**Severity:** INFO &nbsp;•&nbsp; **Confidence:** CONFIRMED &nbsp;•&nbsp;
**Status:** Open (hygiene)

* `IsSuperMajority` (`validation.cpp:3373`) is **defined but never called** —
  BIP66/BIP65 are enforced purely by height (`validation.cpp:3116`). Dead code.
* Numerous `//PEPE TODO Magic number` markers remain around consensus heights
  (`pow.cpp:46`, `validation.cpp` maturity comment, `auxpow_tests.cpp:184`
  `GetConsensus(371337)`), and `chainparams.cpp:84` still has
  `BIP34Hash = uint256S("0x00")` with a “Replace … after mainnet launches”
  TODO. `BIP34Hash = 0x00` currently keeps BIP30 enforced for **all** blocks
  (safe); if a real hash is ever set, verify the BIP30-skip interacts correctly
  with the height-based BIP34 coinbase-height rule (it does, but the TODO
  should be closed deliberately).
* The legacy hash-derived subsidy branch in `GetPepecoinBlockSubsidy`
  (`!fSimplifiedRewards`, using `strtol` on the previous block hash +
  `generateMTRandom`) is **dead on all three networks** (proof of absence
  below) but remains compiled in. Recommend removing to shrink the
  consensus surface.

---

## Proof of Absence — hypotheses investigated and refuted

For each promising attack idea that **failed**, the exact enforcing code is
recorded. These are as important as the positive findings.

| # | Hypothesis | Why it fails | Enforcing code |
|---|-----------|--------------|----------------|
| 1 | Coinbase overpays subsidy (`subsidy+1`, `2×`, `MAX_MONEY`, `MAX_MONEY+1`, split outputs) | Rejected `bad-cb-amount` / `bad-txns-vout-*`; confirmed by test `coinbase_may_not_overpay_subsidy` (all rejected, exact-subsidy accepted) | `validation.cpp:1997`, `CheckTransaction` 542-548 |
| 2 | Coinbase claims fees never paid, or `subsidy+fee+1` | Rejected; `nFees` counts only real `in−out`; test `coinbase_may_not_overpay_fees` | `validation.cpp:1974,1996` |
| 3 | Duplicate-input inflation (CVE-2018-17144) | `CheckTransaction(...,true)` in `CheckBlock`; default arg is `true`; test `duplicate_inputs_rejected_in_block` | `validation.cpp:551-558,2984`, `validation.h:394` |
| 4 | Input-sum overflow past `MAX_MONEY` | Per-input + running `MoneyRange`; test `checktxinputs_amount_ranges` | `validation.cpp:1441-1443` |
| 5 | Outputs > inputs / negative fee | `nValueIn < GetValueOut` and `nTxFee < 0` rejected; test asserts `bad-txns-in-belowout` | `validation.cpp:1447-1454` |
| 6 | Negative / >MAX_MONEY outputs | `bad-txns-vout-negative` / `-toolarge`; `GetValueOut` throws, but `CheckTransaction` runs first everywhere | `transaction.cpp:83-93`, `validation.cpp:542-548` |
| 7 | Immature coinbase spend, incl. across the 30→240 maturity change | Maturity keyed on spent coin’s height; test `coinbase_maturity_enforced` (regtest maturity 60 confirmed) | `validation.cpp:1431-1437` |
| 8 | `subsidy >> halvings` shift UB (`halvings ≥ 64`), negative/huge height | `h < 6*interval` guard caps `halvings ≤ 5`; boundaries tested `subsidy_schedule_boundaries` | `pepecoin.cpp:142-147` |
| 9 | Legacy random-subsidy branch becomes live | `fSimplifiedRewards == true` on every reachable params object/height on main/test/regtest; test asserts it across the full tree | `chainparams.cpp:123,128,249,256,371`; test `subsidy_schedule_boundaries` |
| 10 | `GetConsensus(negative int → uint32)` returns wrong params | Tree walk saturates to the auxpow branch for huge heights; height-0 flags (`BIP66/65/30/34`) identical across all tree nodes (all are copies); tested `consensus_param_tree_boundaries` | `chainparams.cpp:444-456` |
| 11 | BIP30 duplicate-txid can be disabled | `fEnforceBIP30 = true`, ANDed with `BIP34Hash == 0x00` test which never matches a real hash; regtest `BIP34Height=1e8` unreachable → BIP30 always on | `validation.cpp:1869-1888` |
| 12 | AuxPoW negative / out-of-range chain index | `nChainIndex != getExpectedIndex(...)` mismatch; `nIndex != 0` guard; test `auxpow_adversarial_chain_index` (INT_MIN/-1/alias all rejected) | `auxpow.cpp:84,157` |
| 13 | AuxPoW chain-branch length overflow (`1<<h`) | `vChainMerkleBranch.size() > 30` rejected before any shift; test `auxpow_adversarial_branch_length` (h=30 ok, 31/32/33/64 rejected) | `auxpow.cpp:90` |
| 14 | AuxPoW version encoding smuggles a non-auxpow/non-legacy block past the chain-ID or BIP66/65 gate | Strict chain-ID rule requires our chain id for non-legacy; `GetBaseVersion() = ver % 256` never ≥4 for low-byte <4; legacy∧auxpow impossible; test `auxpow_adversarial_version_encoding` (incl. negative nVersion) | `pepecoin.cpp:95`, `pureheader.h:88-155` |
| 15 | AuxPoW flag/payload mismatch or auxpow affecting block hash | `no auxpow on block with auxpow version` / vice-versa; block hash uses pure header only; test `auxpow_flag_and_payload_must_agree` + serialization round-trip | `pepecoin.cpp:102-116`, `block.h:36-47` |
| 16 | Truncated/oversized AuxPoW header deserialization | Round-trips exactly; every truncation throws; test `auxpow_header_serialization_roundtrip` | `block.h SerializationOp`, `validation.cpp:1181` |
| 17 | AuxPoW parent-PoW checked after untrusted structure (b85849d0d) | Pepecoin checks PoW **then** structure; `vin.empty()` guard present | `pepecoin.cpp:118-121`, `auxpow.cpp:105` |
| 18 | Difficulty magic-number cliff at height 1000 / 1250 | Mainnet `timespan==spacing==60` ⇒ retarget interval 1 in both branches, so `145000→1000` / `157500→1250` cause no behavioral cliff; regtest clamps to `powLimit` floor | `pow.cpp:48-51`, `pepecoin.cpp:41-87` |
| 19 | Negative `nActualTimespan` corrupts `arith_uint256 *= int64` | Min/max clamps make `nModulatedTimespan` positive before multiply on every network | `pepecoin.cpp:55-81` |
| 20 | Non-canonical `nBits` inflates work / passes PoW | `nBits != GetNextWorkRequired` equality rejects; `CheckProofOfWork` rejects negative/overflow/zero/`>powLimit`; `arith_uint256` byte-identical | `validation.cpp:3102`, `pow.cpp:113-130` |
| 21 | CVE-2012-2459 merkle mutation marks block permanently invalid | `mutated` flag → `bad-txns-duplicate` (not `BLOCK_FAILED`) | `validation.cpp:2952-2962` |
| 22 | `gettxoutsetinfo` supply overflow | Accumulated in `arith_uint256`, formatted via dedicated overload | `rpc/blockchain.cpp:916,947`, `rpc/server.cpp:146` |
| 23 | Compact-block peer data reaches an `assert` (b5dec9637) | Handled-failure returns present; only `assert(index<...)` is internally bounds-guarded; `blockencodings.cpp` byte-identical to 1.14.9 | `blockencodings.cpp` |
| 24 | Reorg breaks value conservation | Live regtest: connect→invalidate→reconsider returns UTXO hash + total exactly to baseline | see live experiment below |

### Live regtest UTXO-conservation experiment

```
h1000 baseline : total_amount 148166250.0  hash_serialized ab6f52...
+10 blocks     : 148266250.0
spend + 5 blks : 148316250.0  hash_serialized 0ae68e...
invalidate 1001: 148166250.0  hash_serialized ab6f52...   ← exact baseline
reconsider     : 148316250.0  hash_serialized 0ae68e...   ← exact restoration
```

Supply and the full serialized UTXO set return **bit-for-bit** to the correct
state across a disconnect/reconnect cycle — no coins created, destroyed, or
resurrected. Regtest supply at height 1000 (148,166,250 PEPE) matches the
subsidy schedule exactly.

---

## Testing performed

* **Unit tests:** full `test_pepecoin` suite passes **268/268** (253 upstream +
  15 new adversarial cases across monetary invariants, AuxPoW, and network
  time).
* **Functional tests (regtest):** `auxpow.py`, `getauxblock.py`,
  `createauxblock.py`, `p2p-fullblocktest.py`, `invalidblockrequest.py`,
  `invalidtxrequest.py`, `reindex.py`, `invalidateblock.py`, `mempool_reorg.py`,
  `txn_doublespend.py`, `txn_clone.py`, `rawtransactions.py`,
  `getchaintips.py`, `mempool_spendcoinbase.py` **pass**. (`bipdersig.py` /
  `bip65-cltv.py` “fail” identically on upstream Dogecoin — they exercise the
  old *supermajority* activation that Dogecoin/Pepecoin replaced with
  *height-based* activation; the height rule itself is verified by the passing
  C++ `bip65`/DER unit tests and by source. Not a consensus regression.)
* **Live regtest:** 1,000-block chain, subsidy-schedule verification, and the
  reorg round-trip above.

---

## Recommendations (priority order)

1. **Apply PEP-001** (done in this branch): drop `abs64` in `timedata.cpp`.
   This is the only change with real security value found.
2. Port `c4e76a369` (PEP-002) for upstream parity / better error reporting.
3. Add a `MoneyRange(nFees)` guard in `ConnectBlock` as defense-in-depth given
   the unbounded tail emission (PEP-003).
4. Remove dead consensus scaffolding: the legacy hash-derived subsidy branch
   and `IsSuperMajority`; resolve the `BIP34Hash = 0x00` TODO deliberately
   (PEP-004).
5. Keep tracking the Dogecoin `1.14-maint` branch for future consensus fixes;
   the fork is close enough that cherry-picks apply cleanly.

---

## Appendix — reproduction

```bash
./autogen.sh
./configure --with-incompatible-bdb --disable-bench --without-gui
make -j"$(nproc)"

# Adversarial consensus + AuxPoW + timedata regression tests
./src/test/test_pepecoin --run_test=pepecoin_consensus_tests
./src/test/test_pepecoin --run_test=pepecoin_auxpow_adversarial_tests
./src/test/test_pepecoin --run_test=pepecoin_timedata_tests   # passes post-fix

# Full suite
./src/test/test_pepecoin
```
