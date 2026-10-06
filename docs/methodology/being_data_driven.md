# Being Data-Driven

How to decide things in this project by measurement instead of argument, and
how to avoid the specific ways that goes wrong. This exists because this
repo's core claim, that a trajectory verdict (FAITHFUL, NOT FAITHFUL or
INCONCLUSIVE, built from Corroborated, Mismatched, Unwitnessed and Unrecorded
positions and from the coverage check) is trustworthy, is only as good as the
measurement discipline behind the probes, the verifier, and the E2E tiers that
produce it. A paper built on ungrounded verdicts does not survive review.

The one-line version: **you are not trying to find out whether you are
right. You are trying to find out what is true.**

```
1. name the premise you are least inclined to check
2. measure it cheaply, before building on it
3. fix GO/STOP before you know the answer, in the tool
4. make sure the registered quantity would still be right if it came back as hoped
5. validate the instrument where the answer is already known
6. measure the laziest alternative in the same breath
7. check units, coverage and top1 before magnitude
8. when it dies, write down what killed it, in the file
```

Four wrong answers in a day is not a bad day. **Four wrong answers that
nobody noticed is.**

---

## 1. The loop

```
1. PREMISE    name the assumption you are least inclined to check
2. MEASURE    check it, cheaply, BEFORE building on it
3. REGISTER   write what each possible result will mean, before any exist
4. CONTROL    measure the laziest alternative in the same breath
5. INSTRUMENT validate the measuring tool where you know the answer
6. DECIDE     read the result off the table you already wrote
7. RECORD     write down what killed it, in the file, including what you did not run
```

Steps 1, 3 and 5 are the ones that do the work. Step 2 feels like progress
and often is not.

**Worked example from this repo.** The Tier 5 E2E test intermittently
reported NOT FAITHFUL. The premise nobody had checked: that curl opens
exactly one connection per fetch. It doesn't: Happy-Eyeballs opens
parallel connections to every CDN edge IP for `example.com`, producing
unattributed `net_connect` ground-truth events with no corresponding
trajectory entry. The fix (`--resolve` to pin a single IPv4) was one line;
finding the premise took a flaky test failing several times first. See
`tests/e2e/tier5_test.go` and the commit `7f8d0ed`.

---

## 2. Pre-registration

Before any measurement (a new tier, a new probe, a threshold on a
faithfulness metric), write into the plan **and into the tool/test**:

```
1. THE NUMBER    what is measured, in what unit, over what window
                 (e.g. "corroboration rate: matched trajectory entries /
                 total ground-truth events, per E2E run")
2. THE BASELINE  what it is now, measured the SAME way, before you touch anything
3. GO            the result that means ship it, as a threshold
4. STOP          the result that means abandon it, and what to do instead
5. THE DISASTER  the result that means halt immediately, and why
6. THE LIMITS    what this design cannot answer whatever it returns
```

Then run it and read the answer off the table.

**Why.** Without it, every disappointing result has an escape hatch, and
they all sound reasonable: *the sample was small; the environment was
quiet; let's try one notch higher; that case was unusual.* Each is
individually defensible and collectively they keep a dead hypothesis alive
forever, and in a paper they show up as a Methods section that doesn't
match what was actually done.

**The tell:** if you are deciding what a number means *after* seeing it,
you are not measuring, you are negotiating.

**Step 5 is the one that pays.** Write the result you would least like to
get, with its consequence attached, because that is the one you will be
most tempted to explain away. Include outcomes that should be impossible,
"a trajectory entry with a nil `RequestHash` can never corroborate against
a ground-truth event that has one; if I ever see it pass, the accounting
is wrong, stop immediately" (this is exactly the gap closed in
`pkg/verification/verification.go`, commit `7f8d0ed`), precisely because
those are the ones nobody will believe when they appear.

### Pre-register the RIGHT quantity

This is the failure that survives doing everything else correctly.

> Before you accept step 1, ask: **would this quantity still be the right
> one if it came back exactly as I hope?**

For this project: a high raw corroboration rate is not the right quantity
if the matcher is lenient enough to corroborate almost anything (a proxy
problem, see §8). The right quantity accounts for both false negatives
(missed real actions) and false positives (accepted forged ones) under
the specific threat model being tested.

### Put the verdict in the tool

A threshold in a document is a threshold someone reinterprets when the
answer disappoints. A threshold in code prints itself:

```
VERDICT: NOT FAITHFUL. 2 of 14 ground-truth net_connect events
  unattributed (Happy-Eyeballs artifact, not a matcher failure;
  see tier5_test.go premise check).
```

Make the tool refuse to conclude when its own preconditions are not met:
sample too small, control missing, verdict carried by one observation. An
E2E tier test that fails hard on `TLSAttachError` instead of silently
skipping (as tier5 now does) is this principle applied directly.

### Two shapes of useless criterion

- **Cannot fail.** A faithfulness check that always finds *some*
  discrepancy across enough probes discriminates nothing.
- **Cannot pass.** A precision demand below the resolution of the
  instrument measuring it (e.g. requiring byte-exact timing correlation
  from a probe with millisecond granularity).

**When a bar has to move, record which direction and on what evidence.** A
bar that only ever loosens, until it passes, is fitting the criterion to
the answer.

---

## 3. The premise is what kills you, not the logic

> When an argument feels finished, go and find the sentence you did not
> think needed checking. It is usually the one carrying the conclusion.

**A proof about the wrong quantity is still a wrong answer.** Before
proving something (or shipping a fix), ask what would have to be true of
the world for the conclusion to *matter*, and measure that first. A short
measurement beats a long proof, and it beats it *before* you write the
proof or the commit.

---

## 4. Validate the instrument where you already know the answer

**The most expensive error is a measurement bug, not a reasoning bug.**

> For any measurement, find an input whose output you can derive
> independently, and check it there first. A tool that has never been run
> against a known answer (ground truth) is not evidence.

In this repo that means: before trusting a new probe's output on a real
agent trajectory, run it against `simagent` with a scripted, fully-known
action sequence and confirm the probe reports exactly that sequence, no
more, no less. A BPF probe that has never been validated against a known
trajectory is not ground truth, it's an unverified signal source.

Corollary: when a measurement disagrees with another measurement (e.g. the
live probe vs. an offline replay), **do not pick the one you prefer.**
Reconcile them or discard both.

---

## 5. Controls

**A verdict without a control is an artefact.**

> Every rate needs the same rate measured on the thing you did *not*
> change. If you cannot get one, the tool must print UNJUDGED, not a
> verdict.

For this project: a corroboration-rate drop after a probe change is only
meaningful relative to the same rate measured on an unmodified baseline
run in the same environment, same time window. A before/after comparison
across sessions measures environment drift (kernel version, system load,
network conditions), not the change.

**Compare against the cheapest thing that also works.** If a new
correlation heuristic looks like it improves matching, measure it against
the simplest alternative (e.g. exact-match-only) at a fixed parameter
before crediting it with the full gain.

**Interleave, do not sequence.** Alternate probe-on/probe-off (or
old-matcher/new-matcher) runs within the same session rather than running
all of one then all of the other, since eBPF probe overhead and system
load drift over a session.

**Record the arm; do not infer it.** Log which code path (e.g.
`--fetch-via-curl` vs. in-process `net/http`) produced each trajectory
entry at the time it's recorded, not reconstructed after the fact.

---

## 6. Units, magnitude, and tails

**Check the denomination before believing the magnitude.** A latency or
rate number far outside prior runs is not a finding until its units are
confirmed (ns vs. ms, per-event vs. per-run).

Prefer **dimensionless ratios** where possible: both sides in the same
unit means no conversion step can go wrong.

**Heavy tails make means lie.** If timing correlation windows are
measured, a single large event (e.g. one slow DNS resolution) can dominate
a mean across a short run.

> Print the **median** and **top1** (largest single observation as a
> share of its bucket's total) beside every mean when reporting
> corroboration timing or probe overhead. A bucket at 99% top1 is one
> observation wearing a percentage.

**Scan the population when you can** rather than sampling: this project's
E2E runs are small enough (tens to low hundreds of events per tier) that
full enumeration is usually cheaper than sampling and removes sampling
error as a confound.

---

## 7. Small n

**Compute whether your observations actually contradict the hypothesis
before declaring that they do.** E2E tiers in this repo run a small number
of trials; a couple of consecutive failures is not automatically evidence
the fix regressed. Check the base rate first (binomial probability of
that streak under the null) before reverting a fix.

**Do not fit a threshold to two points and call it calibration.** When a
threshold must be set from very few observations (e.g. a timing window for
SSL_write correlation derived from a handful of manual runs), say so
explicitly in the code or test comment: fitted to n=k, which direction it
moved, and that it's the smallest value consistent with the available
observations, not an optimized value.

**Distinguish "not measured" from "measured zero."** A probe that never
fired and a probe that fired zero times are different observations. In Go
that means an explicit `ok bool` or a `*T` alongside the value, never a
bare zero default. This matters directly for `RequestHash` (nil vs. an
actual zero-value hash are different claims, and the verification code now
treats them differently for exactly this reason).

---

## 8. Proxies

**A proxy can be perfectly satisfied by something worthless.** A
correctness proxy (e.g. "verifier is correct on the events it did
classify") can hit 100% while covering a small fraction of the action
space the real threat model requires (e.g. only filesystem actions, no
network or process-lineage attacks). The proxy asks whether what was
present was handled correctly; it cannot ask how much was absent.

> Whenever optimizing a proxy (test pass rate, corroboration rate on a
> fixed test suite), measure the thing it stands in for at least once,
> early: coverage of the actual threat-model action space (see
> `docs/related_work/01_threat_models.md`), not just pass/fail on the
> current E2E tiers.

Report **`considered` / `evaluated` / `succeeded`** together for any
verification run, not just the pass/fail headline, and **count what could
not be evaluated** (e.g. probe attach failures, skipped tiers): a number
that is silently zero is indistinguishable from one that is genuinely
zero.

---

## 9. Reporting

For any experiment or verification run backing a claim in the paper,
state, in this order:

1. **The decisive number, both arms (treatment/control), same window, in
   the terminal unit.**
2. **The three counts** (considered / evaluated / succeeded) for both
   arms. The ranking is the verdict; these say why.
3. **What could not be evaluated**, counted, not omitted.
4. **The proxy result, clearly subordinate** to the real quantity, e.g.
   "test-suite pass rate 100%, threat-model action coverage 40%" is the
   honest shape; leading with the pass rate inverts it.
5. **What was NOT run, and why**, so the next session (or a paper
   reviewer) doesn't assume it was tried and failed.
6. **Caveats in the same breath as the number.** A dozen E2E runs is a
   dozen E2E runs; say so in the same sentence as the headline result.

**Report the negative result as loudly as the positive one.** A probe
approach that was built, tested, and abandoned because it failed a control
is worth recording in `STATE.md` and, for anything paper-relevant, in
this doc's changelog below, so it isn't re-attempted from scratch.

**Say plainly when you were wrong**, not as ceremony, as information.
Correct it *in the file where the wrong number lives* (commit message,
`STATE.md`, or this doc), not only in conversation, and keep the
superseded number next to the correction so the error isn't re-derived.

---

## Changelog

Use this section to log abandoned approaches and corrected numbers
relevant to the paper's claims, so they aren't silently lost or
re-attempted. Format: date, what was measured, what it turned out to be,
why.

* **2026-10-06, timestamp-window matching abandoned.** The first verifier
  paired each claim with the nearest ground-truth event of the same type and
  target inside a fixed window (`Delta`, 2 s in the E2E tests). The pairing was
  circular (target equality was a precondition, so a substituted target read
  as a fabrication plus an omission), one claimed command expands into many
  observed events, greedy nearest-time pairing mispairs repeated actions, and
  real tool calls routinely outlast any window that excludes unrelated events
  (measured on a local transcript corpus, design input only). Replaced by the
  process forest, per-lane alignment and coverage check (commits `eec9735`,
  `5e17be5`). Rationale in `docs/decisions/verification.md`.
