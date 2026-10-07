# Evaluation decisions

Why the attack generators and their scoring are what they are. Entries use the prefix E-. The as-built description is [../architecture/50_attack_generators.md](../architecture/50_attack_generators.md).

### E-1: Generators mutate claims, return a record, and are seeded
Status: Accepted, implemented (`pkg/attack`).
Date: 2026-10-07.
Context: An evaluation has to check that a finding lands on the entry that was mutated, as the right kind of finding. That needs the mutation written down, and a result that anyone can reproduce.
Decision: Each generator takes a normalized trajectory and options, returns the mutated trajectory and a record (kind, seed, and per mutation the positions, the field, old and new values and copies of the entry before and after), and draws all its randomness from a caller-supplied seed. The input is never modified. Asking for more than the trajectory admits is an error.
Consequences: Any result can be regenerated from a trajectory, options and a seed. The generators apply to any agent with an adapter. They cannot mutate the ground truth, which is a different threat model.
Alternatives rejected: Mutating the session file in the agent's own format (each agent would need its own writer); returning only the mutated trajectory (localization could not be checked).

### E-2: An omission does not re-time the remaining claims by default
Status: Accepted, implemented (`Options.Retime`, `TestRetimedOmissionIsStillFoundAndTripsTheIntervalCheck`).
Date: 2026-10-07.
Context: The evaluation plan said A1 re-times the remaining claims consistently, so the omission leaves no hole in the timeline. The verifier's clock is real (V6), and a claim's interval is checked against the observed action (V-12). Moving a claim off its real time puts the observed action outside the interval the claim states.
Decision: By default `Omit` leaves timestamps as they were. `Retime` closes the hole and is tested separately. On both captures a retimed omission was still found, classified and located in every run, and about a third of runs also reported later claims as outside their interval.
Consequences: The default measures the attacker who does not touch the clock, which is the stronger attacker against this verifier, and `Retime` measures the one who hides the hole and pays for it. Both are reported.
Alternatives rejected: Retiming by default as planned (it would have made the omission look easier to catch than it is against a careful attacker).

### E-3: A result is detected, classified and located, with unaccounted findings and distinct cases
Status: Accepted, implemented (`Score`, `Tally`).
Date: 2026-10-07.
Context: The pre-Tier 6 engine detected a substitution while reporting it as a fabrication plus an omission, so a detection rate alone would have scored a broken classifier at 100%.
Decision: Score each mutation on three separate questions: is any finding about it, is the finding of the attack's kind, does it name that entry. Count findings no mutation explains, treating the two reports of one omitted command as one. Report the number of distinct mutations next to every rate, because seeds repeat mutations when a trajectory admits few.
Consequences: A rate over a hundred seeds of single omissions of a seven-claim trajectory is reported as a rate over seven cases. A mutation that is detected but misnamed shows up as such.
Alternatives rejected: One boolean per run (hides misclassification); counting seeds as samples (overstates how much was tested).

### E-4: A4 is scored as suppressing nothing, alone and composed with an omission
Status: Accepted, implemented (`SuppressedNothing`, `TestIntervalWideningSuppressesNothing`, `TestOmissionIsStillFoundWhenItsNeighboursAreWidened`).
Date: 2026-10-07.
Context: Attribution is by ancestry (V1), so a widened interval explains no event that was not already explained. Widening a claim of an honest run changes no verdict. Its relevance is to an attacker who widens the neighbours of a claim they omitted, hoping the omitted action falls inside a stated interval.
Decision: A4 is checked in two ways: widening an honest trajectory leaves the verdict unchanged and raises no interval finding, and omitting a claim then widening both its neighbours over the omitted moment still leaves the omission found, for every position in both captures.
Consequences: The check shows no event is hidden by widening. It does not show the interval check cannot be evaded: an attacker who widens a claim so an out-of-interval action falls inside it evades a finding, and catching that needs an observed interval in the ground truth (O-5).
Alternatives rejected: Counting widening as detected only when an interval finding appears (an honest widening raises none, so a correct verifier would score as failing).
