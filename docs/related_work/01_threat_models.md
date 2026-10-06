## 1. Scope and threat-model taxonomy

This document surveys existing systems that produce, protect, or analyze AI agent trajectories.
A trajectory is a timestamped sequence of entries recording the actions an agent performed during a task.
The survey covers tools (deployed code), protocols (formal or semi-formal specifications), and papers (published or preprint analyses).

To organize the landscape, we label each system by the threat model it addresses.
Four threat models recur across the literature:

| Label | Threat model | Description |
|:------|:-------------|:---------------------|
| `TM-A` | Operator does not trust their own agent | The operator controls the host infrastructure. The agent (or its runtime) may be compromised. The operator wants to detect trajectory manipulation|
| `TM-B` | Delegator does not trust an external agent service | The delegator sent a task to an agent-as-a-service. The delegator receives a trajectory and wants to verify it without host access. |
| `TM-C` | Auditor requires proof of agent behavior | A regulator or compliance auditor needs verifiable evidence. The operator may have incentive to falsify the trajectory. |
| `TM-D` | Target system faces an external agent | An external agent interacts with your system. You want to reconstruct its behavior from your side. |

These labels are descriptive, not evaluative.
They are derived from reading each system's stated adversary model.
A system may address more than one.

---
