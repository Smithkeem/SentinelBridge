# SentinelBridge: AI-Guided Cross-Chain Security Protocol

## Overview

I have engineered **SentinelBridge** to serve as the definitive security layer for the Stacks ecosystem's cross-chain operations. As blockchain interoperability becomes a primary target for sophisticated exploits, the industry requires more than static limits—it requires an adaptive, intelligent guardian.

SentinelBridge integrates off-chain **Artificial Intelligence** with on-chain **Clarity Smart Contracts** to provide a real-time risk mitigation engine. By analyzing threat vectors such as flash loans, liquidity siphoning, and MEV bot anomalies, I have created a system that can autonomously "downshift" its operational capacity or trigger a total "circuit break" during high-volatility events.

---

## System Architecture

The protocol operates on a three-tier defense model:

1. **The Surveillance Layer:** AI Agents monitor mempools and chain state to submit granular risk reports.
2. **The Governance Layer:** A multi-sig of Guardians and a Contract Owner provide human-in-the-loop oversight for emergency overrides.
3. **The Enforcement Layer:** The Smart Contract itself, which executes dynamic logic to block addresses, adjust volume caps, and manage transfer lifecycles.

---

## Detailed Private Function Specification

I have encapsulated the internal logic of the contract within private functions to ensure strict state transitions and modularity. These functions are the "unseen" engine room of the protocol.

### `is-ai-agent`

Checks if the `tx-sender` matches the `authorized-ai-agent` variable. This is critical for ensuring that only my validated AI models can submit risk scores or incident reports.

### `is-guardian (user principal)`

Queries the `authorized-guardians` map. I use this to grant restricted emergency powers (like blocking addresses) to a set of trusted actors without granting them full administrative control.

### `check-paused`

A defensive guard clause used throughout the contract. It returns `(ok true)` if the bridge is operational or `ERR-TRANSFER-PAUSED` if either a global or specific chain pause is active.

### `is-address-blocked (addr principal)`

Performs a lookup in the `blocked-addresses` map. This is checked at the entry point of every transfer to prevent sanctioned or malicious actors from interacting with the protocol.

### `get-chain-config (chain (string-ascii 10))`

Retrieves the operational parameters for a specific destination chain. I designed this to unwrap map data safely, ensuring that calls to unsupported chains fail gracefully with `ERR-CHAIN-NOT-SUPPORTED`.

---

## Detailed Public Function Specification

These are the primary entry points for users, administrators, and the AI agent.

### Administrative & Guardian Functions

* **`add-guardian / remove-guardian`**: Allows the `CONTRACT-OWNER` to manage the circle of trust. Guardians provide an extra layer of human redundancy.
* **`block-address / unblock-address`**: Enables Guardians to manually blacklist malicious principals. I have enabled this as an immediate intervention tool before the AI might even detect the pattern.
* **`configure-chain`**: Used to set daily volume limits and toggle the operational status of destination networks (e.g., Ethereum, Solana, Bitcoin).
* **`set-ai-agent`**: Updates the principal authorized to act as the AI intelligence provider.

### Core Protocol Logic

* **`initiate-transfer (amount uint) (target-chain (string-ascii 10)) (target-address (string-ascii 42))`**:
The main user entry point. I have programmed this function to perform a "pre-flight" check including:
1. Verifying the bridge isn't paused.
2. Checking the sender's blacklist status.
3. Validating the target chain is active.
4. Ensuring the transfer doesn't exceed the global limit or the specific chain's remaining daily capacity.
5. Assigning a unique `request-id` and setting the status to `PENDING`.


* **`submit-risk-assessment (request-id uint) (risk-score uint) (reason (string-utf8 64))`**:
This is where the AI agent intervenes. Based on the `risk-score` (0-100), I have implemented a status transition:
* **Score < 20**: Status becomes `APPROVED`.
* **Score 20-50**: Status becomes `APPROVED` (Standard Risk).
* **Score 51-80**: Status becomes `FLAGGED` (Warning).
* **Score > 80**: Status becomes `REJECTED`.


* **`analyze-incident-report`**:
The most complex logic gate in the contract. It accepts a comprehensive telemetry report.
* If **Critical** (Liquidity drain or Flash loan detected): The bridge is paused immediately, limits are set to zero, and the risk level is maxed.
* If **Warning** (Anomalous volume or Latency): The protocol reduces its global transfer limits by 75% to minimize potential exposure while remaining operational.
* If **Normal**: The protocol enters a "Recovery Mode," slowly restoring limits to their maximum values if the threat score is low.



---

## Threat Vector Analysis

I have designed the `analyze-incident-report` function to handle the following specific attack patterns:

| Vector | Internal Response | Diagnostic Event |
| --- | --- | --- |
| **Liquidity Drain** | Immediate Global Pause | `security-alert: CRITICAL` |
| **Flash Loan** | Immediate Global Pause | `security-alert: CRITICAL` |
| **Anomalous Volume** | 75% Limit Reduction | `security-warning: anomalous-volume` |
| **Latency Spike** | Limit Throttling | `security-warning: latency-spike` |
| **MEV Activity** | Monitoring Intensification | `mev-activity-detected` |

---

## Technical Constants & Error Map

| Name | Code | Description |
| --- | --- | --- |
| `ERR-NOT-AUTHORIZED` | `u100` | Caller does not have the required role |
| `ERR-INVALID-REQUEST` | `u101` | The Request ID does not exist or parameters are invalid |
| `ERR-TRANSFER-PAUSED` | `u102` | Global or local pause is active |
| `ERR-RISK-TOO-HIGH` | `u103` | AI Agent rejected the transfer due to risk |
| `ERR-CHAIN-NOT-SUPPORTED` | `u104` | Destination chain is not whitelisted |
| `ERR-ADDRESS-BLOCKED` | `u105` | Principal is on the blacklist |
| `ERR-LIMIT-EXCEEDED` | `u106` | Transfer exceeds set security thresholds |

---

## MIT License

```text
Copyright (c) 2026 SentinelBridge Protocol

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.

```

---

## Contribution & Audit History

I am committed to an open-source security model. SentinelBridge is a living protocol.

1. **Audits**: Current version `v1.0.4-beta`. Internal security review completed Feb 2026.
2. **Bounty Program**: I encourage researchers to find edge cases in the dynamic limit adjustment logic.
3. **Development**: Built using Clarity 2.0. Optimized for the Stacks Nakamoto release.
