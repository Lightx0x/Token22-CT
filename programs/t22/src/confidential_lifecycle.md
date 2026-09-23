# The confidential lifecycle

A confidential account keeps two balances:

- **pending** — where incoming credits land. The owner cannot spend it and,
  because senders write to it, cannot predict its ciphertext.
- **available** — spendable. Only the owner moves value into it.

That split exists so a sender cannot invalidate a proof the owner is halfway
through building. It is also why `ApplyPendingBalance` is a mandatory step
between "funds arrived" and "funds can be spent", not an optimization.

## The path

| # | instruction | signer | in this program |
|---|---|---|---|
| 1 | `CreateAssociatedTokenAccount` | payer — **anyone** | client |
| 2 | `Reallocate` | owner | client |
| 3 | `ThawAccount` (KYC) | freeze authority | `thaw_after_kyc` |
| 4 | `ConfigureAccount` | **owner only** | `configure_confidential_account` |
| 5 | `ApproveAccount` | confidential-transfer authority | `approve_confidential_account` |
| 6 | `Deposit` | owner | `deposit_confidential` |
| 7 | `ApplyPendingBalance` | owner | `apply_pending_balance` |
| 8 | `TransferWithFee` | owner | `transfer_confidential` |
| 9 | `ApplyPendingBalance`, then `Withdraw` | owner | `withdraw_confidential` |

## Steps 1 and 4 are different in kind

Creating an associated token account is permissionless. A relayer can open one
*for* a user who holds no SOL, and Token-2022 is fine with that because the
address derives from the owner.

`ConfigureAccount` is not. It registers the ElGamal public key that will guard
the balance, so the processor runs `validate_owner` against the token account's
own owner field. A payer who is not the owner cannot do it — and could not
derive the key anyway, since the key comes from a signature by the owner's
wallet.

## Step 2 exists because ConfigureAccount does not grow the account

The ATA program sizes a new account only for the extensions the *mint*
requires — here `TransferFeeAmount`. `ConfidentialTransferAccount` is opt-in,
and `process_configure_account` says as much in a comment: *"The caller is
expected to use the `Reallocate` instruction to ensure there is sufficient room
in their token account"*. On a fee-bearing mint it must also make room for
`ConfidentialTransferFeeAmount`, which `ConfigureAccount` initializes as a side
effect.

## Step 5 exists because approval is manual

The mint is created with `auto_approve_new_accounts: false`. `ConfigureAccount`
leaves `approved` false, and every confidential operation fails until the
mint's confidential-transfer authority signs. It is a second issuer gate,
independent of the KYC thaw in step 3.

## What is frozen-sensitive and what is not

`Reallocate`, `ConfigureAccount` and `ApproveAccount` all work on a still-frozen
account — none of them moves value. Everything from `Deposit` onward, including
`ApplyPendingBalance`, rejects a frozen account. So the KYC thaw has to land
before step 6, and may land any time before it.

## ApplyPendingBalance does not abort on a race

The chain adds the ciphertexts homomorphically; the owner supplies the matching
plaintext sum re-encrypted under their AES key, because only the owner can read
either side.

The credit counter is a race *detector*, not a lock. The chain always applies
whatever is pending, then stores the counter the caller expected alongside the
counter that actually applied. If a credit landed between reading the account
and the instruction landing, the two differ and the `decryptable_available_balance`
written is short by that credit — the ElGamal `available_balance` is still
correct. The fix is to re-read, compare the two counters, and apply again with
the corrected sum; pending is zero by then, so the second apply only rewrites
the decryptable copy.

## Why the proofs are client-side

Every proof here is built from the owner's ElGamal secret. A program cannot
build one, because the secret must never reach the chain. So the client
generates each proof, verifies it into a **context state account** with the ZK
ElGamal proof program, and this program's instructions reference those accounts
by address.

Two practical consequences:

- **One proof per transaction.** A `BatchedRangeProofU256Data` is close to the
  1232-byte packet limit on its own, so the verify instruction cannot share a
  transaction with anything else — the context account is allocated separately.
- **Raise the compute budget.** Verifying a 256-bit range proof exceeds the
  default 200k CU and dies with `ComputationalBudgetExceeded`. The verify
  transaction needs an explicit `SetComputeUnitLimit`.

Context state accounts are rent-bearing and single-use. Close them afterwards
or leak one account's rent per transfer.
