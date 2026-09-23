# Seizure and confidentiality on one mint

Two requirements land on the same token. The regulator wants funds seizable
from sanctioned wallets. Users want transfer amounts hidden. Confidential
transfers cannot be added to a live mint, so the mint is re-issued carrying the
v1 extension set forward, now with `PermanentDelegate` and
`ConfidentialTransferMint`.

Three things fall out of that, and the third is the one that matters.

## 1. Token-2022 forces a third extension

`TransferFeeConfig + ConfidentialTransferMint` is rejected at
`InitializeMint` unless `ConfidentialTransferFeeConfig` is initialized too —
`check_for_invalid_mint_extension_combinations` refuses the pair outright.

The reason is not bureaucratic. A fee on a confidential transfer is a
percentage of an amount nobody can see. The resolution is that the withheld fee
is itself an ElGamal ciphertext, encrypted under a key belonging to the
withdraw-withheld authority, so only that authority can total up what it is
owed. That extension is where the key lives. So it takes an ElGamal public key
rather than just an address, and v2 is seven extensions rather than six.

## 2. The transfer instruction changes

Once a mint has a transfer fee, the plain confidential `Transfer` path is
unreachable. The processor branches on
`mint.get_extension::<TransferFeeConfig>()`, and the fee branch requires
`TransferWithFee`: five proofs instead of three.

The two extra proofs are a percentage-with-cap proof — that the encrypted fee
really is the mint's rate applied to the encrypted amount — and a validity
proof for the fee ciphertext, with the range proof widened from 128 to 256
bits. The first of those is the interesting one: it is how the chain enforces
the fee schedule without learning the amount.

So "keep the fee" and "add confidentiality" are not two independent
checkboxes. Together they change which instruction moves tokens.

## 3. The seizure authority does not reach confidential balances

This is the gap.

`PermanentDelegate` lets the issuer sign a transfer out of any account without
the owner's consent. Token-2022 accepts the delegate wherever it accepts the
owner, so seizure needs no special instruction — only a different signer. That
satisfies the regulator for the **public** balance.

It buys nothing for the confidential balance. Moving confidential funds
requires an equality proof over the source's available balance, and that proof
can only be built with the source owner's ElGamal secret key. The delegate has
the authority and not the key. No combination of extensions changes this,
because it is not an authorization question — it is the encryption doing
exactly what it was chosen to do.

A mint-level auditor key narrows it only partly. An auditor can *decrypt* every
transfer amount, so nothing is hidden from the issuer. But decryption is not
spending authority: knowing a balance does not let you move it.

### What that leaves

- Seizure is reliable only against the public balance. `t22::seize` is honest
  about its own scope.
- Reaching a confidential balance means the holder withdrawing it back to
  public first — that is, cooperation.
- The one unilateral control that does bite is the **freeze authority**.
  Freezing halts deposits, transfers and withdrawals on that account, so funds
  cannot leave while the issuer negotiates. Freeze contains; it does not
  confiscate.
- Order matters: a frozen account cannot be transferred out of even by the
  permanent delegate, so an enforcement flow seizes first and freezes second.

If unilateral confiscation of hidden balances is a hard regulatory
requirement, no extension combination delivers it, and the honest answer is not
to ship confidential transfers on this mint.
