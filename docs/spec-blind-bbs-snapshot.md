%%%
title = "Blind BBS Signatures"
abbrev = "Blind BBS Signatures"
ipr= "trust200902"
area = "Internet"
workgroup = "CFRG"
submissiontype = "IETF"
keyword = [""]

[seriesInfo]
name = "Internet-Draft"
value = "draft-irtf-cfrg-bbs-blind-signatures-latest"
status = "informational"
stream = "IETF"

[[author]]
initials = "V."
surname = "Kalos"
fullname = "Vasilis Kalos"
#role = "editor"
organization = "MATTR"
  [author.address]
  email = "vasilis.kalos@mattr.global"

[[author]]
initials = "G."
surname = "Bernstein"
fullname = "Greg M. Bernstein"
#role = "editor"
organization = "Grotto Networking"
  [author.address]
  email = "gregb@grotto-networking.com"
%%%

.# Abstract

This document defines an extension to the BBS Signature scheme that supports blind digital signatures, i.e., signatures over messages not known to the Signer.

{mainmatter}

# Introduction

Blind signatures are cryptographic protocols that allow for a signer to create a signature over content without actually knowing the content. They form a useful cryptographic primitive particularly in situations that are privacy sensitive. The concept has existed for quite some time and is well explained in Chaum's 1985 popular article "Security without identification: transaction systems to make big brother obsolete" [@Chaum85]. In [@RFC9474], "RSA Blind Signatures", the RSA signature scheme was extended to provide for blind signing. In this document the BBS digital signature scheme, as defined in [@!I-D.irtf-cfrg-bbs-signatures], is extended to provide blind BBS signatures.

Like BBS signatures blind BBS signatures work with a three party model of *Signer*, *Prover*, and *Verifier*. The blind BBS protocol defined here has the following useful properties:

1. Provides a signature over an ordered set of messages from the *Prover* that are kept secret from the *Signer* via a statistically hiding cryptographic commitment.
2. The *Signer* will produce a signature for the *Prover*, only if the later can prove knowledge of the set of messages they choose. This will be done through a zero-knowledge proof-of-knowledge of the ordered set of secret *Prover* messages. The *Signer* will not issue a signature without this proof of knowledge.
3. The Blind BBS signature produced is of the same size as current BBS signatures based on the same elliptic curve.
4. In addition to the *Prover* provided secret messages, the *Signer* can optionally sign over an additional ordered set of messages of their choosing. This is sometimes know as a "partially blind" signature.
5. Using the Blind BBS signature created by the *Signer* the *Prover* can disclose any subset of both the secret *Prover* messages or the *Signer*'s messages and prove that these were in the signed sets.
6. Without knowledge of the ordered set of secret messages no selective disclosure proof can be generated even solely for a subset of the *Signer* messages. (within the security assumptions of the BBS signature scheme).

While the core BBS protocol allows a prover to either disclose or withhold a message from a verifier, this specification allows for **committed disclosure** of a message [@Vision2025]. In this case, the prover provides a commitment (computationally binding and perfectly hiding) to the message along with proof that the commitment corresponds to a particular message in the signature. This enables a prover to demonstrate properties of credential attributes without revealing the underlying attribute values.

The idea behind this committed-disclosure extension for BBS is that it also accommodates further zero-knowledge proof (ZKP) extensions for predicate proofs -- e.g. range proofs or different pseudonyms -- in a modular, plug-and-play style. Such extensions are out of scope of this specification.

## Blind BBS Protocol Overview

The presented protocol, compared to the scheme defined in [@!I-D.irtf-cfrg-bbs-signatures], introduces an additional communication step between the *Prover* and the *Signer*. An overview of the protocol is given below.

1. The *Prover* will start by constructing a "hiding" commitment to the ordered set of messages they want to get a signature on (i.e., a commitment which reveals no information about the committed values), together with a proof of correctness of that commitment.
2. The *Prover* will send the (commitment, proof) pair to the *Signer*, who, upon receiving the pair, will attempt to verify the commitment's proof of correctness.
3. If successful, they will use it in generating a blind BBS signature over the messages committed by the *Prover*, including the *Signer*'s own messages if any.
4. The *Signer* will send the blind signature along with its additional ordered messages (if any) to the *Prover*
5. The *Prover* can choose to selectively disclose or commit to any subset of either its own messages, kept secret from the *Signer* and messages provided by the *Signer* in the signature. They also furnish a ZKP that the these disclosed messages were included in the signature.
6. The *Verifier* verifies the proof received from the *Prover* based on the *Signer*'s public key.

Note: Cryptographic *commitments* are used for two distinct purposes in this specification. One, as a mechanism for the prover to get a blind signature from an signer, i.e., the prover is getting a signature over some data it is not revealing to the signer. And, two, as mechanism to furnish less information from the prover to the verifier by providing a commitment along with a ZKP about that commitment.  For example, instead of providing a date of birth, the prover provides a commitment to that date of birth along with ZKP that indicates that the provers age lies in a particular range.

Below is a basic diagram describing the main entities involved in the scheme.
!---
~~~ ascii-art
 (3) Blind Sign                                          (1) Commit
     +-----                                                +-----
     |    |                                                |    |
     |    |                                                |    |
     |   \ /                                               |   \ /
  +----------+                                          +-----------+
  |          |                                          |           |
  |          |                                          |           |
  |          |<-(2)* Commitment + Proof of Correctness--|           |
  |  Signer  |                                          |   Prover  |
  |          |--(4)* Send signature + msgs + coms------>|           |
  |          |                                          |           |
  |          |                                          |           |
  +----------+                                          +-----------+
                                                              |
                                                              |
                                                              |
                                                      (5)* Send proof
                                                              +
                                                       disclosed msgs
                                                              |
                                                              |
                                                             \ /
                                                        +-----------+
                                                        |           |
                                                        |           |
                                                        |           |
                                                        |  Verifier |
                                                        |           |
                                                        |           |
                                                        |           |
                                                        +-----------+
                                                           |   / \
                                                           |    |
                                                           |    |
                                                           +-----
                                                      (6) ProofVerify
~~~
!---
Figure: Basic diagram capturing the main entities involved in using the scheme.

**Note** The protocols implied by the items annotated by an asterisk are out of scope for this specification

This document, in addition to defining the operation for creating and verifying a commitment, also details a core signature generation operation, different from the one presented in [@!I-D.irtf-cfrg-bbs-signatures], meant to handle the computation of the blind signature. The document will also define a new BBS Interface, which is needed to handle the different inputs, i.e., messages committed by the *Prover* or chosen by the Signer etc.. The signature verification and proof generation and verification core cryptographic operations however, will work as described in [@!I-D.irtf-cfrg-bbs-signatures].

## Example Blind BBS Applications

By allowing the *Prover* to acquire a valid signature over messages not known to the Signer, blind signatures address some limitations of their plain digital signature counterparts. In the BBS Signature scheme, knowledge of a valid signature and set of signed messages allows generation of BBS proofs. As a result, a signature compromise (for example by a Signer database leakage, a phishing attack etc.,) can lead to impersonation of the *Prover* by malicious actors (especially in cases involving "long-lived" signatures, as in digital credentials applications etc.,). Using Blind BBS Signatures on the other hand, the *Prover* can commit to a secret message (for example, a private key) before issuance, guaranteeing that no one will be able to generate a valid BBS proof without knowledge of that secret message.

Furthermore, applications like Privacy Pass ([@I-D.ietf-privacypass-protocol]) may require a signature to be "scoped" to a specific audience or session (as to require "fresh" signatures for different sessions etc.,). However, simply sending an audience or session identifier to the Signer (to be included in the signature), will compromise the privacy guarantees that these applications try to enforce. Using blind signing, the Prover will be able to require signatures bound to those values, without having to reveal them to the Signer.

## Example Committed Disclosure Applications

Privacy is enhanced via the **committed disclosure** mechanism along with an external ZKP proof of some predicate. In this case rather than selectively disclosing a signed message to the verifier the prover provides a (computationally binding and perfectly hiding) commitment along with a ZKP concerning some aspect (the predicate) of the committed value.

For an example, consider a prover who must demonstrate that they are over 18 years old. Rather than revealing the credential attribute containing their date of birth, the prover generates a proof consisting of:

1. A BBS presentation proof according to step 5 of (#blind-bbs-protocol-overview), in which the corresponding attribute remains hidden,
2. The commitment `C` as part of the above proof,
3. A proof of knowledge of the opening of `C`, together with a proof that the committed value is equal to the hidden message contained in the BBS signature,
4. An additional range proof `P` showing that the committed birth date in `C` corresponds to an age greater than or equal to 18.

The generation of predicate proofs (item 4) is outside the scope of this specification. However, this specification defines:

* How Pedersen commitments are generated for attributes subject to predicates (item 2),
* How equality proofs between committed values and credential attributes are constructed (item 3).

For this reason, the `BlindProofGen` procedure outputs, in addition to the proof `proof` sent to the verifier, the tuple `add_zkp_info`, containing the committed messages and the opening information required to reconstruct Pedersen commitments. This information is never sent to the verifier. Instead, it is retained by the prover and later used to generate predicate proofs.

Committed disclosure allows for the modular addition of proving possession of a device key, range proofs, and pseudonyms as discussed in [@Vision2025]. These would all be implemented as an additional predicate ZKP along with the committed disclosure ZKP specified here.

## Terminology

Terminology defined by [@!I-D.irtf-cfrg-bbs-signatures] applies to this draft.

Additionally, the following terminology is used throughout this document:

blind\_signature
: The blind digital signature output.

commitment
: A point of G1, representing a Pedersen commitment ([@P91]) constructed over a vector of messages, as described e.g., in [@BG18].

committed\_messages
: A list of messages committed by the Prover to a commitment.

commitment\_proof
: A zero knowledge proof of correctness of a commitment, consisting of a scalar value, a possibly empty set of scalars (of length equal to the number of committed\_messages, see above) and another scalar, in that order.

secret\_prover\_blind
: A random scalar used to blind (i.e., randomize) the commitment constructed by the prover.

signer\_blind
: A random scalar used by the signer to optionally re-blind the received commitment.

NONE
: An empty function input indicator, used to specify that one of the OPTIONAL inputs of a procedure is not provided by the calling operation.

## Notation

Notation defined by [@!I-D.irtf-cfrg-bbs-signatures] applies to this draft.

Additionally, the following notation and primitives are used:

list.append(elements)
: Append either a single element or a list of elements to the end of a list, maintaining the same order of the list's elements as well as the appended elements. For example, given `list = [a, b, c]` and `elements = [d, a]`, the result of `list.append(elements)` will be `[a, b, c, d, a]`.

# Conventions

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD", "SHOULD NOT", "RECOMMENDED", "NOT RECOMMENDED", "MAY", and "OPTIONAL" in this document are to be interpreted as described in BCP 14 [@!RFC2119] [@!RFC8174] when, and only when, they appear in all capitals, as shown here.

# BBS Signature Scheme Operations

This document makes use of various operations defined by the BBS Signature Scheme document [@!I-D.irtf-cfrg-bbs-signatures]. For clarity, whenever an operation will be used defined in [@!I-D.irtf-cfrg-bbs-signatures], it will be prefixed by "BBS." (e.g., "BBS.CoreVerify" etc.). More specifically, the operations used are the following:

- `BBS.octets_to_point_E1`: Refers to the `octets_to_point_E1` operation defined in [@!I-D.irtf-cfrg-bbs-signatures, section 1.2].
- `BBS.CoreVerify`: Refers to the `CoreVerify` operation defined in [@!I-D.irtf-cfrg-bbs-signatures, section 3.6.2].
- `BBS.ProofInit`: Refers to the `ProofInit` operation defined in [@!I-D.irtf-cfrg-bbs-signatures, section 3.7.1].
- `BBS.ProofFinalize`: Refers to the `ProofFinalize` operation defined in [@!I-D.irtf-cfrg-bbs-signatures, section 3.7.2].
- `BBS.ProofVerifyInit`: Refers to the `ProofVerifyInit` operation defined in [@!I-D.irtf-cfrg-bbs-signatures, section 3.7.3].
- `BBS.create_generators`: Refers to the `create_generators` operation defined in [@!I-D.irtf-cfrg-bbs-signatures, section 4.1.1].
- `BBS.messages_to_scalars`: Refers to the `messages_to_scalars` operation defined in [@!I-D.irtf-cfrg-bbs-signatures, section 4.1.2].
- `BBS.calculate_random_scalars`: Refers to the `calculate_random_scalars` operation defined in [@!I-D.irtf-cfrg-bbs-signatures, section 4.2.1].
- `BBS.hash_to_scalar`: Refers to the `hash_to_scalar` operation defined in [@!I-D.irtf-cfrg-bbs-signatures, section 4.2.2].
- `BBS.calculate_domain`: Refers to the `calculate_domain` operation defined in [@!I-D.irtf-cfrg-bbs-signatures, section 4.2.3].
- `BBS.serialize`: Refers to the `serialize` operation defined in [@!I-D.irtf-cfrg-bbs-signatures, section 4.2.4.1].
- `BBS.signature_to_octets`: Refers to the `signature_to_octets` operation defined in [@!I-D.irtf-cfrg-bbs-signatures, section 4.2.4.2].
- `BBS.octets_to_proof`: Refers to the `octets_to_proof` operation defined in [@!I-D.irtf-cfrg-bbs-signatures, section 4.2.4.5].



# Scheme Definition

## Commitment Operations

<!-- Should we call these blind commitment operations since they are used for blind signing and not for
committed disclosure?-->

### Commitment Computation

This operation is used by the Prover to create a `commitment` to a set of messages (`committed_messages`), that they intend to include in the blind signature. Note that this operation returns both the serialized combination of the commitment and its proof of correctness (`commitment_with_proof`), as well as the random scalar used to blind the commitment (`secret_prover_blind`).

```
(commitment_with_proof, secret_prover_blind) = Commit(
                                                   committed_messages,
                                                   api_id)

Inputs:

- committed_messages (OPTIONAL), a vector of octet strings. If not
                                 supplied it defaults to the empty
                                 array ("()").
- api_id (OPTIONAL), octet string. If not supplied it defaults to the
                     empty octet string ("").

Outputs:

- (commitment_with_proof, secret_prover_blind), a tuple comprising from
                                                an octet string and a
                                                random scalar in that
                                                order.

Procedure:

1. committed_message_scalars = BBS.messages_to_scalars(
                                             committed_messages, api_id)

2. blind_generators = BBS.create_generators(
                                  length(committed_message_scalars) + 1,
                                  "BLIND_" || api_id)

3. return CoreCommit(blind_generators,
                             committed_message_scalars, api_id)
```

### Commitment Validation and Deserialization

The following is a helper operation used by the `BlindSign` procedure ((#blind-signature-generation)) to validate an optional commitment. If a `commitment` is not supplied, or if it is the `Identity_G1`, the following operation will return the `Identity_G1` as the "default" commitment point, which will be ignored by all computations during `BlindSign`.

```
commitment = deserialize_and_validate_commit(commitment_with_proof,
                                               blind_generators, api_id)

Inputs:

- commitment_with_proof (OPTIONAL), octet string. If it is not supplied
                                    it defaults to the empty octet
                                    string ("").
- blind_generators (OPTIONAL), vector of points of G1. If it is not
                               supplied it defaults to the empty set
                               ("()").
- api_id (OPTIONAL), octet string. If not supplied it defaults to the
                     empty octet string ("").

Outputs:

- commitment, a point of G1; or INVALID.

Procedure:

1. if commitment_with_proof is the empty string (""), return Identity_G1

2. com_res = octets_to_commitment_with_proof(commitment_with_proof)
3. if com_res is INVALID, return INVALID

4. (commitment, commitment_proof) = com_res
5. if length(commitment_proof[1]) + 1 != length(blind_generators),
                                                          return INVALID

6. validation_res = CoreCommitVerify(commitment, commitment_proof,
                                               blind_generators, api_id)
7. if validation_res is INVALID, return INVALID
8. return commitment
```

## Blind BBS Signatures Interface

The following section defines a BBS Interface for blind BBS signatures. The identifier of the Interface is defined as `ciphersuite_id || BLIND_H2G_HM2S_`, where `ciphersuite_id` is the unique identifier of the BBS ciphersuite used, as defined in [@!I-D.irtf-cfrg-bbs-signatures, section 6]. Each BBS Interface MUST define operations to map the input messages to scalar values and to create the generator set, required by the core operations. The input messages to the defined Interface will be mapped to scalars using the `messages_to_scalars` operation defined in [@!I-D.irtf-cfrg-bbs-signatures, section 4.1.2]. The generators will be created using the `create_generators` operation defined in [@!I-D.irtf-cfrg-bbs-signatures, section 4.1.1].

Other than the `BlindSign` operation defined in (#blind-signature-generation), which uses the `FinalizeBlindSign` procedure, defined in (#finalize-blind-sign), all other interface operations defined in this section use the core operations defined in [@!I-D.irtf-cfrg-bbs-signatures, section 3.6].

### Blind Signature Generation

This operation returns a BBS blind signature from a secret key (SK), over a `header`, a set of `messages` and optionally a commitment value (see (#terminology)). If supplied, the commitment value must be accompanied by its proof of correctness (`commitment_with_proof`, as outputted by the `Commit` operation defined in (#commitment-computation)).

The `BlindSign` operation makes use of the `FinalizeBlindSign` procedure defined in (#finalize-blind-sign) and the `B_calculate` procedure defined in (#calculate-b-value). The `B_calculate` is defined to return an array of elements, to establish extendability of the scheme by allowing the `B_calculate` operation to return more elements than just the point to be signed.

```
blind_signature = BlindSign(SK, PK, commitment_with_proof, header,
                                                               messages)

Inputs:

- SK (REQUIRED), a secret key in the form outputted by the KeyGen
                 operation.
- PK (REQUIRED), an octet string of the form outputted by SkToPk
                 provided the above SK as input.
- commitment_with_proof (OPTIONAL), an octet string, representing a
                                    serialized commitment and
                                    commitment_proof, as the first
                                    element outputted by the Commit
                                    operation. If not supplied, it
                                    defaults to the empty string ("").
- header (OPTIONAL), an octet string containing context and application
                     specific information. If not supplied, it defaults
                     to an empty string ("").
- messages (OPTIONAL), a vector of octet strings. If not supplied, it
                       defaults to the empty array ("()").

Parameters:

- api_id, the octet string ciphersuite_id || "BLIND_H2G_HM2S_", where
          ciphersuite_id is defined by the ciphersuite and
          "BLIND_H2G_HM2S_"is an ASCII string composed of 15 bytes.
- (octet_point_length, octet_scalar_length), defined by the ciphersuite.

Outputs:

- blind_signature, a blind signature encoded as an octet string; or
                   INVALID.


Deserialization:

1. L = length(messages)

// calculate the number of blind generators used by the commitment,
// if any.
2. M = length(commitment_with_proof)
3. if M != 0, M = M - octet_point_length - 2 * octet_scalar_length
4. M = M / octet_scalar_length
5. if M < 0, return INVALID

Procedure:

1.  generators = BBS.create_generators(L + 1, api_id)
2.  blind_generators = BBS.create_generators(M + 1, "BLIND_" || api_id)

3.  commitment = deserialize_and_validate_commit(commitment_with_proof,
                                               blind_generators, api_id)
4.  if commitment is INVALID, return INVALID

5.  message_scalars = BBS.messages_to_scalars(messages, api_id)

6.  res = B_calculate(PK, generators, blind_generators, commitment, message_scalars, header, api_id)
7.  if res is INVALID, return INVALID
8.  (B) = res

9.  blind_sig = FinalizeBlindSign(SK, B, api_id)
10. if blind_sig is INVALID, return INVALID
11. return blind_sig
```

### Blind Signature Verification

This operation validates a blind BBS signature (`signature`), given the Signer's public key (`PK`), a header (`header`), a set of messages (`messages`), including first the messages chosen by the Issuer and then the ones chosen (and committed to) by the Prover and if used, the `secret_prover_blind` as returned by the `Commit` operation ((#commitment-computation)).

This operation makes use of the `CoreVerify` operation as defined in [@!I-D.irtf-cfrg-bbs-signatures, section 3.6.2].

```
result = VerifyBlindSign(PK, signature, header, messages,
                          issuer_known_messages_no, secret_prover_blind)

Inputs:

- PK (REQUIRED), an octet string of the form outputted by the SkToPk
                 operation.
- signature (REQUIRED), an octet string of the form outputted by the
                        Sign operation.
- header (OPTIONAL), an octet string containing context and application
                     specific information. If not supplied, it defaults
                     to an empty string.
- messages (OPTIONAL), a vector of octet strings. If not supplied, it
                       defaults to the empty array "()".
- issuer_known_messages_no (OPTIONAL), a non-negative integer. If not
                                       supplied, it defaults to 0.
- secret_prover_blind (OPTIONAL), a scalar value. If not supplied it
                                  defaults to zero "0".


Parameters:

- api_id, the octet string ciphersuite_id || "BLIND_H2G_HM2S_", where
          ciphersuite_id is defined by the ciphersuite and
          "BLIND_H2G_HM2S_"is an ASCII string composed of 15 bytes.

Outputs:

- result: either VALID or INVALID

Deserialization:

1. L = length(messages)
2. if issuer_known_messages_no > L, return INVALID

Procedure:

1. generators = BBS.create_generators(issuer_known_messages_no + 1, api_id)
2. blind_generators = BBS.create_generators(
                   L - issuer_known_messages_no + 1, "BLIND_" || api_id)

3. message_scalars = BBS.messages_to_scalars(messages, api_id)

4. signer_scalars = (message_scalars[0], ...,
                          message_scalars[issuer_known_messages_no - 1])
5. committed_message_scalars = (message_scalars[issuer_known_messages_no], ...,
                                            message_scalars[L - 1])
6. proof_scalars = signer_scalars.append(secret_prover_blind)
                                          .append(committed_message_scalars)

7. res = BBS.CoreVerify(PK,
                        signature,
                        generators.append(blind_generators),
                        header,
                        proof_scalars,
                        api_id)
8. return res
```

### Proof Generation

This operation creates a BBS proof, which is a zero-knowledge, proof-of-knowledge, of a BBS signature, while optionally disclosing any subset of the signed messages (either chosen by the Issuer or committed by the Prover). In addition, this operation can generate commitments to un-revealed messages and include with the BBS proof that these commitments correspond to specific un-revealed messages. These commitments can be used in subsequent ZKPs outside the scope of this specification .

When this operation furnishes disclosed commitment values it will also return an additional bundle of information for use in external ZKPs [@Vision2025].  This *add_zkp_info* includes the committed message scalars and the random scalars, from these the disclosed commitments may be recomputed. The  *add_zkp_info*  should never be exposed, i.e., it is NOT to be sent to the verifier. The *add_zkp_info* structure has the following form:

```
add_zkp_info = {
  committed_message_scalars: (REQUIRED) Array of Scalars,
  commitment_rands: (REQUIRED) Array of Scalars
}
```

The operation will accept a set of messages (`messages`), including first the messages chosen by the Issuer and then the ones chosen (and committed to) by the Prover.

Furthermore, the operation also expects the `secret_prover_blind` (as returned from the `Commit` operation defined in (#commitment-computation)) value. If the BBS signature is generated using a commitment value, then the `secret_prover_blind` returned by the `Commit` operation used to generate the commitment should be provided to the `ProofGen` operation (otherwise the resulting proof will be invalid).

This operation makes use of the `CoreProofGen` operation as defined in (#core-proof-generation).

The operation will also accept a map `message_disclosures` between each message index and one of the three values `DISCLOSE`, `HIDE` and `COMMIT`. A `{i: DISCLOSE}` (key, value) pair indicates that `messages[i]` will be revealed to the Verifier. Correspondingly, a `{i: HIDE}` (key, value) pair indicates that `messages[i]` will not be disclosed to the Verifier. Finally, a `{i: COMMIT}` (key, value) pair indicates that only a commitment to `messages[i]` will be disclosed to the Verifier.

An example of the `message_disclosures` input map is the following,

```
message_disclosures = {
  0: DISCLOSE,
  1: HIDE,
  2: HIDE,
  3: COMMIT,
  4: COMMIT,
  5: DISCLOSE,
  6: DISCLOSE,
  7: COMMIT,
  8: DISCLOSE
}
```


```
[proof, add_zkp_info] = BlindProofGen(PK,
                      signature,
                      header,
                      ph,
                      messages,
                      issuer_known_messages_no,
                      message_disclosures,
                      secret_prover_blind)

Inputs:

- PK (REQUIRED), an octet string of the form outputted by the SkToPk
                 operation.
- signature (REQUIRED), an octet string of the form outputted by the
                        Sign operation.
- header (OPTIONAL), an octet string containing context and application
                     specific information. If not supplied, it defaults
                     to an empty string.
- ph (OPTIONAL), an octet string containing the presentation header. If
                 not supplied, it defaults to an empty string.
- messages (OPTIONAL), a vector of octet strings. If not supplied, it
                       defaults to the empty array "()".
- issuer_known_messages_no (OPTIONAL), a non-negative integer. If not
                                       supplied, it defaults to 0.
- message_disclosures (OPTIONAL), a map between message indexes and one
                                   of the DISCLOSE, HIDE or COMMIT
                                   values. If not supplied, it defaults
                                   to the empty map "{}".
- secret_prover_blind (OPTIONAL), a scalar value. If not supplied it
                                  defaults to zero "0".


Parameters:

- api_id, the octet string ciphersuite_id || "BLIND_H2G_HM2S_", where
          ciphersuite_id is defined by the ciphersuite and
          "BLIND_H2G_HM2S_"is an ASCII string composed of 15 bytes.

Outputs:

- proof, an octet string; or INVALID.
- add_zkp_info, a structure containing an array of committed message scalars
                used in committed disclosure, and the array of random scalars
                used to create the respective commitments.

Deserialization:

1. L = length(messages)
2. if length(message_disclosures) != L, return INVALID
3. if issuer_known_messages_no > L, return INVALID
4. if the keys of message_disclosures are not exactly the integers
   0..L - 1, return INVALID
5. if any value in message_disclosures is not one of DISCLOSE, HIDE,
   or COMMIT, return INVALID

6. let disclosed_indexes be the integers i in 0..L - 1 so
   that message_disclosures[i] = DISCLOSE, in
   ascending order.
7. let commitment_indexes be the integers i in 0..L - 1 so
   that message_disclosures[i] = COMMIT, in
   ascending order.

Procedure:

1. generators = BBS.create_generators(
                                  issuer_known_messages_no + 1, api_id)
2. blind_generators = BBS.create_generators(
                   L - issuer_known_messages_no + 1, "BLIND_" || api_id)

3. message_scalars = BBS.messages_to_scalars(messages, api_id)

4. signer_scalars = (message_scalars[0], ...,
                          message_scalars[issuer_known_messages_no - 1])
5. committed_message_scalars = (message_scalars[issuer_known_messages_no], ...,
                                            message_scalars[L - 1])
6. proof_scalars = signer_scalars.append(secret_prover_blind)
                                          .append(committed_message_scalars)
7. let proof_index(i) be i if i < issuer_known_messages_no,
   and i + 1 otherwise.
8. proof_disclosed_indexes = (proof_index(i) for i in disclosed_indexes)
9. proof_commitment_indexes = (proof_index(i) for i in commitment_indexes)

10. proof_with_add_zkp_info = CoreProofGen(PK,
                        signature,
                        generators.append(blind_generators),
                        header,
                        ph,
                        proof_scalars,
                        proof_disclosed_indexes,
                        proof_commitment_indexes,
                        api_id)
11. return proof_with_add_zkp_info
```

### Proof Verification

The ProofVerify operation validates a BBS proof, given the Signer's public key (PK), a header and presentation header values, an array of disclosed messages (the ones provided by the Signer and the ones committed by the prover) and a map `message_disclosures` describing how each signed message index is presented to the Verifier. In addition, the `BlindProofVerify` operation defined in this section accepts the integer `issuer_known_messages_no`, representing the total number of signed messages known by the Signer.

This operation makes use of the `CoreProofVerify` operation as defined in (#core-proof-verification).



```
result = BlindProofVerify(PK,
                          proof,
                          header,
                          ph,
                          issuer_known_messages_no,
                          disclosed_messages,
                          message_disclosures)

Inputs:

- PK (REQUIRED), an octet string of the form outputted by the SkToPk
                 operation.
- proof (REQUIRED), an octet string of the form outputted by the
                    ProofGen operation.
- header (OPTIONAL), an optional octet string containing context and
                     application specific information. If not supplied,
                     it defaults to the empty octet string ("").
- ph (OPTIONAL), an octet string containing the presentation header. If
                 not supplied, it defaults to the empty octet
                 string ("").
- issuer_known_messages_no (OPTIONAL), a non-negative integer. If not
                                       supplied, it defaults to 0.
- disclosed_messages (OPTIONAL), a vector of octet strings. If not
                                 supplied, it defaults to the empty
                                 array ("()").
- message_disclosures (OPTIONAL), a map between message indexes and one
                                   of the DISCLOSE, HIDE or COMMIT
                                   values. If not supplied, it defaults
                                   to the empty map "{}".

Parameters:

- api_id, the octet string ciphersuite_id || "BLIND_H2G_HM2S_", where
          ciphersuite_id is defined by the ciphersuite and
          "BLIND_H2G_HM2S_"is an ASCII string composed of 15 bytes.
- (octet_point_length, octet_scalar_length), defined by the ciphersuite.

Outputs:

- result, either VALID or INVALID.

Deserialization:

1. bbs_proof_len = OS2IP(proof[0..7])
2. undisclosed_msgs_no = (bbs_proof_len
                           - 3 * octet_point_length
                           - 4 * octet_scalar_length)
                           / octet_scalar_length
3. proof_msgs_no = undisclosed_msgs_no + length(disclosed_messages)
4. if proof_msgs_no == 0, return INVALID
5. total_msgs_no = proof_msgs_no - 1
6. if issuer_known_messages_no > total_msgs_no, return INVALID
7. if length(message_disclosures) != total_msgs_no, return INVALID
8. if the keys of message_disclosures are not exactly the integers
   0..total_msgs_no - 1, return INVALID
9. if any value in message_disclosures is not one of DISCLOSE, HIDE,
   or COMMIT, return INVALID

10. let disclosed_indexes be the integers i in 0..total_msgs_no - 1 so
   that message_disclosures[i] = DISCLOSE, in
   ascending order.
11. let commitment_indexes be the integers i in 0..total_msgs_no - 1 so
   that message_disclosures[i] = COMMIT, in
   ascending order.
12. if length(disclosed_indexes) != length(disclosed_messages),
    return INVALID
13. let proof_index(i) be i if i < issuer_known_messages_no,
    and i + 1 otherwise.
14. proof_disclosed_indexes = (proof_index(i) for i in disclosed_indexes)
15. proof_commitment_indexes = (proof_index(i) for i in commitment_indexes)


Procedure:

1. generators = BBS.create_generators(
                                  issuer_known_messages_no + 1, api_id)
2. blind_generators = BBS.create_generators(
                               total_msgs_no - issuer_known_messages_no + 1,
                               "BLIND_" || api_id)

3. message_scalars = BBS.messages_to_scalars(disclosed_messages, api_id)

4. result = CoreProofVerify(
                        PK,
                        proof,
                        generators.append(blind_generators),
                        header,
                        ph,
                        message_scalars,
                        proof_disclosed_indexes,
                        proof_commitment_indexes,
                        api_id)
5. return result
```

## Core Operations

### Core Commitment Computation

<!-- Once again this is only used for blind signing commitment. Should we rename? -->

```
(commitment_with_proof, secret_prover_blind) = CoreCommit(blind_generators,
                                              committed_message_scalars,
                                              api_id)

Inputs:

- blind_generators (REQUIRED), vector of pseudo-random points in G1.
- committed_message_scalars (OPTIONAL), a vector of scalars. If not supplied,
                                 it defaults to the empty array ("()").
- api_id (OPTIONAL), an octet string. If not supplied it defaults to the
                     empty octet string ("").


Deserialization:

1. M = length(committed_message_scalars)
2. if length(blind_generators) != M + 1, return INVALID
3. (Q_2, J_1, ..., J_M) = blind_generators
4. (msg_1, ..., msg_M) = committed_message_scalars
Procedure:

1. (secret_prover_blind, s~, m~_1, ..., m~_M)
                                         = BBS.calculate_random_scalars(M + 2)
2. C = J_1 * msg_1 + ... + J_M * msg_M + Q_2 * secret_prover_blind
3. Cbar = J_1 * m~_1 + ... + J_M * m~_M + Q_2 * s~

4. challenge = calculate_blind_challenge(C, Cbar, blind_generators,
                                                                 api_id)

5. s^ = s~ + secret_prover_blind * challenge
6. for i in (1, 2, ..., M): m^_i = m~_i + msg_i * challenge

7. proof = (s^, (m^_1, ..., m^_M), challenge)
8. commitment_with_proof = commitment_with_proof_to_octets(C, proof)
9. return (commitment_with_proof, secret_prover_blind)
```

### Core Commitment Verification

This operation is used by the Signer to verify the correctness of a `commitment_proof` for a supplied `commitment`, over a list of points of G1 called the `blind_generators`, used to compute that commitment.

```
result = CoreCommitVerify(commitment, commitment_proof,
                                               blind_generators, api_id)

Inputs:

- commitment (REQUIRED), a commitment (see (#terminology)).
- commitment_proof (REQUIRED), a commitment_proof (see (#terminology)).
- blind_generators (REQUIRED), vector of pseudo-random points in G1.
- api_id (OPTIONAL), octet string. If not supplied it defaults to the
                     empty octet string ("").


Outputs:

- result: either VALID or INVALID

Deserialization:

1. (s^, commitments, cp) = commitment_proof

2. M = length(commitments)
3. (m^_1, ..., m^_M) = commitments

4. if length(blind_generators) != M + 1, return INVALID
5. (Q_2, J_1, ..., J_M) = blind_generators

Procedure:

1. Cbar = J_1 * m^_1 + ... + J_M * m^_M + Q_2 * s^ + commitment * (-cp)
2. cv = calculate_blind_challenge(commitment, Cbar, blind_generators,
                                                                 api_id)
3. if cv != cp, return INVALID
4. return VALID
```

### Finalize Blind Sign

This operation computes a blind BBS signature from a secret key (`SK`) and the
point to be signed (`B`). The operation also accepts the identifier of the BBS
Interface that calls this core operation.

```
blind_signature = FinalizeBlindSign(SK, B, api_id)

Inputs:

- SK (REQUIRED), a secret key in the form outputted by the KeyGen
                 operation.
- B (REQUIRED), a point of G1, different than Identity_G1.
- api_id (OPTIONAL), an octet string. If not supplied it defaults to the
                     empty octet string ("").

Outputs:

- blind_signature, a blind signature encoded as an octet string; or
                   INVALID.

Definitions:

1. signature_dst, an octet string representing the domain separation
                  tag: api_id || "H2S_" where "H2S_" is an ASCII string
                  composed of 4 bytes.

Procedure:

1. if B is Identity_G1, return INVALID
2. e_octs = BBS.serialize((SK, B))
3. e = BBS.hash_to_scalar(e_octs, signature_dst)
4. A = B * (1 / (SK + e))
5. return BBS.signature_to_octets((A, e))
```

### Core Proof Generation

The Proof Generation with extension, combines the BBS Proof Generation operations (i.e., `BBS.ProofInit` and `BBS.ProofFinalize`) with a proof of correctness of commitments over some of the signed messages. The commitments proof of correctness will similarly constitute of a initialization and finalization phase. The two proof protocols will use a common challenge, returned by the `ProofChallengeCalculate` operation described in (#proof-challenge-calculation). The result of the commitments proof of correctness initialization process will be an object of the following form

```
CommitmentInitRes = {
  commitments: (REQUIRED) Array of points in G1,
  commitments_proofs: (REQUIRED) Array of Scalars,
  commitment_indexes: (REQUIRED) Array of numbers
}
```

<!--Need to enhance to return information use for externally defined ZKPs.-->

Following, we describe the Proof Generation Procedure.


```
[proof, add_zkp_info] = CoreProofGen(PK, signature, generators,
                                     header, ph, messages,
                                     disclosed_indexes,
                                     commitment_indexes, api_id)

Inputs:

- PK (REQUIRED), an octet string of the form outputted by the SkToPk
                 operation.
- signature (REQUIRED), an octet string of the form outputted by the
                        Sign operation.
- generators (REQUIRED), vector of pseudo-random points in G1.
- header (OPTIONAL), an octet string containing context and application
                     specific information. If not supplied, it defaults
                     to the empty octet string ("").
- ph (OPTIONAL), an octet string containing the presentation_header. If
                 not supplied, it defaults to the empty octet
                 string ("").
- messages (OPTIONAL), a vector of scalars representing the messages.
                       If not supplied, it defaults to the empty
                       array ("()").
- disclosed_indexes (OPTIONAL), vector of non-negative integers in
                                ascending order. Indexes of disclosed
                                messages. If not supplied, it defaults
                                to the empty array ("()").
- commitment_indexes (OPTIONAL), vector of non-negative integers in
                                 ascending order. Indexes of committed
                                 messages. If not supplied, it defaults
                                 to the empty array ("()").
- api_id (OPTIONAL), an octet string. If not supplied it defaults to the
                     empty octet string ("").

Parameters:

- Y_0 and Y_1, fixed points of G1 computed as
  (Y_0, Y_1) = BBS.create_generators(2, "COM_DIS_" || api_id)

Outputs:

- proof, an octet string; or INVALID.
- add_zkp_info, a structure containing an array of committed message scalars
                used in committed disclosure, and the array of random scalars
                used to create the respective commitments.

Deserialization:

1. signature_result = octets_to_signature(signature)
2. if signature_result is INVALID, return INVALID
3. (A, e) = signature_result

4.  L = length(messages)
5. if commitment_indexes is not a strictly ascending list of integers
    in 0..L - 1, return INVALID
6. if disclosed_indexes is not a strictly ascending list of integers
    in 0..L - 1, return INVALID
7. if disclosed_indexes and commitment_indexes are not disjoint,
    return INVALID
8.  N = length(commitment_indexes)
9.  R = length(disclosed_indexes)
10. U = L - R
11. (i1, ..., iR) = disclosed_indexes
12. disclosed_messages = (messages[i1], ..., messages[iR])
13. undisclosed_indexes = (0, 1, ..., L - 1) \ disclosed_indexes
14. (j1, ..., jU) = undisclosed_indexes
15. undisclosed_messages = (messages[j1], ..., messages[jU])

Procedure:

1.  init_random_scalars = BBS.calculate_random_scalars(5+U)
2.  (r1, r2, e~, r1~, r3~, m~_j1, ..., m~_jU) =
                                         init_random_scalars
3.  init_res = BBS.ProofInit(PK,
                             signature_result,
                             generators,
                             init_random_scalars,
                             header,
                             messages,
                             undisclosed_indexes,
                             api_id)
4.  if init_res is INVALID, return INVALID


// Calculate the commitments and initiate the correctness proof
5.  (s_1, ..., s_N, s~_1, ..., s~_N) = BBS.calculate_random_scalars(2*N)

6.  for i in (1, 2, ..., N):
7.      idx = commitment_indexes[i]
8.      C_i = Y_0 * s_i + Y_1 * messages[idx]
9.      let k be the integer such that j_k == idx
10.     C~_i = Y_0 * s~_i + Y_1 * m~_k

11. commitment_init_res = {commitments: (C_1, ..., C_N),
                           commitments_proofs: (C~_1, ...,C~_N),
                           commitment_indexes: commitment_indexes}

12. challenge = ProofChallengeCalculate(init_res, commitment_init_res,
                                        disclosed_messages, disclosed_indexes,
                                        ph, api_id)
13. if challenge is INVALID, return INVALID

14. bbs_proof = BBS.ProofFinalize(init_res,
                                  challenge,
                                  e,
                                  init_random_scalars,
                                  undisclosed_messages)

// Finalize the commitment correctness proof
15. for i in (1, 2, ..., N): s^_i =  s~_i + challenge * s_i
16. commitments_proof = ((C_1, ..., C_N), (s^_1, ..., s^_N))

17. proof = proof_to_octets(length(bbs_proof), bbs_proof,
                           N, commitments_proof)
18. add_zkp_info = {committed_message_scalars:
                       (messages[commitment_indexes[1]], ...,
                        messages[commitment_indexes[N]]),
                    commitment_rands: (s_1, ..., s_N)}
19. return [proof, add_zkp_info]
```

### Core Proof Verification

```
result = CoreProofVerify(PK, proof, generators, header, ph,
                         disclosed_messages, disclosed_indexes,
                         commitment_indexes, api_id)

Inputs:

- PK (REQUIRED), an octet string of the form outputted by the SkToPk
                 operation.
- proof (REQUIRED), an octet string of the form outputted by the
                        ProofGen operation.
- generators (REQUIRED), vector of pseudo-random points in G1.
- header (OPTIONAL), an optional octet string containing context and
                     application specific information. If not supplied,
                     it defaults to the empty octet string ("").
- ph (OPTIONAL), an octet string containing the presentation_header. If
                 not supplied, it defaults to the empty octet
                 string ("").
- disclosed_messages (OPTIONAL), a vector of scalars representing the
                                 messages. If not supplied, it defaults
                                 to the empty array ("()").
- disclosed_indexes (OPTIONAL), vector of non-negative integers in
                                ascending order. Indexes of disclosed
                                messages. If not supplied, it defaults
                                to the empty array ("()").
- commitment_indexes (OPTIONAL), vector of non-negative integers in
                                 ascending order. Indexes of committed
                                 messages. If not supplied, it defaults
                                 to the empty array ("()").
- api_id (OPTIONAL), an octet string. If not supplied it defaults to the
                     empty octet string ("").

Parameters:

- Y_0 and Y_1, fixed points of G1 computed as (Y_0, Y_1) = BBS.create_generators(2, "COM_DIS_" || api_id)
- BP2, fixed point of G2, defined by the ciphersuite.

Outputs:

- result, either VALID or INVALID.

Deserialization:

1.  W = octets_to_pubkey(PK)
2.  if W is INVALID, return INVALID

3.  proof_res = octets_to_proof(proof)
4.  if proof_res is INVALID, return INVALID
5.  (bbs_proof_res, commitments_proof_res) = proof_res

6.  (Abar, Bbar, D, e^, r1^, r3^, hats, cp) = bbs_proof_res
7.  (commitments, commitments_proof) = commitments_proof_res

8.  N = length(commitments)
9.  if length(commitments_proof) != N, return INVALID
10. if length(commitment_indexes) != N, return INVALID
11. U = length(hats)
12. R = length(disclosed_indexes)
13. if length(disclosed_messages) != R, return INVALID
14. L = R + U

15. if commitment_indexes is not a strictly ascending list of integers
    in 0..L - 1, return INVALID

16. if disclosed_indexes is not a strictly ascending list of integers
    in 0..L - 1, return INVALID

17. if disclosed_indexes and commitment_indexes are not disjoint,
    return INVALID

18. undisclosed_indexes = (0, 1, ..., L - 1) \ disclosed_indexes
19. (j1, ..., jU) = undisclosed_indexes
20. (m^_j1, ..., m^_jU) = hats
21. (C_1, ... C_N) = commitments
22. (s^_1, ..., s^_N) = commitments_proof

Procedure:

1.  init_res = BBS.ProofVerifyInit(PK, bbs_proof_res, generators, header,
                                                   disclosed_messages,
                                                   disclosed_indexes,
                                                   api_id)
2.  if init_res is INVALID, return INVALID

3.  for i in (1, 2, ..., N):
4.      idx = commitment_indexes[i]
5.      let k be the integer such that j_k == idx
6.      C^_i = Y_0 * s^_i + Y_1 * m^_k - C_i * cp

7.  commitment_init_res = {commitments: (C_1, ..., C_N),
                           commitments_proofs: (C^_1, ...,C^_N),
                           commitment_indexes: commitment_indexes}

8.  challenge = ProofChallengeCalculate(init_res, commitment_init_res,
                                        disclosed_messages, disclosed_indexes,
                                        ph, api_id)
9.  if challenge is INVALID, return INVALID

10. if cp != challenge, return INVALID
11. if e(Abar, W) * e(Bbar, -BP2) != Identity_GT, return INVALID
12. return VALID
```

# Utilities

## Calculate B value

```
res  = B_calculate(PK, generators, blind_generators, commitment,
                   message_scalars, header, api_id)

Inputs:

- PK (REQUIRED), an octet string of the form outputted by the SkToPk
                 operation.
- generators (REQUIRED), an array of at least one point from the
                         G1 group.
- blind_generators (OPTIONAL), vector of pseudo-random points in G1. If
                               not supplied it defaults to the empty
                               array.
- commitment (OPTIONAL), a point from the G1 group. If not supplied it
                         defaults to the Identity_G1 point.
- message_scalars (OPTIONAL), an array of scalar values. If not
                              supplied, it defaults to the empty
                              array ("()").
- header (OPTIONAL), an octet string containing context and application
                     specific information. If not supplied, it defaults
                     to an empty string.
- api_id (OPTIONAL), an octet string. If not supplied it defaults to the
                     empty octet string ("").

Parameters:

- P1, fixed point of G1, defined by the ciphersuite.

Outputs:

- res, an array of a single element from the G1 subgroup, or INVALID.

Deserialization:

1. L = length(message_scalars)
2. M = length(blind_generators) - 1
3. if length(generators) != L + 1, return INVALID
4. if M < 0, return INVALID
5. (Q_1, H_1, ..., H_L) = generators
6. (msg_1, ..., msg_L) = message_scalars
7. (Q_2, J_1, ..., J_M) = blind_generators

Procedure:

1. domain = BBS.calculate_domain(PK, Q_1, (H_1, ..., H_L, Q_2, J_1, ..., J_M),
                                                         header, api_id)
2. B = P1 + Q_1 * domain + H_1 * msg_1 + ... + H_L * msg_L + commitment
3. if B is Identity_G1, return INVALID
4. return (B)
```

## Blind Challenge Calculation

```
challenge = calculate_blind_challenge(C, Cbar, generators, api_id)

Inputs:

- C (REQUIRED), a point of G1.
- Cbar (REQUIRED), a point of G1.
- generators (REQUIRED), an array of points from G1, of length at
                         least 1.
- api_id (OPTIONAL), octet string. If not supplied it defaults to the
                     empty octet string ("").

Definition:

- blind_challenge_dst, an octet string representing the domain
                       separation tag: api_id || "H2S_" where "H2S_" is
                       an ASCII string composed of 4 bytes.

Deserialization:

1. if length(generators) == 0, return INVALID
2. M = length(generators) - 1

Procedure:

1. c_arr = (M)
2. c_arr.append(generators)
3. c_octs = BBS.serialize(c_arr.append(C, Cbar))
4. return BBS.hash_to_scalar(c_octs, blind_challenge_dst)
```

## Proof Challenge Calculation

```
challenge = ProofChallengeCalculate(init_res, commitment_init_res,
                                    disclosed_messages, disclosed_indexes,
                                    ph, api_id)

Inputs:
- init_res (REQUIRED), a ProofInitRes object representing the value
                       returned after initializing the proof generation
                       or verification operations.
- commitment_init_res (REQUIRED), a CommitmentInitRes representing the value
                                 returned after initializing the commitments
                                 proof of correctness generation or
                                 verification.
- disclosed_messages (OPTIONAL), a vector of scalars representing the
                                 messages. If not supplied, it defaults
                                 to the empty array ("()").
- disclosed_indexes (OPTIONAL), vector of non-negative integers in
                                ascending order. Indexes of disclosed
                                messages. If not supplied, it defaults
                                to the empty array ("()").
- ph (OPTIONAL), an octet string. If not supplied, it must default to
                 the empty octet string ("").
- api_id (OPTIONAL), an octet string. If not supplied it defaults to the
                     empty octet string ("").

Outputs:

- challenge, a scalar.

Definitions:

1. hash_to_scalar_dst, an octet string representing the domain
                       separation tag: api_id || "H2S_" where "H2S_" is
                       an ASCII string comprised of 4 bytes.

Deserialization:

1.  (Abar, Bbar, D, T1, T2, domain) = (init_res.Abar,
                                       init_res.Bbar,
                                       init_res.D,
                                       init_res.T1,
                                       init_res.T2,
                                       init_res.domain)

2.  R = length(disclosed_indexes)
3.  (i1, ..., iR) = disclosed_indexes
4. if length(disclosed_messages) != R, return INVALID
5.  (msg_i1, ..., msg_iR) = disclosed_messages

6.  N = length(commitment_init_res.commitments)
7.  if length(commitment_init_res.commitments_proofs) != N, return INVALID
8.  if length(commitment_init_res.commitment_indexes) != N, return INVALID
9.  (C_1, ..., C_N) = commitment_init_res.commitments
10. (C~_1, ...,C~_N) = commitment_init_res.commitments_proofs
11. (i_1, ..., i_N) = commitment_init_res.commitment_indexes

ABORT if:

1. R > 2^64 - 1
2. length(ph) > 2^64 - 1

Procedure:

1. c_arr = (R, i1, msg_i1, i2, msg_i2, ..., iR, msg_iR, Abar, Bbar,
                                                      D, T1, T2, domain)
2. c_octs = BBS.serialize(c_arr)

3. commitment_arr = (N, i_1, C_1, C~_1, ..., i_N, C_N, C~_N)
4. c_octs = c_octs || BBS.serialize(commitment_arr)

5. c_octs = c_octs || I2OSP(length(ph), 8) || ph
6. return BBS.hash_to_scalar(c_octs, hash_to_scalar_dst)
```

## Serialize

### Commitment with Proof to Octets

```
commitment_octets = commitment_with_proof_to_octets(commitment, proof)

Inputs:

- commitment (REQUIRED), a point of G1.
- proof (REQUIRED), a vector comprising of a scalar, a possibly empty
                    vector of scalars and another scalar in that order.

Outputs:

- commitment_octets, an octet string or INVALID.

Procedure:

1. commitment_octs = BBS.serialize((commitment))
2. if commitment_octs is INVALID, return INVALID
3. (s^, (m^_1, ..., m^_M), challenge) = proof
4. proof_octs = BBS.serialize((s^, m^_1, ..., m^_M, challenge))
5. if proof_octs is INVALID, return INVALID
6. return commitment_octs || proof_octs
```

### Octets to Commitment with Proof

```
commitment = octets_to_commitment_with_proof(commitment_octs)

Inputs:

- commitment_octs (REQUIRED), an octet string in the form outputted from
                              the commitment_to_octets operation.

Parameters:

- (octet_point_length, octet_scalar_length), defined by the ciphersuite.

Outputs:

- commitment, a commitment in the form (C, proof), where C a point of G1
              and a proof vector comprising of a scalar, a possibly
              empty vector of scalars and another scalar in that order.

Procedure:

1.  commitment_len_floor = octet_point_length + 2 * octet_scalar_length
2.  if length(commitment_octs) < commitment_len_floor, return INVALID

3.  C_octets = commitment_octs[0..(octet_point_length - 1)]
4.  C = octets_to_point_E1(C_octets)
5.  if C is INVALID, return INVALID
6.  if C == Identity_G1, return INVALID

7.  j = 0
8.  index = octet_point_length
9.  while index < length(commitment_octs):
10.     end_index = index + octet_scalar_length - 1
11.     s_j = OS2IP(commitment_octs[index..end_index])
12.     if s_j = 0 or if s_j >= r, return INVALID
13.     index += octet_scalar_length
14.     j += 1

15. if index != length(commitment_octs), return INVALID
16. if j < 2, return INVALID
17. msg_commitments = ()
18. if j >= 3, set msg_commitments = (s_1, ..., s_(j-2))
19. return (C, (s_0, msg_commitments, s_(j-1)))
```

### Proof to Octets

```
proof_octets = proof_to_octets(bbs_proof_len, bbs_proof_octs,
                               commitments_count, commitments_proof)

Inputs:

- bbs_proof_len (REQUIRED), a non negative integer.
- bbs_proof_octs (REQUIRED), an octet string.
- commitments_count (REQUIRED), a non negative integer.
- commitments_proof (REQUIRED), a tuple with two arrays, the first with
                                points in G1 and the second with Scalars

Outputs:

- proof_octets, an octet string.

Procedure:

1. oct = I2OSP(bbs_proof_len, 8) || bbs_proof_octs ||
         I2OSP(commitments_count, 8) || BBS.serialize(commitments_proof)
2. return oct

```

### Octets to Proof

The `octets_to_proof` procedure, on input an octet string will return a BBS proof with commitments proof comprised from the following elements

1. A BBS Proof
2. A tuple with two arrays. One array of points in G1, corresponding to the message commitments and one array with scalars, corresponding to the proof of correctness of the previous commitments.

```
proof = octets_to_proof(proof_octets)

- proof_octets (REQUIRED), an octet string of the form outputted from
                           the proof_to_octets operation.

Parameters:

- int_octet_length = 8. The number of octets of encoded integers.
- r, non-negative integer. The prime order of the G1 and G2 groups,
      defined by the ciphersuite.
- octet_scalar_length, non-negative integer. The length of a scalar
                       octet representation, defined by the ciphersuite.
- octet_point_length, non-negative integer. The length of a point in G1
                      octet representation, defined by the ciphersuite.
- subgroup_check_G1, operation that on input a point P returns VALID if
                     P is a valid point of the G1 subgroup, otherwise it
                     returns INVALID (see (#notation)).

Outputs:

- proof, a proof value in the form described above or INVALID

Procedure:

1.  sidx = 0
2.  eidx = int_octet_length - 1
3.  if length(proof_octets) < eidx, return INVALID
4.  bbs_proof_len = OS2IP(proof_octets[sidx, ..., eidx])

5.  sidx = eidx + 1
6.  eidx = sidx + bbs_proof_len
7.  if length(proof_octets) < eidx, return INVALID
8.  bbs_proof_octs = proof_octets[sidx, ..., eidx]
9.  bbs_proof = BBS.octets_to_proof(bbs_proof_octs)
10. if bbs_proof is INVALID, return INVALID

// Deserialize commitments_proof
11. sidx = eidx + 1
12. eidx = sidx + int_octet_length
13. if length(proof_octets) < eidx, return INVALID
14. N = OS2IP(proof_octets[sidx, ..., eidx]) // commitments count

15. len_floor = eidx + N * (octet_point_length + octet_scalar_length)
16. if length(proof_octets) < len_floor, return INVALID

17. for i in (1..N)
18.     sidx = eidx + 1
19.     eidx = sidx + octet_point_length
20.     C_i = BBS.octets_to_point_E1(proof_octets[sidx, ..., eidx])
21.     if C_i is INVALID or Identity_G1, return INVALID
22.     if subgroup_check_G1(C_i) returns INVALID, return INVALID

23. for i in (1..N)
24.     sidx = eidx + 1
25.     eidx = sidx + octet_scalar_length
26.     s_i = OS2IP(proof_octets[sidx, ..., eidx])
27.     if s_i = 0 or if s_i >= r, return INVALID

28. commitments_proof = ((C_1, ..., C_N), (s_1, ..., s_N))

29. if length(proof_octets) not equal to eidx, return INVALID
30. return (bbs_proof, commitments_proof)
```

# Privacy Considerations

The privacy considerations discussed in [@!I-D.irtf-cfrg-bbs-signatures, section 5] apply to this draft as well.

## Total Number and Index of Committed Messages

When a Prover submits a commitment to the Signer, the Prover's committed messages are "perfectly" (statistically) hidden from the Signer. However, the proof of the committed messages, which is also sent from the Prover to the Signer, contains the number of committed messages.

In the proof sent from the Prover to the Verifier the number of committed messages can be inferred. In addition, indexes of disclosed and committed messages are revealed to the Verifier. In [@!I-D.irtf-cfrg-bbs-signatures, section 5.2] the threats to unlinkability and mitigations for this information with respect to Signer messages is discussed. These threats and mitigations apply to the Prover total number of committed messages and the disclosed and committed indexes as well.

# Application Considerations

## Input Validity Checks

Applications using `CoreProofGen` (as defined in (#core-proof-generation)) only as a subroutine of `BlindProofGen` (as defined in (#proof-generation)), or `CoreProofVerify` (as defined in (#core-proof-verification)) only as a subroutine of `BlindProofVerify` (as defined in (#proof-verification)), can skip the checks of the `commitment_indexes` and `disclosed_indexes` inputs performed in the corresponding core operation, since the inputs provided by the calling operation will always have the correct form. However, if applications intend to use either core operation in different contexts, those checks must be applied.

# Security Considerations

Security considerations detailed in [@!I-D.irtf-cfrg-bbs-signatures, section 6] apply to this draft as well.

## Prover Blind Factor

The random scalar value `secret_prover_blind` calculated and returned by the `Commit` operation is responsible for "hiding" the committed messages (otherwise, in many practical applications, the Signer may be able to retrieve them). Furthermore, it guarantees that the entity generating the BBS proof (see `BlindProofGen` defined in (#proof-generation)) has knowledge of that factor. As a result, the `secret_prover_blind` MUST remain private by the Prover and it MUST be generated using a cryptographically secure pseudo-random number generator. See [@!I-D.irtf-cfrg-bbs-signatures, section 6.7] on recommendations and requirements for implementing the `BBS.calculate_random_scalars` operation (which is used to calculate the `secret_prover_blind` value).

## Key Binding

One natural use case for the blind signatures extension of the BBS scheme is key binding. In the context of BBS Signatures, key binding guarantees that only entities in control of a specific private key can compute BBS proofs. This can be achieved by committing to the private key prior to issuance, resulting in a BBS signature that includes that key as one of the signed messages. Creating a BBS proof from that signature will then require knowledge of that key (similar to any signed message). The Prover MUST NOT disclose that key as part of a proof generation procedure. Note also that the `secret_prover_blind` value returned by the `Commit` operation defined in (#commitment-computation) (see (#prover-blind-factor)), has a similar property, i.e., it's knowledge is required to generate a proof from a blind signature. Many applications however, requiring key binding, mandate that the same private key is used among multiple signatures, whereas the `secret_prover_blind` is uniquely generated for each blind signature issuance request. In those cases, a commitment to a private key must be used, as described above.

# Ciphersuites

This document uses the `BBS_BLS12381G1_XOF:SHAKE-256_SSWU_RO_` and `BBS_BLS12381G1_XMD:SHA-256_SSWU_RO_` defined in [@!I-D.irtf-cfrg-bbs-signatures, section 7.2.1] and [@!I-D.irtf-cfrg-bbs-signatures, section 7.2.2] correspondingly.

# Test Vectors

Test vectors are being revised to include new committed disclosure functionality.

<!--

## BLS12-381-SHA-256

### Generators

```
api_id = {{ $generatorFixtures.bls12-381-sha-256.generators.api_id }}

P1 = {{ $generatorFixtures.bls12-381-sha-256.generators.P1 }}
Q1 = {{ $generatorFixtures.bls12-381-sha-256.generators.Q1 }}

Generators = {

H_0 = {{ $generatorFixtures.bls12-381-sha-256.generators.MsgGenerators[0] }}
H_1 = {{ $generatorFixtures.bls12-381-sha-256.generators.MsgGenerators[1] }}
H_2 = {{ $generatorFixtures.bls12-381-sha-256.generators.MsgGenerators[2] }}
H_3 = {{ $generatorFixtures.bls12-381-sha-256.generators.MsgGenerators[3] }}
H_4 = {{ $generatorFixtures.bls12-381-sha-256.generators.MsgGenerators[4] }}
H_5 = {{ $generatorFixtures.bls12-381-sha-256.generators.MsgGenerators[5] }}
H_6 = {{ $generatorFixtures.bls12-381-sha-256.generators.MsgGenerators[6] }}
H_7 = {{ $generatorFixtures.bls12-381-sha-256.generators.MsgGenerators[7] }}
H_8 = {{ $generatorFixtures.bls12-381-sha-256.generators.MsgGenerators[8] }}
H_9 = {{ $generatorFixtures.bls12-381-sha-256.generators.MsgGenerators[9] }}

}
```

### Blind Generators

```
api_id = {{ $generatorFixtures.bls12-381-sha-256.blindGenerators.api_id }}

P1 = {{ $generatorFixtures.bls12-381-sha-256.blindGenerators.P1 }}
Q1 = {{ $generatorFixtures.bls12-381-sha-256.blindGenerators.Q1 }}

Blind Generators = {

J_0 = {{ $generatorFixtures.bls12-381-sha-256.blindGenerators.MsgGenerators[0] }}
J_1 = {{ $generatorFixtures.bls12-381-sha-256.blindGenerators.MsgGenerators[1] }}
J_2 = {{ $generatorFixtures.bls12-381-sha-256.blindGenerators.MsgGenerators[2] }}
J_3 = {{ $generatorFixtures.bls12-381-sha-256.blindGenerators.MsgGenerators[3] }}
J_4 = {{ $generatorFixtures.bls12-381-sha-256.blindGenerators.MsgGenerators[4] }}

}
```

### Commitment

Mocked random scalar parameters

```
seed = {{ $commitmentFixtures.bls12-381-sha-256.commit001.mockRngParameters.SEED }}
dst = {{ $commitmentFixtures.bls12-381-sha-256.commit001.mockRngParameters.commit.DST }}
```

#### valid no committed messages commitment with proof

```
committedMessages = {{ $commitmentFixtures.bls12-381-sha-256.commit001.committedMessages }}
proverBlind = {{ $commitmentFixtures.bls12-381-sha-256.commit001.proverBlind }}

Trace:

s_tilde = {{ $commitmentFixtures.bls12-381-sha-256.commit001.trace.random_scalars.s_tilde }}
m_tildes = {{ $commitmentFixtures.bls12-381-sha-256.commit001.trace.random_scalars.m_tildes }}

commitmentWithProof = {{ $commitmentFixtures.bls12-381-sha-256.commit001.commitmentWithProof }}
```

#### valid multiple committed messages commitment with proof

```
committedMessages = {{ $commitmentFixtures.bls12-381-sha-256.commit002.committedMessages }}
proverBlind = {{ $commitmentFixtures.bls12-381-sha-256.commit002.proverBlind }}

Trace:

s_tilde = {{ $commitmentFixtures.bls12-381-sha-256.commit002.trace.random_scalars.s_tilde }}
m_tildes = {{ $commitmentFixtures.bls12-381-sha-256.commit002.trace.random_scalars.m_tildes }}

commitmentWithProof = {{ $commitmentFixtures.bls12-381-sha-256.commit002.commitmentWithProof }}
```

### Signature Test Vectors

#### valid no prover committed messages, no signer messages signature

```
secretKey = {{ $signatureFixtures.bls12-381-sha-256.signature001.signerKeyPair.secretKey }}
publicKey = {{ $signatureFixtures.bls12-381-sha-256.signature001.signerKeyPair.publicKey }}

header = {{ $signatureFixtures.bls12-381-sha-256.signature001.header }}
messages = {{ $signatureFixtures.bls12-381-sha-256.signature001.messages }}

commitmentWithProof = {{ $signatureFixtures.bls12-381-sha-256.signature001.commitmentWithProof }}

committedMessages = {{ $signatureFixtures.bls12-381-sha-256.signature001.committedMessages }}

proverBlind = {{ $signatureFixtures.bls12-381-sha-256.signature001.proverBlind }}

Trace:

B = {{ $signatureFixtures.bls12-381-sha-256.signature001.trace.B }}
domain = {{ $signatureFixtures.bls12-381-sha-256.signature001.trace.domain }}

signature = {{ $signatureFixtures.bls12-381-sha-256.signature001.signature }}
```

#### valid multi prover committed messages, no signer messages signature

```
secretKey = {{ $signatureFixtures.bls12-381-sha-256.signature002.signerKeyPair.secretKey }}
publicKey = {{ $signatureFixtures.bls12-381-sha-256.signature002.signerKeyPair.publicKey }}

header = {{ $signatureFixtures.bls12-381-sha-256.signature002.header }}
messages = {{ $signatureFixtures.bls12-381-sha-256.signature002.messages }}

commitmentWithProof = {{ $signatureFixtures.bls12-381-sha-256.signature002.commitmentWithProof }}

committedMessages = {{ $signatureFixtures.bls12-381-sha-256.signature002.committedMessages }}

proverBlind = {{ $signatureFixtures.bls12-381-sha-256.signature002.proverBlind }}

Trace:

B = {{ $signatureFixtures.bls12-381-sha-256.signature002.trace.B }}
domain = {{ $signatureFixtures.bls12-381-sha-256.signature002.trace.domain }}

signature = {{ $signatureFixtures.bls12-381-sha-256.signature002.signature }}
```

#### valid no prover committed messages, multiple signer messages signature

```
secretKey = {{ $signatureFixtures.bls12-381-sha-256.signature003.signerKeyPair.secretKey }}
publicKey = {{ $signatureFixtures.bls12-381-sha-256.signature003.signerKeyPair.publicKey }}

header = {{ $signatureFixtures.bls12-381-sha-256.signature003.header }}
messages = {{ $signatureFixtures.bls12-381-sha-256.signature003.messages }}

commitmentWithProof = {{ $signatureFixtures.bls12-381-sha-256.signature003.commitmentWithProof }}

committedMessages = {{ $signatureFixtures.bls12-381-sha-256.signature003.committedMessages }}

proverBlind = {{ $signatureFixtures.bls12-381-sha-256.signature003.proverBlind }}

Trace:

B = {{ $signatureFixtures.bls12-381-sha-256.signature003.trace.B }}
domain = {{ $signatureFixtures.bls12-381-sha-256.signature003.trace.domain }}

signature = {{ $signatureFixtures.bls12-381-sha-256.signature003.signature }}
```

#### valid multiple signer and prover committed messages signature

```
secretKey = {{ $signatureFixtures.bls12-381-sha-256.signature004.signerKeyPair.secretKey }}
publicKey = {{ $signatureFixtures.bls12-381-sha-256.signature004.signerKeyPair.publicKey }}

header = {{ $signatureFixtures.bls12-381-sha-256.signature004.header }}
messages = {{ $signatureFixtures.bls12-381-sha-256.signature004.messages }}

commitmentWithProof = {{ $signatureFixtures.bls12-381-sha-256.signature004.commitmentWithProof }}

committedMessages = {{ $signatureFixtures.bls12-381-sha-256.signature004.committedMessages }}

proverBlind = {{ $signatureFixtures.bls12-381-sha-256.signature004.proverBlind }}

Trace:

B = {{ $signatureFixtures.bls12-381-sha-256.signature004.trace.B }}
domain = {{ $signatureFixtures.bls12-381-sha-256.signature004.trace.domain }}

signature = {{ $signatureFixtures.bls12-381-sha-256.signature004.signature }}
```

#### valid no commitment signature

```
secretKey = {{ $signatureFixtures.bls12-381-sha-256.signature005.signerKeyPair.secretKey }}
publicKey = {{ $signatureFixtures.bls12-381-sha-256.signature005.signerKeyPair.publicKey }}

header = {{ $signatureFixtures.bls12-381-sha-256.signature005.header }}
messages = {{ $signatureFixtures.bls12-381-sha-256.signature005.messages }}

commitmentWithProof = {{ $signatureFixtures.bls12-381-sha-256.signature005.commitmentWithProof }}

committedMessages = {{ $signatureFixtures.bls12-381-sha-256.signature005.committedMessages }}

proverBlind = {{ $signatureFixtures.bls12-381-sha-256.signature005.proverBlind }}

Trace:

B = {{ $signatureFixtures.bls12-381-sha-256.signature005.trace.B }}
domain = {{ $signatureFixtures.bls12-381-sha-256.signature005.trace.domain }}

signature = {{ $signatureFixtures.bls12-381-sha-256.signature005.signature }}
```

### Proof Test Vectors

Mocked random scalar parameters

```
seed = {{ $proofFixtures.bls12-381-sha-256.proof001.mockRngParameters.SEED }}
dst = {{ $proofFixtures.bls12-381-sha-256.proof001.mockRngParameters.proof.DST }}
```

#### valid all prover committed messages and signer messages revealed proof

```
signerPublicKey = {{ $proofFixtures.bls12-381-sha-256.proof001.signerPublicKey }}
signature = {{ $proofFixtures.bls12-381-sha-256.proof001.signature }}

commitmentWithProof = {{ $proofFixtures.bls12-381-sha-256.proof001.commitmentWithProof }}
proverBlind = {{ $proofFixtures.bls12-381-sha-256.proof001.proverBlind }}

header = {{ $proofFixtures.bls12-381-sha-256.proof001.header }}
presentationHeader =  {{ $proofFixtures.bls12-381-sha-256.proof001.presentationHeader }}

revealedMessages =

0: {{ $proofFixtures.bls12-381-sha-256.proof001.revealedMessages[0] }}
1: {{ $proofFixtures.bls12-381-sha-256.proof001.revealedMessages[1] }}
2: {{ $proofFixtures.bls12-381-sha-256.proof001.revealedMessages[2] }}
3: {{ $proofFixtures.bls12-381-sha-256.proof001.revealedMessages[3] }}
4: {{ $proofFixtures.bls12-381-sha-256.proof001.revealedMessages[4] }}
5: {{ $proofFixtures.bls12-381-sha-256.proof001.revealedMessages[5] }}
6: {{ $proofFixtures.bls12-381-sha-256.proof001.revealedMessages[6] }}
7: {{ $proofFixtures.bls12-381-sha-256.proof001.revealedMessages[7] }}
8: {{ $proofFixtures.bls12-381-sha-256.proof001.revealedMessages[8] }}
9: {{ $proofFixtures.bls12-381-sha-256.proof001.revealedMessages[9] }}


revealedCommittedMessages  =

0: {{ $proofFixtures.bls12-381-sha-256.proof001.revealedCommittedMessages[0] }}
1: {{ $proofFixtures.bls12-381-sha-256.proof001.revealedCommittedMessages[1] }}
2: {{ $proofFixtures.bls12-381-sha-256.proof001.revealedCommittedMessages[2] }}
3: {{ $proofFixtures.bls12-381-sha-256.proof001.revealedCommittedMessages[3] }}
4: {{ $proofFixtures.bls12-381-sha-256.proof001.revealedCommittedMessages[4] }}

Trace:

random_scalars:

r_1 = {{ $proofFixtures.bls12-381-sha-256.proof001.trace.random_scalars.r1 }}
r_2 = {{ $proofFixtures.bls12-381-sha-256.proof001.trace.random_scalars.r2 }}
e_tilde = {{ $proofFixtures.bls12-381-sha-256.proof001.trace.random_scalars.e_tilde }}
r1_tilde = {{ $proofFixtures.bls12-381-sha-256.proof001.trace.random_scalars.r1_tilde }}
r3_tilde = {{ $proofFixtures.bls12-381-sha-256.proof001.trace.random_scalars.r3_tilde }}
m_tilde_scalars = {{ $proofFixtures.bls12-381-sha-256.proof001.trace.random_scalars.m_tilde_scalars }}

domain = {{ $proofFixtures.bls12-381-sha-256.proof001.trace.domain }}
challenge = {{ $proofFixtures.bls12-381-sha-256.proof001.trace.challenge }}


L = {{ $proofFixtures.bls12-381-sha-256.proof001.L }}

proof = {{ $proofFixtures.bls12-381-sha-256.proof001.proof }}
```

#### valid half prover committed messages and all signer messages revealed proof

```
signerPublicKey = {{ $proofFixtures.bls12-381-sha-256.proof002.signerPublicKey }}
signature = {{ $proofFixtures.bls12-381-sha-256.proof002.signature }}

commitmentWithProof = {{ $proofFixtures.bls12-381-sha-256.proof002.commitmentWithProof }}
proverBlind = {{ $proofFixtures.bls12-381-sha-256.proof002.proverBlind }}

header = {{ $proofFixtures.bls12-381-sha-256.proof002.header }}
presentationHeader =  {{ $proofFixtures.bls12-381-sha-256.proof002.presentationHeader }}

revealedMessages =

0: {{ $proofFixtures.bls12-381-sha-256.proof002.revealedMessages[0] }}
1: {{ $proofFixtures.bls12-381-sha-256.proof002.revealedMessages[1] }}
2: {{ $proofFixtures.bls12-381-sha-256.proof002.revealedMessages[2] }}
3: {{ $proofFixtures.bls12-381-sha-256.proof002.revealedMessages[3] }}
4: {{ $proofFixtures.bls12-381-sha-256.proof002.revealedMessages[4] }}
5: {{ $proofFixtures.bls12-381-sha-256.proof002.revealedMessages[5] }}
6: {{ $proofFixtures.bls12-381-sha-256.proof002.revealedMessages[6] }}
7: {{ $proofFixtures.bls12-381-sha-256.proof002.revealedMessages[7] }}
8: {{ $proofFixtures.bls12-381-sha-256.proof002.revealedMessages[8] }}
9: {{ $proofFixtures.bls12-381-sha-256.proof002.revealedMessages[9] }}


revealedCommittedMessages  =

0: {{ $proofFixtures.bls12-381-sha-256.proof002.revealedCommittedMessages[0] }}
2: {{ $proofFixtures.bls12-381-sha-256.proof002.revealedCommittedMessages[2] }}
4: {{ $proofFixtures.bls12-381-sha-256.proof002.revealedCommittedMessages[4] }}

Trace:

random_scalars:

r_1 = {{ $proofFixtures.bls12-381-sha-256.proof002.trace.random_scalars.r1 }}
r_2 = {{ $proofFixtures.bls12-381-sha-256.proof002.trace.random_scalars.r2 }}
e_tilde = {{ $proofFixtures.bls12-381-sha-256.proof002.trace.random_scalars.e_tilde }}
r1_tilde = {{ $proofFixtures.bls12-381-sha-256.proof002.trace.random_scalars.r1_tilde }}
r3_tilde = {{ $proofFixtures.bls12-381-sha-256.proof002.trace.random_scalars.r3_tilde }}
m_tilde_scalars = {{ $proofFixtures.bls12-381-sha-256.proof002.trace.random_scalars.m_tilde_scalars }}

domain = {{ $proofFixtures.bls12-381-sha-256.proof002.trace.domain }}
challenge = {{ $proofFixtures.bls12-381-sha-256.proof002.trace.challenge }}

L = {{ $proofFixtures.bls12-381-sha-256.proof002.L }}

proof = {{ $proofFixtures.bls12-381-sha-256.proof002.proof }}
```

#### valid half prover committed messages and all signer messages revealed proof

```
signerPublicKey = {{ $proofFixtures.bls12-381-sha-256.proof003.signerPublicKey }}
signature = {{ $proofFixtures.bls12-381-sha-256.proof003.signature }}

commitmentWithProof = {{ $proofFixtures.bls12-381-sha-256.proof003.commitmentWithProof }}
proverBlind = {{ $proofFixtures.bls12-381-sha-256.proof003.proverBlind }}

header = {{ $proofFixtures.bls12-381-sha-256.proof003.header }}
presentationHeader =  {{ $proofFixtures.bls12-381-sha-256.proof003.presentationHeader }}

revealedMessages =

0: {{ $proofFixtures.bls12-381-sha-256.proof003.revealedMessages[0] }}
2: {{ $proofFixtures.bls12-381-sha-256.proof003.revealedMessages[2] }}
4: {{ $proofFixtures.bls12-381-sha-256.proof003.revealedMessages[4] }}
6: {{ $proofFixtures.bls12-381-sha-256.proof003.revealedMessages[6] }}
8: {{ $proofFixtures.bls12-381-sha-256.proof003.revealedMessages[8] }}


revealedCommittedMessages  =

0: {{ $proofFixtures.bls12-381-sha-256.proof003.revealedCommittedMessages[0] }}
1: {{ $proofFixtures.bls12-381-sha-256.proof003.revealedCommittedMessages[1] }}
2: {{ $proofFixtures.bls12-381-sha-256.proof003.revealedCommittedMessages[2] }}
3: {{ $proofFixtures.bls12-381-sha-256.proof003.revealedCommittedMessages[3] }}
4: {{ $proofFixtures.bls12-381-sha-256.proof003.revealedCommittedMessages[4] }}

Trace:

random_scalars:

r_1 = {{ $proofFixtures.bls12-381-sha-256.proof003.trace.random_scalars.r1 }}
r_2 = {{ $proofFixtures.bls12-381-sha-256.proof003.trace.random_scalars.r2 }}
e_tilde = {{ $proofFixtures.bls12-381-sha-256.proof003.trace.random_scalars.e_tilde }}
r1_tilde = {{ $proofFixtures.bls12-381-sha-256.proof003.trace.random_scalars.r1_tilde }}
r3_tilde = {{ $proofFixtures.bls12-381-sha-256.proof003.trace.random_scalars.r3_tilde }}
m_tilde_scalars = {{ $proofFixtures.bls12-381-sha-256.proof003.trace.random_scalars.m_tilde_scalars }}

domain = {{ $proofFixtures.bls12-381-sha-256.proof003.trace.domain }}
challenge = {{ $proofFixtures.bls12-381-sha-256.proof003.trace.challenge }}

L = {{ $proofFixtures.bls12-381-sha-256.proof003.L }}

proof = {{ $proofFixtures.bls12-381-sha-256.proof003.proof }}
```

#### valid half prover committed messages and half signer messages revealed proof

```
signerPublicKey = {{ $proofFixtures.bls12-381-sha-256.proof004.signerPublicKey }}
signature = {{ $proofFixtures.bls12-381-sha-256.proof004.signature }}

commitmentWithProof = {{ $proofFixtures.bls12-381-sha-256.proof004.commitmentWithProof }}
proverBlind = {{ $proofFixtures.bls12-381-sha-256.proof004.proverBlind }}

header = {{ $proofFixtures.bls12-381-sha-256.proof004.header }}
presentationHeader =  {{ $proofFixtures.bls12-381-sha-256.proof004.presentationHeader }}

revealedMessages =

0: {{ $proofFixtures.bls12-381-sha-256.proof004.revealedMessages[0] }}
2: {{ $proofFixtures.bls12-381-sha-256.proof004.revealedMessages[2] }}
4: {{ $proofFixtures.bls12-381-sha-256.proof004.revealedMessages[4] }}
6: {{ $proofFixtures.bls12-381-sha-256.proof004.revealedMessages[6] }}
8: {{ $proofFixtures.bls12-381-sha-256.proof004.revealedMessages[8] }}


revealedCommittedMessages  =

0: {{ $proofFixtures.bls12-381-sha-256.proof004.revealedCommittedMessages[0] }}
2: {{ $proofFixtures.bls12-381-sha-256.proof004.revealedCommittedMessages[2] }}
4: {{ $proofFixtures.bls12-381-sha-256.proof004.revealedCommittedMessages[4] }}


Trace:

random_scalars:

r_1 = {{ $proofFixtures.bls12-381-sha-256.proof004.trace.random_scalars.r1 }}
r_2 = {{ $proofFixtures.bls12-381-sha-256.proof004.trace.random_scalars.r2 }}
e_tilde = {{ $proofFixtures.bls12-381-sha-256.proof004.trace.random_scalars.e_tilde }}
r1_tilde = {{ $proofFixtures.bls12-381-sha-256.proof004.trace.random_scalars.r1_tilde }}
r3_tilde = {{ $proofFixtures.bls12-381-sha-256.proof004.trace.random_scalars.r3_tilde }}
m_tilde_scalars = {{ $proofFixtures.bls12-381-sha-256.proof004.trace.random_scalars.m_tilde_scalars }}

domain = {{ $proofFixtures.bls12-381-sha-256.proof004.trace.domain }}
challenge = {{ $proofFixtures.bls12-381-sha-256.proof004.trace.challenge }}


L = {{ $proofFixtures.bls12-381-sha-256.proof004.L }}

proof = {{ $proofFixtures.bls12-381-sha-256.proof004.proof }}
```

#### valid no prover committed messages and half signer messages revealed proof

```
signerPublicKey = {{ $proofFixtures.bls12-381-sha-256.proof005.signerPublicKey }}
signature = {{ $proofFixtures.bls12-381-sha-256.proof005.signature }}

commitmentWithProof = {{ $proofFixtures.bls12-381-sha-256.proof005.commitmentWithProof }}
proverBlind = {{ $proofFixtures.bls12-381-sha-256.proof005.proverBlind }}

header = {{ $proofFixtures.bls12-381-sha-256.proof005.header }}
presentationHeader =  {{ $proofFixtures.bls12-381-sha-256.proof005.presentationHeader }}

revealedMessages =

0: {{ $proofFixtures.bls12-381-sha-256.proof005.revealedMessages[0] }}
2: {{ $proofFixtures.bls12-381-sha-256.proof005.revealedMessages[2] }}
4: {{ $proofFixtures.bls12-381-sha-256.proof005.revealedMessages[4] }}
6: {{ $proofFixtures.bls12-381-sha-256.proof005.revealedMessages[6] }}
8: {{ $proofFixtures.bls12-381-sha-256.proof005.revealedMessages[8] }}

revealedCommittedMessages  = {}

Trace:

random_scalars:

r_1 = {{ $proofFixtures.bls12-381-sha-256.proof005.trace.random_scalars.r1 }}
r_2 = {{ $proofFixtures.bls12-381-sha-256.proof005.trace.random_scalars.r2 }}
e_tilde = {{ $proofFixtures.bls12-381-sha-256.proof005.trace.random_scalars.e_tilde }}
r1_tilde = {{ $proofFixtures.bls12-381-sha-256.proof005.trace.random_scalars.r1_tilde }}
r3_tilde = {{ $proofFixtures.bls12-381-sha-256.proof005.trace.random_scalars.r3_tilde }}
m_tilde_scalars = {{ $proofFixtures.bls12-381-sha-256.proof005.trace.random_scalars.m_tilde_scalars }}

domain = {{ $proofFixtures.bls12-381-sha-256.proof005.trace.domain }}
challenge = {{ $proofFixtures.bls12-381-sha-256.proof005.trace.challenge }}

L = {{ $proofFixtures.bls12-381-sha-256.proof005.L }}

proof = {{ $proofFixtures.bls12-381-sha-256.proof005.proof }}
```

#### valid half prover committed messages and no signer messages revealed proof

```
signerPublicKey = {{ $proofFixtures.bls12-381-sha-256.proof006.signerPublicKey }}
signature = {{ $proofFixtures.bls12-381-sha-256.proof006.signature }}

commitmentWithProof = {{ $proofFixtures.bls12-381-sha-256.proof006.commitmentWithProof }}
proverBlind = {{ $proofFixtures.bls12-381-sha-256.proof006.proverBlind }}

header = {{ $proofFixtures.bls12-381-sha-256.proof006.header }}
presentationHeader =  {{ $proofFixtures.bls12-381-sha-256.proof006.presentationHeader }}

revealedMessages = {}


revealedCommittedMessages  =

0: {{ $proofFixtures.bls12-381-sha-256.proof006.revealedCommittedMessages[0] }}
2: {{ $proofFixtures.bls12-381-sha-256.proof006.revealedCommittedMessages[2] }}
4: {{ $proofFixtures.bls12-381-sha-256.proof006.revealedCommittedMessages[4] }}

Trace:

random_scalars:

r_1 = {{ $proofFixtures.bls12-381-sha-256.proof006.trace.random_scalars.r1 }}
r_2 = {{ $proofFixtures.bls12-381-sha-256.proof006.trace.random_scalars.r2 }}
e_tilde = {{ $proofFixtures.bls12-381-sha-256.proof006.trace.random_scalars.e_tilde }}
r1_tilde = {{ $proofFixtures.bls12-381-sha-256.proof006.trace.random_scalars.r1_tilde }}
r3_tilde = {{ $proofFixtures.bls12-381-sha-256.proof006.trace.random_scalars.r3_tilde }}
m_tilde_scalars = {{ $proofFixtures.bls12-381-sha-256.proof006.trace.random_scalars.m_tilde_scalars }}

domain = {{ $proofFixtures.bls12-381-sha-256.proof006.trace.domain }}
challenge = {{ $proofFixtures.bls12-381-sha-256.proof006.trace.challenge }}

L = {{ $proofFixtures.bls12-381-sha-256.proof006.L }}

proof = {{ $proofFixtures.bls12-381-sha-256.proof006.proof }}
```

#### valid no prover committed messages and no signer messages revealed proof

```
signerPublicKey = {{ $proofFixtures.bls12-381-sha-256.proof007.signerPublicKey }}
signature = {{ $proofFixtures.bls12-381-sha-256.proof007.signature }}

commitmentWithProof = {{ $proofFixtures.bls12-381-sha-256.proof007.commitmentWithProof }}
proverBlind = {{ $proofFixtures.bls12-381-sha-256.proof007.proverBlind }}

header = {{ $proofFixtures.bls12-381-sha-256.proof007.header }}
presentationHeader =  {{ $proofFixtures.bls12-381-sha-256.proof007.presentationHeader }}

revealedMessages = {}

revealedCommittedMessages  = {}

Trace:

random_scalars:

r_1 = {{ $proofFixtures.bls12-381-sha-256.proof007.trace.random_scalars.r1 }}
r_2 = {{ $proofFixtures.bls12-381-sha-256.proof007.trace.random_scalars.r2 }}
e_tilde = {{ $proofFixtures.bls12-381-sha-256.proof007.trace.random_scalars.e_tilde }}
r1_tilde = {{ $proofFixtures.bls12-381-sha-256.proof007.trace.random_scalars.r1_tilde }}
r3_tilde = {{ $proofFixtures.bls12-381-sha-256.proof007.trace.random_scalars.r3_tilde }}
m_tilde_scalars = {{ $proofFixtures.bls12-381-sha-256.proof007.trace.random_scalars.m_tilde_scalars }}

domain = {{ $proofFixtures.bls12-381-sha-256.proof007.trace.domain }}
challenge = {{ $proofFixtures.bls12-381-sha-256.proof007.trace.challenge }}

L = {{ $proofFixtures.bls12-381-sha-256.proof007.L }}

proof = {{ $proofFixtures.bls12-381-sha-256.proof007.proof }}
```

#### valid all prover committed messages and signer messages revealed proof

```
signerPublicKey = {{ $proofFixtures.bls12-381-sha-256.proof008.signerPublicKey }}
signature = {{ $proofFixtures.bls12-381-sha-256.proof008.signature }}

commitmentWithProof = {{ $proofFixtures.bls12-381-sha-256.proof008.commitmentWithProof }}
proverBlind = {{ $proofFixtures.bls12-381-sha-256.proof008.proverBlind }}

header = {{ $proofFixtures.bls12-381-sha-256.proof008.header }}
presentationHeader =  {{ $proofFixtures.bls12-381-sha-256.proof008.presentationHeader }}

revealedMessages =

0: {{ $proofFixtures.bls12-381-sha-256.proof008.revealedMessages[0] }}
2: {{ $proofFixtures.bls12-381-sha-256.proof008.revealedMessages[2] }}
4: {{ $proofFixtures.bls12-381-sha-256.proof008.revealedMessages[4] }}
6: {{ $proofFixtures.bls12-381-sha-256.proof008.revealedMessages[6] }}
8: {{ $proofFixtures.bls12-381-sha-256.proof008.revealedMessages[8] }}


revealedCommittedMessages  = null

L = {{ $proofFixtures.bls12-381-sha-256.proof008.L }}

proof = {{ $proofFixtures.bls12-381-sha-256.proof008.proof }}
```

## BLS12-381-SHAKE-256

### Generators

```
api_id = {{ $generatorFixtures.bls12-381-shake-256.generators.api_id }}

P1 = {{ $generatorFixtures.bls12-381-shake-256.generators.P1 }}
Q1 = {{ $generatorFixtures.bls12-381-shake-256.generators.Q1 }}

Generators = {

H_0 = {{ $generatorFixtures.bls12-381-shake-256.generators.MsgGenerators[0] }}
H_1 = {{ $generatorFixtures.bls12-381-shake-256.generators.MsgGenerators[1] }}
H_2 = {{ $generatorFixtures.bls12-381-shake-256.generators.MsgGenerators[2] }}
H_3 = {{ $generatorFixtures.bls12-381-shake-256.generators.MsgGenerators[3] }}
H_4 = {{ $generatorFixtures.bls12-381-shake-256.generators.MsgGenerators[4] }}
H_5 = {{ $generatorFixtures.bls12-381-shake-256.generators.MsgGenerators[5] }}
H_6 = {{ $generatorFixtures.bls12-381-shake-256.generators.MsgGenerators[6] }}
H_7 = {{ $generatorFixtures.bls12-381-shake-256.generators.MsgGenerators[7] }}
H_8 = {{ $generatorFixtures.bls12-381-shake-256.generators.MsgGenerators[8] }}
H_9 = {{ $generatorFixtures.bls12-381-shake-256.generators.MsgGenerators[9] }}

}
```

### Blind Generators

```
api_id = {{ $generatorFixtures.bls12-381-shake-256.blindGenerators.api_id }}

P1 = {{ $generatorFixtures.bls12-381-shake-256.blindGenerators.P1 }}
Q1 = {{ $generatorFixtures.bls12-381-shake-256.blindGenerators.Q1 }}

Blind Generators = {

J_0 = {{ $generatorFixtures.bls12-381-shake-256.blindGenerators.MsgGenerators[0] }}
J_1 = {{ $generatorFixtures.bls12-381-shake-256.blindGenerators.MsgGenerators[1] }}
J_2 = {{ $generatorFixtures.bls12-381-shake-256.blindGenerators.MsgGenerators[2] }}
J_3 = {{ $generatorFixtures.bls12-381-shake-256.blindGenerators.MsgGenerators[3] }}
J_4 = {{ $generatorFixtures.bls12-381-shake-256.blindGenerators.MsgGenerators[4] }}

}
```

### Commitment

Mocked random scalar parameters

```
seed = {{ $commitmentFixtures.bls12-381-shake-256.commit001.mockRngParameters.SEED }}
dst = {{ $commitmentFixtures.bls12-381-shake-256.commit001.mockRngParameters.commit.DST }}
```

#### valid no committed messages commitment with proof

```
committedMessages = {{ $commitmentFixtures.bls12-381-shake-256.commit001.committedMessages }}
proverBlind = {{ $commitmentFixtures.bls12-381-shake-256.commit001.proverBlind }}

Trace:

s_tilde = {{ $commitmentFixtures.bls12-381-shake-256.commit001.trace.random_scalars.s_tilde }}
m_tildes = {{ $commitmentFixtures.bls12-381-shake-256.commit001.trace.random_scalars.m_tildes }}

commitmentWithProof = {{ $commitmentFixtures.bls12-381-shake-256.commit001.commitmentWithProof }}
```

#### valid multiple committed messages commitment with proof

```
committedMessages = {{ $commitmentFixtures.bls12-381-shake-256.commit002.committedMessages }}
proverBlind = {{ $commitmentFixtures.bls12-381-shake-256.commit002.proverBlind }}

Trace:

s_tilde = {{ $commitmentFixtures.bls12-381-shake-256.commit001.trace.random_scalars.s_tilde }}
m_tildes = {{ $commitmentFixtures.bls12-381-shake-256.commit001.trace.random_scalars.m_tildes }}

commitmentWithProof = {{ $commitmentFixtures.bls12-381-shake-256.commit002.commitmentWithProof }}
```

### Blind Generators

```
api_id = {{ $generatorFixtures.bls12-381-shake-256.blindGenerators.api_id }}

P1 = {{ $generatorFixtures.bls12-381-shake-256.blindGenerators.P1 }}
Q1 = {{ $generatorFixtures.bls12-381-shake-256.blindGenerators.Q1 }}

Blind Generators = {

J_0 = {{ $generatorFixtures.bls12-381-shake-256.blindGenerators.MsgGenerators[0] }}
J_1 = {{ $generatorFixtures.bls12-381-shake-256.blindGenerators.MsgGenerators[1] }}
J_2 = {{ $generatorFixtures.bls12-381-shake-256.blindGenerators.MsgGenerators[2] }}
J_3 = {{ $generatorFixtures.bls12-381-shake-256.blindGenerators.MsgGenerators[3] }}
J_4 = {{ $generatorFixtures.bls12-381-shake-256.blindGenerators.MsgGenerators[4] }}

}
```


### Signature Test Vectors

#### valid no prover committed messages, no signer messages signature

```
secretKey = {{ $signatureFixtures.bls12-381-shake-256.signature001.signerKeyPair.secretKey }}
publicKey = {{ $signatureFixtures.bls12-381-shake-256.signature001.signerKeyPair.publicKey }}

header = {{ $signatureFixtures.bls12-381-shake-256.signature001.header }}
messages = {{ $signatureFixtures.bls12-381-shake-256.signature001.messages }}

commitmentWithProof = {{ $signatureFixtures.bls12-381-shake-256.signature001.commitmentWithProof }}

committedMessages = {{ $signatureFixtures.bls12-381-shake-256.signature001.committedMessages }}

proverBlind = {{ $signatureFixtures.bls12-381-shake-256.signature001.proverBlind }}

B = {{ $signatureFixtures.bls12-381-shake-256.signature001.trace.B }}
domain = {{ $signatureFixtures.bls12-381-shake-256.signature001.trace.domain }}

signature = {{ $signatureFixtures.bls12-381-shake-256.signature001.signature }}
```

#### valid multi prover committed messages, no signer messages signature

```
secretKey = {{ $signatureFixtures.bls12-381-shake-256.signature002.signerKeyPair.secretKey }}
publicKey = {{ $signatureFixtures.bls12-381-shake-256.signature002.signerKeyPair.publicKey }}

header = {{ $signatureFixtures.bls12-381-shake-256.signature002.header }}
messages = {{ $signatureFixtures.bls12-381-shake-256.signature002.messages }}

commitmentWithProof = {{ $signatureFixtures.bls12-381-shake-256.signature002.commitmentWithProof }}

committedMessages = {{ $signatureFixtures.bls12-381-shake-256.signature002.committedMessages }}

proverBlind = {{ $signatureFixtures.bls12-381-shake-256.signature002.proverBlind }}

B = {{ $signatureFixtures.bls12-381-shake-256.signature002.trace.B }}
domain = {{ $signatureFixtures.bls12-381-shake-256.signature002.trace.domain }}

signature = {{ $signatureFixtures.bls12-381-shake-256.signature002.signature }}
```

#### valid no prover committed messages, multiple signer messages signature

```
secretKey = {{ $signatureFixtures.bls12-381-shake-256.signature003.signerKeyPair.secretKey }}
publicKey = {{ $signatureFixtures.bls12-381-shake-256.signature003.signerKeyPair.publicKey }}

header = {{ $signatureFixtures.bls12-381-shake-256.signature003.header }}
messages = {{ $signatureFixtures.bls12-381-shake-256.signature003.messages }}

commitmentWithProof = {{ $signatureFixtures.bls12-381-shake-256.signature003.commitmentWithProof }}

committedMessages = {{ $signatureFixtures.bls12-381-shake-256.signature003.committedMessages }}

proverBlind = {{ $signatureFixtures.bls12-381-shake-256.signature003.proverBlind }}

B = {{ $signatureFixtures.bls12-381-shake-256.signature003.trace.B }}
domain = {{ $signatureFixtures.bls12-381-shake-256.signature003.trace.domain }}

signature = {{ $signatureFixtures.bls12-381-shake-256.signature003.signature }}
```

#### valid multiple signer and prover committed messages signature

```
secretKey = {{ $signatureFixtures.bls12-381-shake-256.signature004.signerKeyPair.secretKey }}
publicKey = {{ $signatureFixtures.bls12-381-shake-256.signature004.signerKeyPair.publicKey }}

header = {{ $signatureFixtures.bls12-381-shake-256.signature004.header }}
messages = {{ $signatureFixtures.bls12-381-shake-256.signature004.messages }}

commitmentWithProof = {{ $signatureFixtures.bls12-381-shake-256.signature004.commitmentWithProof }}

committedMessages = {{ $signatureFixtures.bls12-381-shake-256.signature004.committedMessages }}

proverBlind = {{ $signatureFixtures.bls12-381-shake-256.signature004.proverBlind }}

B = {{ $signatureFixtures.bls12-381-shake-256.signature004.trace.B }}
domain = {{ $signatureFixtures.bls12-381-shake-256.signature004.trace.domain }}

signature = {{ $signatureFixtures.bls12-381-shake-256.signature004.signature }}
```

#### valid no commitment signature

```
secretKey = {{ $signatureFixtures.bls12-381-shake-256.signature005.signerKeyPair.secretKey }}
publicKey = {{ $signatureFixtures.bls12-381-shake-256.signature005.signerKeyPair.publicKey }}

header = {{ $signatureFixtures.bls12-381-shake-256.signature005.header }}
messages = {{ $signatureFixtures.bls12-381-shake-256.signature005.messages }}

commitmentWithProof = {{ $signatureFixtures.bls12-381-shake-256.signature005.commitmentWithProof }}

committedMessages = {{ $signatureFixtures.bls12-381-shake-256.signature005.committedMessages }}

proverBlind = {{ $signatureFixtures.bls12-381-shake-256.signature005.proverBlind }}

B = {{ $signatureFixtures.bls12-381-shake-256.signature005.trace.B }}
domain = {{ $signatureFixtures.bls12-381-shake-256.signature005.trace.domain }}

signature = {{ $signatureFixtures.bls12-381-shake-256.signature005.signature }}
```

### Proof Test Vectors


Mocked random scalar parameters

```
seed = {{ $proofFixtures.bls12-381-shake-256.proof001.mockRngParameters.SEED }}
dst = {{ $proofFixtures.bls12-381-shake-256.proof001.mockRngParameters.proof.DST }}
```

#### valid all prover committed messages and signer messages revealed proof

```
signerPublicKey = {{ $proofFixtures.bls12-381-shake-256.proof001.signerPublicKey }}
signature = {{ $proofFixtures.bls12-381-shake-256.proof001.signature }}

commitmentWithProof = {{ $proofFixtures.bls12-381-shake-256.proof001.commitmentWithProof }}
proverBlind = {{ $proofFixtures.bls12-381-shake-256.proof001.proverBlind }}

header = {{ $proofFixtures.bls12-381-shake-256.proof001.header }}
presentationHeader =  {{ $proofFixtures.bls12-381-shake-256.proof001.presentationHeader }}

revealedMessages =

0: {{ $proofFixtures.bls12-381-shake-256.proof001.revealedMessages[0] }}
1: {{ $proofFixtures.bls12-381-shake-256.proof001.revealedMessages[1] }}
2: {{ $proofFixtures.bls12-381-shake-256.proof001.revealedMessages[2] }}
3: {{ $proofFixtures.bls12-381-shake-256.proof001.revealedMessages[3] }}
4: {{ $proofFixtures.bls12-381-shake-256.proof001.revealedMessages[4] }}
5: {{ $proofFixtures.bls12-381-shake-256.proof001.revealedMessages[5] }}
6: {{ $proofFixtures.bls12-381-shake-256.proof001.revealedMessages[6] }}
7: {{ $proofFixtures.bls12-381-shake-256.proof001.revealedMessages[7] }}
8: {{ $proofFixtures.bls12-381-shake-256.proof001.revealedMessages[8] }}
9: {{ $proofFixtures.bls12-381-shake-256.proof001.revealedMessages[9] }}


revealedCommittedMessages  =

0: {{ $proofFixtures.bls12-381-shake-256.proof001.revealedCommittedMessages[0] }}
1: {{ $proofFixtures.bls12-381-shake-256.proof001.revealedCommittedMessages[1] }}
2: {{ $proofFixtures.bls12-381-shake-256.proof001.revealedCommittedMessages[2] }}
3: {{ $proofFixtures.bls12-381-shake-256.proof001.revealedCommittedMessages[3] }}
4: {{ $proofFixtures.bls12-381-shake-256.proof001.revealedCommittedMessages[4] }}

Trace:

random_scalars:

r_1 = {{ $proofFixtures.bls12-381-shake-256.proof001.trace.random_scalars.r1 }}
r_2 = {{ $proofFixtures.bls12-381-shake-256.proof001.trace.random_scalars.r2 }}
e_tilde = {{ $proofFixtures.bls12-381-shake-256.proof001.trace.random_scalars.e_tilde }}
r1_tilde = {{ $proofFixtures.bls12-381-shake-256.proof001.trace.random_scalars.r1_tilde }}
r3_tilde = {{ $proofFixtures.bls12-381-shake-256.proof001.trace.random_scalars.r3_tilde }}
m_tilde_scalars = {{ $proofFixtures.bls12-381-shake-256.proof001.trace.random_scalars.m_tilde_scalars }}

domain = {{ $proofFixtures.bls12-381-shake-256.proof001.trace.domain }}
challenge = {{ $proofFixtures.bls12-381-shake-256.proof001.trace.challenge }}

L = {{ $proofFixtures.bls12-381-shake-256.proof001.L }}

proof = {{ $proofFixtures.bls12-381-shake-256.proof001.proof }}
```

#### valid half prover committed messages and all signer messages revealed proof

```
signerPublicKey = {{ $proofFixtures.bls12-381-shake-256.proof002.signerPublicKey }}
signature = {{ $proofFixtures.bls12-381-shake-256.proof002.signature }}

commitmentWithProof = {{ $proofFixtures.bls12-381-shake-256.proof002.commitmentWithProof }}
proverBlind = {{ $proofFixtures.bls12-381-shake-256.proof002.proverBlind }}

header = {{ $proofFixtures.bls12-381-shake-256.proof002.header }}
presentationHeader =  {{ $proofFixtures.bls12-381-shake-256.proof002.presentationHeader }}

revealedMessages =

0: {{ $proofFixtures.bls12-381-shake-256.proof002.revealedMessages[0] }}
1: {{ $proofFixtures.bls12-381-shake-256.proof002.revealedMessages[1] }}
2: {{ $proofFixtures.bls12-381-shake-256.proof002.revealedMessages[2] }}
3: {{ $proofFixtures.bls12-381-shake-256.proof002.revealedMessages[3] }}
4: {{ $proofFixtures.bls12-381-shake-256.proof002.revealedMessages[4] }}
5: {{ $proofFixtures.bls12-381-shake-256.proof002.revealedMessages[5] }}
6: {{ $proofFixtures.bls12-381-shake-256.proof002.revealedMessages[6] }}
7: {{ $proofFixtures.bls12-381-shake-256.proof002.revealedMessages[7] }}
8: {{ $proofFixtures.bls12-381-shake-256.proof002.revealedMessages[8] }}
9: {{ $proofFixtures.bls12-381-shake-256.proof002.revealedMessages[9] }}


revealedCommittedMessages  =

0: {{ $proofFixtures.bls12-381-shake-256.proof002.revealedCommittedMessages[0] }}
2: {{ $proofFixtures.bls12-381-shake-256.proof002.revealedCommittedMessages[2] }}
4: {{ $proofFixtures.bls12-381-shake-256.proof002.revealedCommittedMessages[4] }}

Trace:

random_scalars:

r_1 = {{ $proofFixtures.bls12-381-shake-256.proof002.trace.random_scalars.r1 }}
r_2 = {{ $proofFixtures.bls12-381-shake-256.proof002.trace.random_scalars.r2 }}
e_tilde = {{ $proofFixtures.bls12-381-shake-256.proof002.trace.random_scalars.e_tilde }}
r1_tilde = {{ $proofFixtures.bls12-381-shake-256.proof002.trace.random_scalars.r1_tilde }}
r3_tilde = {{ $proofFixtures.bls12-381-shake-256.proof002.trace.random_scalars.r3_tilde }}
m_tilde_scalars = {{ $proofFixtures.bls12-381-shake-256.proof002.trace.random_scalars.m_tilde_scalars }}

domain = {{ $proofFixtures.bls12-381-shake-256.proof002.trace.domain }}
challenge = {{ $proofFixtures.bls12-381-shake-256.proof002.trace.challenge }}

L = {{ $proofFixtures.bls12-381-shake-256.proof002.L }}

proof = {{ $proofFixtures.bls12-381-shake-256.proof002.proof }}
```

#### valid half prover committed messages and all signer messages revealed proof

```
signerPublicKey = {{ $proofFixtures.bls12-381-shake-256.proof003.signerPublicKey }}
signature = {{ $proofFixtures.bls12-381-shake-256.proof003.signature }}

commitmentWithProof = {{ $proofFixtures.bls12-381-shake-256.proof003.commitmentWithProof }}
proverBlind = {{ $proofFixtures.bls12-381-shake-256.proof003.proverBlind }}

header = {{ $proofFixtures.bls12-381-shake-256.proof003.header }}
presentationHeader =  {{ $proofFixtures.bls12-381-shake-256.proof003.presentationHeader }}

revealedMessages =

0: {{ $proofFixtures.bls12-381-shake-256.proof003.revealedMessages[0] }}
2: {{ $proofFixtures.bls12-381-shake-256.proof003.revealedMessages[2] }}
4: {{ $proofFixtures.bls12-381-shake-256.proof003.revealedMessages[4] }}
6: {{ $proofFixtures.bls12-381-shake-256.proof003.revealedMessages[6] }}
8: {{ $proofFixtures.bls12-381-shake-256.proof003.revealedMessages[8] }}


revealedCommittedMessages  =

0: {{ $proofFixtures.bls12-381-shake-256.proof003.revealedCommittedMessages[0] }}
1: {{ $proofFixtures.bls12-381-shake-256.proof003.revealedCommittedMessages[1] }}
2: {{ $proofFixtures.bls12-381-shake-256.proof003.revealedCommittedMessages[2] }}
3: {{ $proofFixtures.bls12-381-shake-256.proof003.revealedCommittedMessages[3] }}
4: {{ $proofFixtures.bls12-381-shake-256.proof003.revealedCommittedMessages[4] }}

Trace:

random_scalars:

r_1 = {{ $proofFixtures.bls12-381-shake-256.proof003.trace.random_scalars.r1 }}
r_2 = {{ $proofFixtures.bls12-381-shake-256.proof003.trace.random_scalars.r2 }}
e_tilde = {{ $proofFixtures.bls12-381-shake-256.proof003.trace.random_scalars.e_tilde }}
r1_tilde = {{ $proofFixtures.bls12-381-shake-256.proof003.trace.random_scalars.r1_tilde }}
r3_tilde = {{ $proofFixtures.bls12-381-shake-256.proof003.trace.random_scalars.r3_tilde }}
m_tilde_scalars = {{ $proofFixtures.bls12-381-shake-256.proof003.trace.random_scalars.m_tilde_scalars }}

domain = {{ $proofFixtures.bls12-381-shake-256.proof003.trace.domain }}
challenge = {{ $proofFixtures.bls12-381-shake-256.proof003.trace.challenge }}

L = {{ $proofFixtures.bls12-381-shake-256.proof003.L }}

proof = {{ $proofFixtures.bls12-381-shake-256.proof003.proof }}
```

#### valid half prover committed messages and half signer messages revealed proof

```
signerPublicKey = {{ $proofFixtures.bls12-381-shake-256.proof004.signerPublicKey }}
signature = {{ $proofFixtures.bls12-381-shake-256.proof004.signature }}

commitmentWithProof = {{ $proofFixtures.bls12-381-shake-256.proof004.commitmentWithProof }}
proverBlind = {{ $proofFixtures.bls12-381-shake-256.proof004.proverBlind }}

header = {{ $proofFixtures.bls12-381-shake-256.proof004.header }}
presentationHeader =  {{ $proofFixtures.bls12-381-shake-256.proof004.presentationHeader }}

revealedMessages =

0: {{ $proofFixtures.bls12-381-shake-256.proof004.revealedMessages[0] }}
2: {{ $proofFixtures.bls12-381-shake-256.proof004.revealedMessages[2] }}
4: {{ $proofFixtures.bls12-381-shake-256.proof004.revealedMessages[4] }}
6: {{ $proofFixtures.bls12-381-shake-256.proof004.revealedMessages[6] }}
8: {{ $proofFixtures.bls12-381-shake-256.proof004.revealedMessages[8] }}


revealedCommittedMessages  =

0: {{ $proofFixtures.bls12-381-shake-256.proof004.revealedCommittedMessages[0] }}
2: {{ $proofFixtures.bls12-381-shake-256.proof004.revealedCommittedMessages[2] }}
4: {{ $proofFixtures.bls12-381-shake-256.proof004.revealedCommittedMessages[4] }}

Trace:

random_scalars:

r_1 = {{ $proofFixtures.bls12-381-shake-256.proof004.trace.random_scalars.r1 }}
r_2 = {{ $proofFixtures.bls12-381-shake-256.proof004.trace.random_scalars.r2 }}
e_tilde = {{ $proofFixtures.bls12-381-shake-256.proof004.trace.random_scalars.e_tilde }}
r1_tilde = {{ $proofFixtures.bls12-381-shake-256.proof004.trace.random_scalars.r1_tilde }}
r3_tilde = {{ $proofFixtures.bls12-381-shake-256.proof004.trace.random_scalars.r3_tilde }}
m_tilde_scalars = {{ $proofFixtures.bls12-381-shake-256.proof004.trace.random_scalars.m_tilde_scalars }}

domain = {{ $proofFixtures.bls12-381-shake-256.proof004.trace.domain }}
challenge = {{ $proofFixtures.bls12-381-shake-256.proof004.trace.challenge }}

L = {{ $proofFixtures.bls12-381-shake-256.proof004.L }}

proof = {{ $proofFixtures.bls12-381-shake-256.proof004.proof }}
```

#### valid no prover committed messages and half signer messages revealed proof

```
signerPublicKey = {{ $proofFixtures.bls12-381-shake-256.proof005.signerPublicKey }}
signature = {{ $proofFixtures.bls12-381-shake-256.proof005.signature }}

commitmentWithProof = {{ $proofFixtures.bls12-381-shake-256.proof005.commitmentWithProof }}
proverBlind = {{ $proofFixtures.bls12-381-shake-256.proof005.proverBlind }}

header = {{ $proofFixtures.bls12-381-shake-256.proof005.header }}
presentationHeader =  {{ $proofFixtures.bls12-381-shake-256.proof005.presentationHeader }}

revealedMessages =

0: {{ $proofFixtures.bls12-381-shake-256.proof005.revealedMessages[0] }}
2: {{ $proofFixtures.bls12-381-shake-256.proof005.revealedMessages[2] }}
4: {{ $proofFixtures.bls12-381-shake-256.proof005.revealedMessages[4] }}
6: {{ $proofFixtures.bls12-381-shake-256.proof005.revealedMessages[6] }}
8: {{ $proofFixtures.bls12-381-shake-256.proof005.revealedMessages[8] }}

revealedCommittedMessages  = {}

Trace:

random_scalars:

r_1 = {{ $proofFixtures.bls12-381-shake-256.proof005.trace.random_scalars.r1 }}
r_2 = {{ $proofFixtures.bls12-381-shake-256.proof005.trace.random_scalars.r2 }}
e_tilde = {{ $proofFixtures.bls12-381-shake-256.proof005.trace.random_scalars.e_tilde }}
r1_tilde = {{ $proofFixtures.bls12-381-shake-256.proof005.trace.random_scalars.r1_tilde }}
r3_tilde = {{ $proofFixtures.bls12-381-shake-256.proof005.trace.random_scalars.r3_tilde }}
m_tilde_scalars = {{ $proofFixtures.bls12-381-shake-256.proof005.trace.random_scalars.m_tilde_scalars }}

domain = {{ $proofFixtures.bls12-381-shake-256.proof005.trace.domain }}
challenge = {{ $proofFixtures.bls12-381-shake-256.proof005.trace.challenge }}

L = {{ $proofFixtures.bls12-381-shake-256.proof005.L }}

proof = {{ $proofFixtures.bls12-381-shake-256.proof005.proof }}
```

#### valid half prover committed messages and no signer messages revealed proof

```
signerPublicKey = {{ $proofFixtures.bls12-381-shake-256.proof006.signerPublicKey }}
signature = {{ $proofFixtures.bls12-381-shake-256.proof006.signature }}

commitmentWithProof = {{ $proofFixtures.bls12-381-shake-256.proof006.commitmentWithProof }}
proverBlind = {{ $proofFixtures.bls12-381-shake-256.proof006.proverBlind }}

header = {{ $proofFixtures.bls12-381-shake-256.proof006.header }}
presentationHeader =  {{ $proofFixtures.bls12-381-shake-256.proof006.presentationHeader }}

revealedMessages = {}


revealedCommittedMessages  =

0: {{ $proofFixtures.bls12-381-shake-256.proof006.revealedCommittedMessages[0] }}
2: {{ $proofFixtures.bls12-381-shake-256.proof006.revealedCommittedMessages[2] }}
4: {{ $proofFixtures.bls12-381-shake-256.proof006.revealedCommittedMessages[4] }}

Trace:

random_scalars:

r_1 = {{ $proofFixtures.bls12-381-shake-256.proof006.trace.random_scalars.r1 }}
r_2 = {{ $proofFixtures.bls12-381-shake-256.proof006.trace.random_scalars.r2 }}
e_tilde = {{ $proofFixtures.bls12-381-shake-256.proof006.trace.random_scalars.e_tilde }}
r1_tilde = {{ $proofFixtures.bls12-381-shake-256.proof006.trace.random_scalars.r1_tilde }}
r3_tilde = {{ $proofFixtures.bls12-381-shake-256.proof006.trace.random_scalars.r3_tilde }}
m_tilde_scalars = {{ $proofFixtures.bls12-381-shake-256.proof006.trace.random_scalars.m_tilde_scalars }}

domain = {{ $proofFixtures.bls12-381-shake-256.proof006.trace.domain }}
challenge = {{ $proofFixtures.bls12-381-shake-256.proof006.trace.challenge }}

L = {{ $proofFixtures.bls12-381-shake-256.proof006.L }}

proof = {{ $proofFixtures.bls12-381-shake-256.proof006.proof }}
```

#### valid no prover committed messages and no signer messages revealed proof

```
signerPublicKey = {{ $proofFixtures.bls12-381-shake-256.proof007.signerPublicKey }}
signature = {{ $proofFixtures.bls12-381-shake-256.proof007.signature }}

commitmentWithProof = {{ $proofFixtures.bls12-381-shake-256.proof007.commitmentWithProof }}
proverBlind = {{ $proofFixtures.bls12-381-shake-256.proof007.proverBlind }}

header = {{ $proofFixtures.bls12-381-shake-256.proof007.header }}
presentationHeader =  {{ $proofFixtures.bls12-381-shake-256.proof007.presentationHeader }}

revealedMessages = {}

revealedCommittedMessages  = {}

Trace:

random_scalars:

r_1 = {{ $proofFixtures.bls12-381-shake-256.proof007.trace.random_scalars.r1 }}
r_2 = {{ $proofFixtures.bls12-381-shake-256.proof007.trace.random_scalars.r2 }}
e_tilde = {{ $proofFixtures.bls12-381-shake-256.proof007.trace.random_scalars.e_tilde }}
r1_tilde = {{ $proofFixtures.bls12-381-shake-256.proof007.trace.random_scalars.r1_tilde }}
r3_tilde = {{ $proofFixtures.bls12-381-shake-256.proof007.trace.random_scalars.r3_tilde }}
m_tilde_scalars = {{ $proofFixtures.bls12-381-shake-256.proof007.trace.random_scalars.m_tilde_scalars }}

domain = {{ $proofFixtures.bls12-381-shake-256.proof007.trace.domain }}
challenge = {{ $proofFixtures.bls12-381-shake-256.proof007.trace.challenge }}

L = {{ $proofFixtures.bls12-381-shake-256.proof007.L }}

proof = {{ $proofFixtures.bls12-381-shake-256.proof007.proof }}
```

#### valid all prover committed messages and signer messages revealed proof

```
signerPublicKey = {{ $proofFixtures.bls12-381-shake-256.proof008.signerPublicKey }}
signature = {{ $proofFixtures.bls12-381-shake-256.proof008.signature }}

commitmentWithProof = {{ $proofFixtures.bls12-381-shake-256.proof008.commitmentWithProof }}
proverBlind = {{ $proofFixtures.bls12-381-shake-256.proof008.proverBlind }}

header = {{ $proofFixtures.bls12-381-shake-256.proof008.header }}
presentationHeader =  {{ $proofFixtures.bls12-381-shake-256.proof008.presentationHeader }}

revealedMessages =

0: {{ $proofFixtures.bls12-381-shake-256.proof008.revealedMessages[0] }}
2: {{ $proofFixtures.bls12-381-shake-256.proof008.revealedMessages[2] }}
4: {{ $proofFixtures.bls12-381-shake-256.proof008.revealedMessages[4] }}
6: {{ $proofFixtures.bls12-381-shake-256.proof008.revealedMessages[6] }}
8: {{ $proofFixtures.bls12-381-shake-256.proof008.revealedMessages[8] }}


revealedCommittedMessages  = null

L = {{ $proofFixtures.bls12-381-shake-256.proof008.L }}

proof = {{ $proofFixtures.bls12-381-shake-256.proof008.proof }}
```
-->

# IANA Considerations

This document does not make any requests of IANA.

{backmatter}

# Document History

-00

* Initial Version

-01

* Change `committed_messages` to `committed_message_scalars` in `CoreCommit`
* Added explanatory text
* Added test vectors

-02

* Expanded privacy and security considerations
* Updated the introduction

-03

* Add committed disclosure functionality and explanatory text
* Editorial fixes

-04

* Fixed generator counts, scalar ordering, and disclosure indexing in blind signature and proof operations
* Corrected inputs, outputs, and undefined variables in core operations
* Unified commitment terminology and simplified proof serialization

<reference anchor="Chaum85" target="https://dl.acm.org/doi/pdf/10.1145/4372.4373">
 <front>
   <title>Security without identification: transaction systems to make big brother obsolete</title>
   <author initials="D." surname="Chaum" fullname="David Chaum">
    </author>
    <date year="1985"/>
 </front>
 <seriesInfo name="In" value="Commun. ACM"/>
 <seriesInfo name="vol" value="10" />
 <seriesInfo name="pages" value="1030-1044"/>
</reference>

<reference anchor="P91" target="https://ia.cr/2023/275">
  <front>
    <title>Non-Interactive and Information-Theoretic Secure Verifiable Secret Sharing</title>
    <author initials="T." surname="Pedersen" fullname="Torden Pryds Pedersen">
      <organization>Aarhus University</organization>
    </author>
    <date year="1991"/>
  </front>
  <seriesInfo name="In" value="CRYPTO"/>
</reference>

<reference anchor="BG18" target="https://link.springer.com/chapter/10.1007/978-3-319-76581-5_19">
  <front>
    <title>Efficient Batch Zero-Knowledge Arguments for Low Degree Polynomials</title>
    <author initials="J." surname="Bootle" fullname="Jonathan Bootle">
      <organization>University College London</organization>
    </author>
    <author initials="J." surname="Groth" fullname="Jens Groth">
      <organization>University College London</organization>
    </author>
    <date year="2018"/>
  </front>
  <seriesInfo name="In" value="CRYPTO"/>
</reference>
<reference anchor="Vision2025" target="https://eprint.iacr.org/2025/1981">
  <front>
  <title>Vision: A Modular Framework for Anonymous Credential Systems</title>
  <author surname="Lehmann" fullname="Anja Lehmann" />
  <author surname="Sidorenko" fullname="Andrey Sidorenko" />
  <author surname="Zacharakis" fullname="Alexandros Zacharakis" />
  <date year="2025" />
  </front>
</reference>
<reference anchor="LegacyBinding2026" target="https://eprint.iacr.org/2026/965">
  <front>
  <title>Device Binding for Anonymous Credentials on Legacy Phones</title>
  <author surname="Celi" fullname="Sof&#237;a Celi" />
  <author surname="Lehmann" fullname="Anja Lehmann" />
  <author surname="Levin" fullname="Shai Levin" />
  <author surname="Zacharakis" fullname="Alexandros Zacharakis" />
  <date year="2026" />
  </front>
</reference>
