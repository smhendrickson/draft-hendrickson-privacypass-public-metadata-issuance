---
title: "Public Metadata Issuance"
abbrev: "Public Metadata Issuance"
category: info

docname: draft-hendrickson-privacypass-public-metadata-issuance-latest
submissiontype: IETF  # also: "independent", "IAB", or "IRTF"
number:
date:
consensus: true
v: 3
area: "Security"
workgroup: "Privacy Pass"
keyword:
 - public metadata issuance
venue:
  group: "Privacy Pass"
  type: "Working Group"
  mail: "privacy-pass@ietf.org"
  arch: "https://mailarchive.ietf.org/arch/browse/privacy-pass/"
  github: "smhendrickson/draft-hendrickson-privacypass-public-metadata-issuance"
  latest: "https://smhendrickson.github.io/draft-hendrickson-privacypass-public-metadata-issuance/draft-hendrickson-privacypass-public-metadata-issuance.html"

author:
 -
    fullname: Scott Hendrickson
    organization: Google
    email: "scott@shendrickson.com"

normative:
  PROTOCOL: I-D.draft-ietf-privacypass-protocol-08
  BLINDRSA: I-D.draft-irtf-cfrg-rsa-blind-signatures-07
  PBLINDRSA:
    title: Public Metadata Blind RSA TODO LINK
    target: https://www.example.com/


--- abstract

TODO Abstract


--- middle

# Introduction

TODO Introduction

# Terminology

{::boilerplate bcp14}

The following terms are used throughout this document.

- Public Metadata: Arbitrary length metadata that can be viewed by the client, attester, issuer, and verifier. After signing metadata is bound to the token & signature and cannot be mutated as described in TODO_link_crypto_draft. In literature this may also be referred to as 'partial blinding'. We will refer to it as public metadata throughout this draft and privacy pass.

# Issuance Protocol for Publicly Verifiable Tokens {#public-flow}

This section describes a variant of the issuance protocol in {{Section 6 of PROTOCOL}}
for producing publicly verifiable tokens including public metadata using {{PBLINDRSA}}.
In particular, this variant of the issuance protocol works for the
TODO_insert_variants of the blind RSA protocol variants described in {{Section 5 of BLINDRSA}}.

The public metadata issuance protocol differs from the protocol in
{{Section 6 of PROTOCOL}} in that the issuance and redemption protocols carry metadata provided by the Client and visible to the Attester, Issuer, and Origin. This means Clients can set arbitrary metadata when requesting a token, but specific values of metadata may be rejected by either Attester, Issuer, or Origin. Similar to a token nonce, metadata is cryptographically bound to a token and cannot be altered.

Beyond this difference, the publicly metadata issuance protocol variant is
nearly identical to the publicy verifiable issuance protocol variant. In
particular, Issuers provide a Private and Public Key, denoted skI and pkI,
respectively, used to produce tokens as input to the protocol. See
{{Section 6.5 of PROTOCOL}} for how this key pair is generated.

Clients provide the following as input to the issuance protocol:

- Issuer Request URI: A URI to which token request messages are sent. This can
  be a URL derived from the "issuer-request-uri" value in the Issuer's
  directory resource, or it can be another Client-configured URL. The value
  of this parameter depends on the Client configuration and deployment model.
  For example, in the 'Split Origin, Attester, Issuer' deployment model, the
  Issuer Request URI might be correspond to the Client's configured Attester,
  and the Attester is configured to relay requests to the Issuer.
- Issuer name: An identifier for the Issuer. This is typically a host name that
  can be used to construct HTTP requests to the Issuer.
- Issuer Public Key: `pkI`, with a key identifier `token_key_id` computed as
  described in {{public-issuer-configuration}}.
- Challenge value: `challenge`, an opaque byte string. For example, this might
  be provided by the redemption protocol in [AUTHSCHEME].
- Metadata value: `metadata`, an opaque byte string of length at most 2<sup>16-1</sup> bytes.

Given this configuration and these inputs, the two messages exchanged in
this protocol are described below. The constant `Nk` is defined as 256 for token type 0x1234 in
{{PROTOCOL}}.

## Client-to-Issuer Request {#public-request}

The Client first creates an issuance request message for a random value
`nonce` using the input challenge and Issuer key identifier as follows:

~~~
nonce = random(32)
challenge_digest = SHA256(challenge)
token_input = concat(0x1234, // Token type field is 2 bytes long
                     len_in_bytes(metadata), // 2-byte length of metadata
                     metadata,
                     nonce,
                     challenge_digest,
                     token_key_id)
blinded_msg, blind_inv =
  Blind(pkI, metadata, PrepareIdentity(token_input))
~~~

The PrepareIdentity and Blind functions are defined in
{{PBLINDRSA}} and {{PBLINDRSA}}, respectively.
The Client stores the nonce, challenge_digest, and metadata values locally for use
when finalizing the issuance protocol to produce a token (as described
in {{public-finalize}}).

The Client then creates a TokenRequest structured as follows:

~~~
struct {
  uint16_t token_type = 0x1234; /* Type Public Metadata Blind RSA (2048-bit) */
  uint8_t truncated_token_key_id;
  opaque metadata<1..2^16-1>;
  uint8_t blinded_msg[Nk];
} TokenRequest;
~~~

The structure fields are defined as follows:

- "token_type" is a 2-octet integer, which matches the type in the challenge.

- "truncated_token_key_id" is the least significant byte of the `token_key_id`
  ({{public-issuer-configuration}}) in network byte order (in other words, the
  last 8 bits of `token_key_id`).

- "metadata" is the opaque metadata value that all `blinded_msg` values are encoded for.

- "blinded_msg" is the Nk-octet request defined above.

The Client then generates an HTTP POST request to send to the Issuer Request
URI, with the TokenRequest as the content. The media type for this request
is "application/private-token-request". An example request is shown below:

~~~
:method = POST
:scheme = https
:authority = issuer.example.net
:path = /request
accept = application/private-token-response
cache-control = no-cache, no-store
content-type = application/private-token-request
content-length = <Length of TokenRequest>

<Bytes containing the TokenRequest>
~~~

## Issuer-to-Client Response {#public-response}

Upon receipt of the request, the Issuer validates the following conditions:

- The TokenRequest contains a supported token_type.
- The TokenRequest.truncated_token_key_id corresponds to the truncated key
  ID of an Issuer Public Key.
- The TokenRequest.blinded_msg is of the correct size.
- The TokenREquest.metadata satisfies issuer requirements.

If any of these conditions is not met, the Issuer MUST return an HTTP 400 error
to the Client, which will forward the error to the client. Otherwise, if the
Issuer is willing to produce a token token to the Client, the Issuer
completes the issuance flow by computing a blinded response as follows:

~~~
blind_sig = BlindSign(skI, metadata, TokenRequest.blinded_msg)
~~~

The BlindSign function is defined in {{PBLINDRSA}}.
The result is encoded and transmitted to the client in the following
TokenResponse structure:

~~~
struct {
  uint8_t blind_sig[Nk];
} TokenResponse;
~~~

The Issuer generates an HTTP response with status code 200 whose content
consists of TokenResponse, with the content type set as
"application/private-token-response".

~~~
:status = 200
content-type = application/private-token-response
content-length = <Length of TokenResponse>

<Bytes containing the TokenResponse>
~~~

## Finalization {#public-finalize}

Upon receipt, the Client handles the response and, if successful, processes the
content as follows:

~~~
authenticator =
  Finalize(pkI, nonce, metadata, blind_sig, blind_inv)
~~~

The Finalize function is defined in {{PBLINDRSA}}. If this
succeeds, the Client then constructs a Token as described in [AUTHSCHEME] as
follows:

~~~
struct {
  uint16_t token_type = 0x1234; /* Type Blind RSA (2048-bit) */
  opaque metadata<1..2^16-1>;
  uint8_t nonce[32];
  uint8_t challenge_digest[32];
  uint8_t token_key_id[32];
  uint8_t authenticator[Nk];
} Token;
~~~

The Token.nonce value is that which was sampled in {{Section 5.1 of PROTOCOL}}.
If the Finalize function fails, the Client aborts the protocol.

## Token Verification

TODO(shendrick): Replace this entire section with a correct verification description

Verifying a Token requires checking that Token.authenticator is a valid
signature over the remainder of the token input using the Issuer Public Key.
The function `RSASSA-PSS-VERIFY` is defined in Section 8.1.2 of !RFC8017}},
using SHA-384 as the Hash function, MGF1 with SHA-384 as the PSS mask
generation function (MGF), and a 48-byte salt length (sLen).

~~~
token_authenticator_input =
  concat(Token.token_type,
         Token.nonce,
         Token.challenge_digest,
         Token.token_key_id)
valid = RSASSA-PSS-VERIFY(pkI,
                          token_authenticator_input,
                          Token.authenticator)
~~~

## Issuer Configuration {#public-issuer-configuration}

Issuers are configured with Private and Public Key pairs, each denoted skI and
pkI, respectively, used to produce tokens. Each key pair SHALL be generated as
as specified in FIPS 186-4 {{?DSS=DOI.10.6028/NIST.FIPS.186-4}}, where n is 4096 bits in length. These key
pairs MUST NOT be reused in other protocols.

The key identifier for a keypair (skI, pkI), denoted `token_key_id`, is
computed as SHA256(encoded_key), where encoded_key is a DER-encoded
SubjectPublicKeyInfo (SPKI) object carrying pkI. The SPKI object MUST use the
RSASSA-PSS OID {{!RFC5756}}, which specifies the hash algorithm and salt size.
The salt size MUST match the output size of the hash function associated with
the public key and token type.

Since Clients truncate `token_key_id` in each `TokenRequest`, Issuers should
ensure that the truncated form of new key IDs do not collide with other
truncated key IDs in rotation.


# Security Considerations

TODO Security


# IANA Considerations

This document has no IANA actions.


--- back

# Acknowledgments
{:numbered="false"}

TODO acknowledge.
