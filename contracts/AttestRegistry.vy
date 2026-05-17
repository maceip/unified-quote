# pragma version ^0.4.0

# @title Attestation Registry
# @notice Stores TEE attestation identities on-chain.
#         Anyone can register a quote, anyone can verify.
#         Acts as a public bulletin board for TEE identities.

event AttestationRegistered:
    registrant: indexed(address)
    value_x_high: bytes32
    value_x_low: bytes16
    platform: uint8
    quote_hash: bytes32
    pubkey: bytes32
    timestamp: uint256

event AttestationVerified:
    verifier: indexed(address)
    value_x_high: bytes32
    value_x_low: bytes16
    match_found: bool

struct Attestation:
    value_x_high: bytes32
    value_x_low: bytes16
    platform: uint8
    quote_hash: bytes32
    pubkey: bytes32
    registered_at: uint256
    registrant: address

# Storage
attestations: public(HashMap[bytes32, Attestation])
attestation_count: public(uint256)
latest_key: public(bytes32)

@external
def register(
    value_x_high: bytes32,
    value_x_low: bytes16,
    platform: uint8,
    quote_hash: bytes32,
    pubkey: bytes32,
):
    """
    @notice Register a TEE attestation on-chain.
    @param value_x_high First 32 bytes of Value X (sha384)
    @param value_x_low  Remaining 16 bytes of Value X
    @param platform     1=Nitro, 2=SNP, 3=TDX
    @param quote_hash   sha256 of the full platform quote
    @param pubkey       ed25519 pubkey of the TEE signing key
    """
    key: bytes32 = keccak256(concat(value_x_high, value_x_low, pubkey))
    assert self.attestations[key].registered_at == 0, "already registered"
    assert platform >= 1 and platform <= 3, "unknown platform"
    assert pubkey != empty(bytes32), "empty pubkey"

    self.attestations[key] = Attestation(
        value_x_high=value_x_high,
        value_x_low=value_x_low,
        platform=platform,
        quote_hash=quote_hash,
        pubkey=pubkey,
        registered_at=block.timestamp,
        registrant=msg.sender,
    )
    self.attestation_count += 1
    self.latest_key = key

    log AttestationRegistered(
        registrant=msg.sender,
        value_x_high=value_x_high,
        value_x_low=value_x_low,
        platform=platform,
        quote_hash=quote_hash,
        pubkey=pubkey,
        timestamp=block.timestamp,
    )


@view
@external
def verify(value_x_high: bytes32, value_x_low: bytes16, pubkey: bytes32) -> bool:
    """
    @notice Check if a Value X + pubkey combination is registered.
    """
    key: bytes32 = keccak256(concat(value_x_high, value_x_low, pubkey))
    return self.attestations[key].registered_at > 0


@view
@external
def get_attestation(key: bytes32) -> (bytes32, bytes16, uint8, bytes32, bytes32, uint256, address):
    """
    @notice Get a registered attestation by key.
    """
    a: Attestation = self.attestations[key]
    return (a.value_x_high, a.value_x_low, a.platform, a.quote_hash, a.pubkey, a.registered_at, a.registrant)
