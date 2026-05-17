# pragma version ^0.4.0

# @title TEE-Gated Contract
# @notice Accepts a UnifiedQuote at instantiation to register a TEE identity.
#         All subsequent state-changing actions require a valid attestation
#         proof from the same TEE (matching pubkey).
#
# @dev Ed25519 is not EVM-native, so we use a two-layer approach:
#      - The TEE's ed25519 pubkey hash + value_x are stored as identity
#      - The TEE also signs with a secp256k1 key (EVM-compatible)
#      - ecrecover verifies the secp256k1 signature on-chain
#      - The secp256k1 address is bound to the ed25519 pubkey at registration
#
# UnifiedQuote compact fields (on-chain):
#   value_x:             bytes32[2]  (48 bytes, packed into 2 slots)
#   platform:            uint8       (1=Nitro, 2=SNP, 3=TDX)
#   platform_quote_hash: bytes32
#   timestamp:           uint256
#   nonce:               bytes32
#   ed25519_signature:   bytes32[2]  (64 bytes, packed)
#   ed25519_pubkey:      bytes32

# === Events ===

event TeeRegistered:
    value_x_high: bytes32
    value_x_low: bytes16
    platform: uint8
    tee_address: address
    timestamp: uint256

event ActionExecuted:
    action_id: uint256
    caller: address
    data_hash: bytes32
    timestamp: uint256

event ValueXUpdated:
    old_high: bytes32
    old_low: bytes16
    new_high: bytes32
    new_low: bytes16
    timestamp: uint256

# === Storage ===

# TEE identity (set at construction, immutable after)
registered_value_x_high: public(bytes32)    # value_x bytes [0:32]
registered_value_x_low: public(bytes16)     # value_x bytes [32:48]
registered_platform: public(uint8)
registered_quote_hash: public(bytes32)      # sha256(platform_quote)
registered_ed25519_pubkey: public(bytes32)  # ed25519 pubkey
registered_tee_address: public(address)     # secp256k1 address bound to TEE

# Contract state
owner: public(address)
action_count: public(uint256)
is_initialized: public(bool)

# Nonce replay protection
used_nonces: public(HashMap[bytes32, bool])

@deploy
def __init__(
    value_x_high: bytes32,
    value_x_low: bytes16,
    platform: uint8,
    quote_hash: bytes32,
    ed25519_pubkey: bytes32,
    tee_address: address,
    timestamp: uint256,
    nonce: bytes32,
    # secp256k1 proof that tee_address is controlled by TEE
    sig_v: uint8,
    sig_r: bytes32,
    sig_s: bytes32,
):
    """
    @notice Register a TEE identity from a UnifiedQuote.
    @dev The TEE must sign a registration message with its secp256k1 key
         to prove it controls tee_address. This binds the EVM address
         to the TEE attestation.
    """
    # Verify the registration signature
    # Message: keccak256(value_x_high || value_x_low || platform || quote_hash || ed25519_pubkey || timestamp || nonce)
    reg_hash: bytes32 = keccak256(
        concat(
            value_x_high,
            value_x_low,
            convert(platform, bytes1),
            quote_hash,
            ed25519_pubkey,
            convert(timestamp, bytes32),
            nonce,
        )
    )
    eth_hash: bytes32 = keccak256(
        concat(
            b"\x19Ethereum Signed Message:\n32",
            reg_hash,
        )
    )

    signer: address = ecrecover(eth_hash, convert(sig_v, uint256), convert(sig_r, uint256), convert(sig_s, uint256))
    assert signer == tee_address, "registration signature invalid"
    assert signer != empty(address), "zero signer"
    assert nonce != empty(bytes32), "empty nonce"
    assert timestamp + 300 >= block.timestamp, "registration too old"
    assert timestamp <= block.timestamp + 60, "registration from future"

    # Store TEE identity
    self.registered_value_x_high = value_x_high
    self.registered_value_x_low = value_x_low
    self.registered_platform = platform
    self.registered_quote_hash = quote_hash
    self.registered_ed25519_pubkey = ed25519_pubkey
    self.registered_tee_address = tee_address
    self.owner = msg.sender
    self.is_initialized = True
    self.used_nonces[nonce] = True

    log TeeRegistered(
        value_x_high=value_x_high,
        value_x_low=value_x_low,
        platform=platform,
        tee_address=tee_address,
        timestamp=timestamp,
    )


@internal
def _verify_tee_action(
    action_hash: bytes32,
    timestamp: uint256,
    nonce: bytes32,
    sig_v: uint8,
    sig_r: bytes32,
    sig_s: bytes32,
):
    """
    @notice Verify that an action was authorized by the registered TEE.
    @dev Checks:
         1. Nonce hasn't been used (replay protection)
         2. Timestamp is recent (staleness check)
         3. Signature recovers to registered_tee_address
    """
    assert self.is_initialized, "not initialized"
    assert not self.used_nonces[nonce], "nonce already used"
    assert nonce != empty(bytes32), "empty nonce"

    # Staleness: timestamp must be within 5 minutes
    assert timestamp + 300 >= block.timestamp, "attestation too old"
    assert timestamp <= block.timestamp + 60, "attestation from future"

    # Build the signed message
    msg_hash: bytes32 = keccak256(
        concat(
            action_hash,
            convert(timestamp, bytes32),
            nonce,
        )
    )
    eth_hash: bytes32 = keccak256(
        concat(
            b"\x19Ethereum Signed Message:\n32",
            msg_hash,
        )
    )

    signer: address = ecrecover(eth_hash, convert(sig_v, uint256), convert(sig_r, uint256), convert(sig_s, uint256))
    assert signer == self.registered_tee_address, "not the registered TEE"
    assert signer != empty(address), "zero signer"

    # Mark nonce as used
    self.used_nonces[nonce] = True


@external
def execute_action(
    data: bytes32,
    timestamp: uint256,
    nonce: bytes32,
    sig_v: uint8,
    sig_r: bytes32,
    sig_s: bytes32,
) -> uint256:
    """
    @notice Execute a TEE-gated action.
    @dev Only succeeds if the TEE signs the action with a valid, fresh attestation.
    @return The action ID.
    """
    action_hash: bytes32 = keccak256(
        concat(
            convert(self.action_count, bytes32),
            data,
        )
    )
    self._verify_tee_action(action_hash, timestamp, nonce, sig_v, sig_r, sig_s)

    action_id: uint256 = self.action_count
    self.action_count = action_id + 1

    log ActionExecuted(
        action_id=action_id,
        caller=msg.sender,
        data_hash=data,
        timestamp=timestamp,
    )

    return action_id


@external
def update_value_x(
    new_value_x_high: bytes32,
    new_value_x_low: bytes16,
    new_quote_hash: bytes32,
    timestamp: uint256,
    nonce: bytes32,
    sig_v: uint8,
    sig_r: bytes32,
    sig_s: bytes32,
):
    """
    @notice Update Value X (e.g., after runner image update).
    @dev Requires TEE attestation proof. Only the registered TEE can update.
    """
    action_hash: bytes32 = keccak256(
        concat(
            b"update_value_x",
            new_value_x_high,
            new_value_x_low,
            new_quote_hash,
        )
    )
    self._verify_tee_action(action_hash, timestamp, nonce, sig_v, sig_r, sig_s)

    old_high: bytes32 = self.registered_value_x_high
    old_low: bytes16 = self.registered_value_x_low

    self.registered_value_x_high = new_value_x_high
    self.registered_value_x_low = new_value_x_low
    self.registered_quote_hash = new_quote_hash

    log ValueXUpdated(
        old_high=old_high,
        old_low=old_low,
        new_high=new_value_x_high,
        new_low=new_value_x_low,
        timestamp=timestamp,
    )


@view
@external
def get_tee_identity() -> (bytes32, bytes16, uint8, bytes32, bytes32, address):
    """
    @notice Return the registered TEE identity.
    @return (value_x_high, value_x_low, platform, quote_hash, ed25519_pubkey, tee_address)
    """
    return (
        self.registered_value_x_high,
        self.registered_value_x_low,
        self.registered_platform,
        self.registered_quote_hash,
        self.registered_ed25519_pubkey,
        self.registered_tee_address,
    )


@view
@external
def verify_value_x(value_x_high: bytes32, value_x_low: bytes16) -> bool:
    """
    @notice Check if a given Value X matches the registered TEE identity.
    @dev Anyone can call this to verify a runner's identity against on-chain state.
    """
    return (
        self.registered_value_x_high == value_x_high
        and self.registered_value_x_low == value_x_low
    )
