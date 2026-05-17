# pragma version ^0.4.0

# @title Update Challenge — Multi-winner commit-reveal update validation
# @notice When a new Value X is proposed (software update), the network
#         validates it through a commit-reveal voting game.
#
# Based on:
#   - (Im)possibility of Incentive Design: multi-winner rewards
#   - Hollow Victory: commit-reveal voting + escrowed rewards
#   - RogueOne: trust-domain analysis results stored as metadata
#
# Phases:
#   1. PROPOSAL  — proposer submits new Value X + stake
#   2. COMMIT    — challengers submit hidden votes
#   3. REVEAL    — challengers reveal votes
#   4. RESOLUTION — tally votes, distribute rewards

# === Constants ===

COMMIT_PERIOD: constant(uint256) = 50400    # ~7 days in blocks (12s/block)
REVEAL_PERIOD: constant(uint256) = 21600    # ~3 days in blocks
ESCROW_LOCK: constant(uint256) = 216000     # ~30 days post-resolution

# === Events ===

event UpdateProposed:
    proposal_id: indexed(bytes32)
    proposer: indexed(address)
    new_value_x_high: bytes32
    new_value_x_low: bytes16
    stake: uint256
    commit_deadline: uint256
    reveal_deadline: uint256

event VoteCommitted:
    proposal_id: indexed(bytes32)
    voter: indexed(address)

event VoteRevealed:
    proposal_id: indexed(bytes32)
    voter: indexed(address)
    approved: bool

event ProposalResolved:
    proposal_id: indexed(bytes32)
    approved: bool
    approve_count: uint256
    reject_count: uint256

event RewardClaimed:
    proposal_id: indexed(bytes32)
    voter: indexed(address)
    amount: uint256

# === Storage ===

struct Proposal:
    proposer: address
    new_value_x_high: bytes32
    new_value_x_low: bytes16
    build_provenance_hash: bytes32   # sha256 of Sigstore attestation
    analysis_hash: bytes32           # sha256 of CI analysis results (RogueOne/CodeQL)
    stake: uint256
    commit_deadline: uint256
    reveal_deadline: uint256
    resolved: bool
    approved: bool
    approve_count: uint256
    reject_count: uint256
    escrow_unlock_block: uint256

proposals: public(HashMap[bytes32, Proposal])
proposal_count: public(uint256)

# Commit-reveal storage
# voter -> proposal_id -> commitment hash
commitments: public(HashMap[address, HashMap[bytes32, bytes32]])
# voter -> proposal_id -> revealed vote (0=not revealed, 1=approve, 2=reject)
reveals: public(HashMap[address, HashMap[bytes32, uint8]])
# voter -> proposal_id -> reward claimed
claimed: public(HashMap[address, HashMap[bytes32, bool]])

# Current recommended Value X (updated on approval)
current_value_x_high: public(bytes32)
current_value_x_low: public(bytes16)

# Minimum stake to propose an update
min_stake: public(uint256)

owner: public(address)

@deploy
def __init__(min_stake_wei: uint256):
    self.owner = msg.sender
    self.min_stake = min_stake_wei

# === Propose ===

@external
@payable
def propose(
    new_value_x_high: bytes32,
    new_value_x_low: bytes16,
    build_provenance_hash: bytes32,
    analysis_hash: bytes32,
) -> bytes32:
    """
    @notice Propose a new Value X for the network to validate.
    @dev Proposer stakes ETH. If rejected, stake goes to challengers.
    """
    assert msg.value >= self.min_stake, "insufficient stake"

    proposal_id: bytes32 = keccak256(
        concat(
            new_value_x_high,
            new_value_x_low,
            convert(block.number, bytes32),
        )
    )
    assert self.proposals[proposal_id].commit_deadline == 0, "exists"

    self.proposals[proposal_id] = Proposal(
        proposer=msg.sender,
        new_value_x_high=new_value_x_high,
        new_value_x_low=new_value_x_low,
        build_provenance_hash=build_provenance_hash,
        analysis_hash=analysis_hash,
        stake=msg.value,
        commit_deadline=block.number + COMMIT_PERIOD,
        reveal_deadline=block.number + COMMIT_PERIOD + REVEAL_PERIOD,
        resolved=False,
        approved=False,
        approve_count=0,
        reject_count=0,
        escrow_unlock_block=0,
    )
    self.proposal_count += 1

    log UpdateProposed(
        proposal_id=proposal_id,
        proposer=msg.sender,
        new_value_x_high=new_value_x_high,
        new_value_x_low=new_value_x_low,
        stake=msg.value,
        commit_deadline=block.number + COMMIT_PERIOD,
        reveal_deadline=block.number + COMMIT_PERIOD + REVEAL_PERIOD,
    )

    return proposal_id

# === Commit Phase ===

@external
def commit_vote(proposal_id: bytes32, commitment: bytes32):
    """
    @notice Submit a hidden vote. commitment = keccak256(approve_bool, salt).
    @dev Must be during commit phase. Vote is hidden until reveal.
    """
    p: Proposal = self.proposals[proposal_id]
    assert p.commit_deadline > 0, "no proposal"
    assert block.number <= p.commit_deadline, "commit phase ended"
    assert self.commitments[msg.sender][proposal_id] == empty(bytes32), "already committed"

    self.commitments[msg.sender][proposal_id] = commitment
    log VoteCommitted(proposal_id=proposal_id, voter=msg.sender)

# === Reveal Phase ===

@external
def reveal_vote(proposal_id: bytes32, approved: bool, salt: bytes32):
    """
    @notice Reveal your vote. Must match your commitment.
    @dev Must be during reveal phase.
    """
    p: Proposal = self.proposals[proposal_id]
    assert p.commit_deadline > 0, "no proposal"
    assert block.number > p.commit_deadline, "still in commit phase"
    assert block.number <= p.reveal_deadline, "reveal phase ended"
    assert self.reveals[msg.sender][proposal_id] == 0, "already revealed"

    # Verify commitment
    expected: bytes32 = keccak256(
        concat(
            convert(approved, bytes1),
            salt,
        )
    )
    assert self.commitments[msg.sender][proposal_id] == expected, "commitment mismatch"

    if approved:
        self.reveals[msg.sender][proposal_id] = 1
        self.proposals[proposal_id].approve_count = p.approve_count + 1
    else:
        self.reveals[msg.sender][proposal_id] = 2
        self.proposals[proposal_id].reject_count = p.reject_count + 1

    log VoteRevealed(proposal_id=proposal_id, voter=msg.sender, approved=approved)

# === Resolution ===

@external
def resolve(proposal_id: bytes32):
    """
    @notice Resolve the proposal after reveal phase ends.
    @dev Anyone can call. Outcome based on vote tally.
    """
    p: Proposal = self.proposals[proposal_id]
    assert p.commit_deadline > 0, "no proposal"
    assert block.number > p.reveal_deadline, "reveal phase not ended"
    assert not p.resolved, "already resolved"

    total: uint256 = p.approve_count + p.reject_count
    approved: bool = False

    if total == 0:
        # No quorum: do not advance current Value X. The proposer can
        # reclaim stake after escrow, but silence is not approval.
        approved = False
    else:
        # Simple majority
        approved = p.approve_count > p.reject_count

    self.proposals[proposal_id].resolved = True
    self.proposals[proposal_id].approved = approved

    if approved:
        # Update the current Value X
        self.current_value_x_high = p.new_value_x_high
        self.current_value_x_low = p.new_value_x_low
        # Proposer gets stake back (after escrow period)
        self.proposals[proposal_id].escrow_unlock_block = block.number + ESCROW_LOCK
    else:
        # Rejected: stake distributed to rejecting voters (multi-winner)
        # Escrow locked so proposer can't recapture via MEV
        self.proposals[proposal_id].escrow_unlock_block = block.number + ESCROW_LOCK

    log ProposalResolved(
        proposal_id=proposal_id,
        approved=approved,
        approve_count=p.approve_count,
        reject_count=p.reject_count,
    )

# === Claim Rewards ===

@external
def claim_reward(proposal_id: bytes32):
    """
    @notice Claim reward for voting on the winning side.
    @dev Multi-winner: ALL correct voters split the reward equally.
    """
    p: Proposal = self.proposals[proposal_id]
    assert p.resolved, "not resolved"
    assert block.number >= p.escrow_unlock_block, "escrow locked"
    assert not self.claimed[msg.sender][proposal_id], "already claimed"

    reward: uint256 = 0

    if p.approved:
        # Approved: proposer gets stake back
        if msg.sender == p.proposer:
            reward = p.stake
        # Approvers get nothing extra (they endorsed the update)
    else:
        if p.reject_count == 0:
            # No quorum: no one earned the stake, so refund proposer.
            if msg.sender == p.proposer:
                reward = p.stake
        else:
            vote: uint8 = self.reveals[msg.sender][proposal_id]
            assert vote > 0, "did not vote"
            # Rejected: rejectors split the proposer's stake
            if vote == 2:  # rejected
                reward = p.stake // p.reject_count

    assert reward > 0, "no reward"
    self.claimed[msg.sender][proposal_id] = True

    send(msg.sender, reward)
    log RewardClaimed(proposal_id=proposal_id, voter=msg.sender, amount=reward)

# === Views ===

@view
@external
def get_proposal(proposal_id: bytes32) -> (address, bytes32, bytes16, uint256, uint256, uint256, bool, bool, uint256, uint256):
    p: Proposal = self.proposals[proposal_id]
    return (
        p.proposer,
        p.new_value_x_high,
        p.new_value_x_low,
        p.stake,
        p.commit_deadline,
        p.reveal_deadline,
        p.resolved,
        p.approved,
        p.approve_count,
        p.reject_count,
    )

@view
@external
def is_active(proposal_id: bytes32) -> bool:
    p: Proposal = self.proposals[proposal_id]
    return p.commit_deadline > 0 and not p.resolved

@view
@external
def current_value_x() -> (bytes32, bytes16):
    return (self.current_value_x_high, self.current_value_x_low)
