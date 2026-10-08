#!/usr/bin/env python3
# TODO: eventually add networked mining and transaction signing
# TODO: maybe put this into gs_usb driver
import argparse
import hashlib
import json
import os
import random
import re
import sys
import time

POW_ZERO_BYTES = 2          # Leading zero bytes the proof of work needs
CAN_CMD_BASE = 0x18FFDA00   # Extended CAN ID base for host -> ECU trigger
CAN_RSP_BASE = 0x18FFDB00   # Extended CAN ID base for ECU -> host result
ECU_ADDRESSES = {"B": 0x0B, "C": 0x0C, "D": 0x0D}
SLCAN_BAUDRATE = 2000000
COINBASE = "COINBASE"
BLOCK_REWARD = 50
MAX_TXS_PER_BLOCK = 20
NO_HASH = "0" * 64
ACCOUNT_NAME = re.compile(r"[A-Za-z0-9_-]{1,32}")

class LedgerError(Exception):
    """The ledger or a requested change breaks a chain rule."""

# ---- Hashing ----

def sha256(data):
    return hashlib.sha256(data).digest()

def tx_hash(tx):
    return sha256(f"{tx['from']}|{tx['to']}|{tx['amount']}".encode()).hex()

def merkle_root(txs):
    """Pairwise-hash the transaction hashes up to one root, duplicating the last one when odd."""
    level = [bytes.fromhex(tx_hash(tx)) for tx in txs]
    if not level:
        return NO_HASH
    while len(level) > 1:
        if len(level) % 2:
            level.append(level[-1])
        level = [sha256(level[i] + level[i + 1]) for i in range(0, len(level), 2)]
    return level[0].hex()

def header_digest(block):
    header = f"{block['index']}|{block['prev_hash']}|{block['merkle_root']}|{block['timestamp']}"
    return sha256(header.encode())

def challenge_of(block):
    """The 32-bit challenge the nonce is searched against: the first 4 bytes of the header digest."""
    return header_digest(block)[:4].hex().upper()

def block_hash(block):
    return sha256(header_digest(block) + block["nonce"].to_bytes(4, "little")).hex()

def proof_hash(challenge_hex, nonce):
    return sha256(bytes.fromhex(challenge_hex) + nonce.to_bytes(4, "little"))

def has_valid_proof(block):
    return proof_hash(challenge_of(block), block["nonce"])[:POW_ZERO_BYTES] == bytes(POW_ZERO_BYTES)

# ---- Blocks ----

def genesis_block():
    block = {"index": 0, "prev_hash": NO_HASH, "merkle_root": NO_HASH, "timestamp": 0,
             "nonce": 0, "transactions": []}
    block["hash"] = block_hash(block)
    return block

def build_candidate(tip, miner, transfers, timestamp):
    """A block on top of `tip` that pays the reward to `miner`; it still needs a nonce."""
    txs = [{"from": COINBASE, "to": miner, "amount": BLOCK_REWARD}] + transfers
    return {"index": tip["index"] + 1, "prev_hash": tip["hash"], "merkle_root": merkle_root(txs),
            "timestamp": timestamp, "nonce": 0, "transactions": txs}

def seal(block, nonce):
    block["nonce"] = nonce
    block["hash"] = block_hash(block)

def mine_software(challenge_hex, rng=random):
    """Search for a nonce whose proof hash starts with the required zero bytes."""
    nonce = rng.getrandbits(32)
    while proof_hash(challenge_hex, nonce)[:POW_ZERO_BYTES] != bytes(POW_ZERO_BYTES):
        nonce = (nonce + 1) & 0xFFFFFFFF
    return nonce

# ---- Validation ----

def check_account(name):
    if not isinstance(name, str) or ACCOUNT_NAME.fullmatch(name) is None or name == COINBASE:
        raise LedgerError(f"invalid account name {name!r}")

def check_amount(amount):
    if not isinstance(amount, int) or isinstance(amount, bool) or amount <= 0:
        raise LedgerError(f"invalid amount {amount!r}")

def apply_transfer(balances, tx):
    """Check a transfer against `balances` and apply it. Nothing changes if it is rejected."""
    if not isinstance(tx, dict) or set(tx) != {"from", "to", "amount"}:
        raise LedgerError(f"malformed transaction {tx!r}")
    check_account(tx["from"])
    check_account(tx["to"])
    check_amount(tx["amount"])
    if balances.get(tx["from"], 0) < tx["amount"]:
        raise LedgerError(f"{tx['from']} cannot send {tx['amount']}: balance is {balances.get(tx['from'], 0)}")
    balances[tx["from"]] -= tx["amount"]
    balances[tx["to"]] = balances.get(tx["to"], 0) + tx["amount"]

def check_coinbase(tx):
    if (not isinstance(tx, dict) or set(tx) != {"from", "to", "amount"}
            or tx["from"] != COINBASE or tx["amount"] != BLOCK_REWARD):
        raise LedgerError(f"first transaction must be a {BLOCK_REWARD} coin reward from {COINBASE}")
    check_account(tx["to"])

def check_block(block, prev):
    if block["index"] != prev["index"] + 1:
        raise LedgerError("wrong index")
    if block["prev_hash"] != prev["hash"]:
        raise LedgerError("prev_hash does not match the previous block")
    if not isinstance(block["timestamp"], int) or block["timestamp"] < prev["timestamp"]:
        raise LedgerError("timestamp goes backwards")
    txs = block["transactions"]
    if not txs:
        raise LedgerError("block has no transactions")
    check_coinbase(txs[0])
    if block["merkle_root"] != merkle_root(txs):
        raise LedgerError("merkle_root does not match the transactions")
    nonce = block["nonce"]
    if not isinstance(nonce, int) or isinstance(nonce, bool) or not 0 <= nonce <= 0xFFFFFFFF:
        raise LedgerError("nonce is not a 32-bit integer")
    if not has_valid_proof(block):
        raise LedgerError("proof of work is invalid")
    if block["hash"] != block_hash(block):
        raise LedgerError("hash does not match the block contents")

def apply_block(balances, block):
    coinbase, *transfers = block["transactions"]
    balances[coinbase["to"]] = balances.get(coinbase["to"], 0) + coinbase["amount"]
    for tx in transfers:
        apply_transfer(balances, tx)

def validate_chain(chain):
    """Re-check every rule from the genesis block and return the resulting balances."""
    if not chain or chain[0] != genesis_block():
        raise LedgerError("block 0 is not the RAMN Coin genesis block")
    balances = {}
    for index, (prev, block) in enumerate(zip(chain, chain[1:]), start=1):
        try:
            check_block(block, prev)
            apply_block(balances, block)
        except LedgerError as error:
            raise LedgerError(f"block {index}: {error}") from None
        except (KeyError, TypeError, ValueError, AttributeError) as error:
            raise LedgerError(f"block {index} is malformed ({error!r})") from None
    return balances

# ---- Ledger file ----

class Ledger:
    def __init__(self, chain, mempool):
        self.chain = chain
        self.mempool = mempool

    @classmethod
    def new(cls):
        return cls([genesis_block()], [])

    @classmethod
    def load(cls, path):
        try:
            with open(path, encoding="utf-8") as handle:
                data = json.load(handle)
        except FileNotFoundError:
            raise LedgerError(f"no ledger at {path}; run 'init' first") from None
        except json.JSONDecodeError as error:
            raise LedgerError(f"{path} is not valid JSON: {error}") from None
        if not isinstance(data, dict) or not isinstance(data.get("chain"), list) \
                or not isinstance(data.get("mempool"), list):
            raise LedgerError(f"{path} is not a RAMN Coin ledger")
        return cls(data["chain"], data["mempool"])

    def save(self, path):
        temporary = f"{path}.tmp"
        with open(temporary, "w", encoding="utf-8") as handle:
            json.dump({"chain": self.chain, "mempool": self.mempool}, handle, indent=2)
        os.replace(temporary, path)

    def valid_pending(self, balances):
        """Return the queued transfers that still apply in order, updating `balances` as it goes."""
        accepted = []
        for tx in self.mempool:
            try:
                apply_transfer(balances, tx)
            except LedgerError:
                continue
            accepted.append(tx)
        return accepted

    def add_transaction(self, sender, recipient, amount):
        balances = validate_chain(self.chain)
        self.valid_pending(balances)
        tx = {"from": sender, "to": recipient, "amount": amount}
        apply_transfer(balances, tx)
        self.mempool.append(tx)

    def append_block(self, block):
        validate_chain(self.chain + [block])
        for tx in block["transactions"][1:]:
            if tx in self.mempool:
                self.mempool.remove(tx)
        self.chain.append(block)

# ---- ECU protocol ----

def normalize_challenge(challenge):
    """Validate a 32-bit hexadecimal challenge and return eight uppercase digits."""
    challenge = challenge.strip()
    if challenge.lower().startswith("0x"):
        challenge = challenge[2:]
    if not 1 <= len(challenge) <= 8 or any(
            digit not in "0123456789abcdefABCDEF" for digit in challenge):
        raise ValueError("challenge must contain 1 to 8 hexadecimal digits")
    return f"{int(challenge, 16):08X}"

def selected_ecus(ecu):
    """Return the list of ECU letters named by a --ecu value."""
    ecu = ecu.upper()
    if ecu == "ALL":
        return sorted(ECU_ADDRESSES)
    if ecu not in ECU_ADDRESSES:
        raise ValueError("ECU must be B, C, D or all")
    return [ecu]

def command_id(ecu):
    return CAN_CMD_BASE | ECU_ADDRESSES[ecu]

def response_id(ecu):
    return CAN_RSP_BASE | ECU_ADDRESSES[ecu]

def ecu_for_response_id(can_id):
    """Return the ECU letter that owns a result CAN ID, or None."""
    for ecu in ECU_ADDRESSES:
        if can_id == response_id(ecu):
            return ecu
    return None

def trigger_data(challenge):
    """Payload of the trigger frame: 'M' followed by the big-endian challenge."""
    return bytes([0x4D]) + int(normalize_challenge(challenge), 16).to_bytes(4, "big")

def slcan_trigger_line(ecu, challenge):
    data = trigger_data(challenge)
    return f"T{command_id(ecu):08X}{len(data):X}{data.hex().upper()}\r"

def parse_slcan_frame(line):
    """Return (can_id, data) for an slcan extended-ID frame, or None for anything else."""
    if isinstance(line, (bytes, bytearray)):
        line = bytes(line).decode("ascii", errors="replace")
    match = re.fullmatch(r"T([0-9A-Fa-f]{8})([0-8])((?:[0-9A-Fa-f]{2})*)", line.strip())
    if match is None:
        return None
    data = bytes.fromhex(match.group(3))
    if len(data) != int(match.group(2)):
        return None
    return int(match.group(1), 16), data

def validate_can_response(data, challenge):
    """Return (nonce, hash_prefix, matches) for a result frame; the ECU sends 3 hash bytes."""
    data = bytes(data)
    if len(data) != 8 or data[0] != 0x52:
        raise ValueError("malformed ECU response")
    nonce = int.from_bytes(data[1:5], "little")
    prefix = data[5:8].hex()
    expected = proof_hash(normalize_challenge(challenge), nonce).hex()[:6]
    return nonce, prefix, prefix == expected

def first_valid_result(frames, challenges):
    """Return (ecu, nonce) for the first result frame that proves work on that ECU's own challenge."""
    for can_id, data in frames:
        ecu = ecu_for_response_id(can_id)
        if ecu not in challenges:
            continue
        try:
            nonce, _, matches = validate_can_response(data, challenges[ecu])
        except ValueError:
            continue
        proof = proof_hash(challenges[ecu], nonce)
        if matches and proof[:POW_ZERO_BYTES] == bytes(POW_ZERO_BYTES):
            return ecu, nonce
    return None

def open_slcan(port):
    try:
        import serial
    except ImportError:
        raise ValueError("pySerial is required for ECU mining: pip install pyserial") from None
    ser = serial.Serial(port, SLCAN_BAUDRATE, timeout=0.5)
    ser.reset_input_buffer()
    ser.write(b"O\r")  # Opening the channel also makes ECU A forward bus frames
    time.sleep(0.3)
    return ser

def iter_slcan_frames(ser, deadline):
    """Yield (can_id, data) for each extended-ID slcan frame read before the deadline."""
    buffer = bytearray()
    while time.monotonic() < deadline:
        buffer.extend(ser.read_until(b"\r"))
        while b"\r" in buffer:
            line, _, rest = bytes(buffer).partition(b"\r")
            buffer = bytearray(rest)
            frame = parse_slcan_frame(line)
            if frame is not None:
                yield frame

def mine_first_via_usb(port, challenges, timeout=30, settle=1.0):
    """Trigger each ECU with its own challenge and return (ecu, nonce) of the first valid result.

    Late results are read for `settle` seconds and dropped, so they cannot leak into the next round.
    """
    ser = open_slcan(port)
    try:
        for ecu, challenge in challenges.items():
            ser.write(slcan_trigger_line(ecu, challenge).encode("ascii"))
        winner = first_valid_result(iter_slcan_frames(ser, time.monotonic() + timeout), challenges)
        if winner is not None:
            for _ in iter_slcan_frames(ser, time.monotonic() + settle):
                pass
    finally:
        ser.write(b"C\r")
        ser.close()
    if winner is None:
        raise TimeoutError(
            f"no valid response from ECU {', '.join(sorted(challenges))} within {timeout:g}s. "
            "Check that ECU B, C and D run the RAMN Coin firmware and the CAN bus is connected.")
    return winner

def probe_ecus(port, ecus, challenge, timeout=30):
    """Trigger the ECUs with `challenge` and report each result. Returns the ECUs that failed."""
    challenge = normalize_challenge(challenge)
    pending, failed = set(ecus), []
    ser = open_slcan(port)
    try:
        for ecu in ecus:
            ser.write(slcan_trigger_line(ecu, challenge).encode("ascii"))
        for can_id, data in iter_slcan_frames(ser, time.monotonic() + timeout):
            ecu = ecu_for_response_id(can_id)
            if ecu not in pending:
                continue
            pending.discard(ecu)
            try:
                nonce, prefix, matches = validate_can_response(data, challenge)
            except ValueError as error:
                failed.append(ecu)
                print(f"[!] ECU {ecu}: {error}")
            else:
                if not matches:
                    failed.append(ecu)
                print(f"[*] ECU {ecu}: nonce=0x{nonce:08X} hash_prefix={prefix} "
                      f"{'OK' if matches else 'MISMATCH'}")
            if not pending:
                break
    finally:
        ser.write(b"C\r")
        ser.close()
    for ecu in sorted(pending):
        print(f"[!] ECU {ecu}: no response within {timeout:g}s")
    return sorted(pending) + failed

# ---- Mining ----

def mine_block(ledger, args):
    tip = ledger.chain[-1]
    transfers = ledger.valid_pending(validate_chain(ledger.chain))[:MAX_TXS_PER_BLOCK]
    timestamp = max(int(time.time()), tip["timestamp"])

    if args.miner == "software":
        block = build_candidate(tip, args.name, transfers, timestamp)
        seal(block, mine_software(challenge_of(block)))
        return block

    candidates = {ecu: build_candidate(tip, f"ecu{ecu}", transfers, timestamp)
                  for ecu in selected_ecus(args.ecu)}
    challenges = {ecu: challenge_of(block) for ecu, block in candidates.items()}
    print(f"[*] Block {tip['index'] + 1}: ECU {', '.join(candidates)} racing for the reward...")
    winner, nonce = mine_first_via_usb(args.port, challenges, args.timeout)
    seal(candidates[winner], nonce)
    return candidates[winner]

def describe_block(block):
    miner = block["transactions"][0]["to"]
    proof = proof_hash(challenge_of(block), block["nonce"]).hex()
    return (f"Block {block['index']} mined by {miner}: nonce=0x{block['nonce']:08X} "
            f"proof={proof[:16]}... hash={block['hash'][:16]}... "
            f"transfers={len(block['transactions']) - 1}")

# ---- Commands ----

def cmd_init(args):
    if os.path.exists(args.ledger) and not args.force:
        raise LedgerError(f"{args.ledger} already exists; use --force to replace it")
    Ledger.new().save(args.ledger)
    print(f"[+] Created {args.ledger} with the genesis block")

def cmd_mine(args):
    ledger = Ledger.load(args.ledger)
    for _ in range(args.blocks):
        block = mine_block(ledger, args)
        ledger.append_block(block)
        ledger.save(args.ledger)
        print(f"[+] {describe_block(block)}")

def cmd_probe(args):
    if probe_ecus(args.port, selected_ecus(args.ecu), args.challenge, args.timeout):
        sys.exit(1)

def cmd_balance(args):
    balances = validate_chain(Ledger.load(args.ledger).chain)
    if args.account:
        print(f"{args.account}: {balances.get(args.account, 0)}")
    elif balances:
        for account, amount in sorted(balances.items()):
            print(f"{account}: {amount}")
    else:
        print("No balances yet; mine a block first.")

def cmd_send(args):
    ledger = Ledger.load(args.ledger)
    ledger.add_transaction(args.sender, args.recipient, args.amount)
    ledger.save(args.ledger)
    print(f"[+] Queued {args.sender} -> {args.recipient}: {args.amount} (included in the next block)")

def cmd_show(args):
    ledger = Ledger.load(args.ledger)
    for block in ledger.chain[1:]:
        print(describe_block(block))
        for tx in block["transactions"][1:]:
            print(f"    {tx['from']} -> {tx['to']}: {tx['amount']}")
    print(f"{len(ledger.chain) - 1} blocks, {len(ledger.mempool)} queued transfers")

def cmd_verify(args):
    ledger = Ledger.load(args.ledger)
    validate_chain(ledger.chain)
    print(f"[+] Chain is valid: {len(ledger.chain) - 1} blocks")

# ---- Main ----

def positive_int(text):
    value = int(text)
    if value <= 0:
        raise argparse.ArgumentTypeError("must be a positive integer")
    return value

def build_parser():
    parser = argparse.ArgumentParser(description="RAMN Coin — an offline educational toy blockchain")
    parser.add_argument("--ledger", default="ramncoin.json", help="Ledger file (default: ramncoin.json)")
    subp = parser.add_subparsers(dest="command", required=True)

    p_init = subp.add_parser("init", help="Create a new ledger")
    p_init.add_argument("--force", action="store_true", help="Replace an existing ledger")
    p_init.set_defaults(handler=cmd_init)

    p_mine = subp.add_parser("mine", help="Mine blocks")
    p_mine.add_argument("--blocks", type=positive_int, default=1, help="Number of blocks (default: 1)")
    p_mine.add_argument("--miner", choices=["ecu", "software"], default="ecu",
                        help="Mine on the ECUs or on the PC (default: ecu)")
    p_mine.add_argument("--ecu", default="all", help="Racing ECUs: B, C, D or all (default: all)")
    p_mine.add_argument("--port", default="/dev/ttyACM0", help="ECU A serial port (default: /dev/ttyACM0)")
    p_mine.add_argument("--timeout", type=float, default=30, help="ECU response timeout in seconds (default: 30)")
    p_mine.add_argument("--name", default="software", help="Reward account for --miner software")
    p_mine.set_defaults(handler=cmd_mine)

    p_probe = subp.add_parser("probe", help="Check that the ECUs answer a mining trigger")
    p_probe.add_argument("--ecu", default="all", help="ECUs to check: B, C, D or all (default: all)")
    p_probe.add_argument("--port", default="/dev/ttyACM0", help="ECU A serial port (default: /dev/ttyACM0)")
    p_probe.add_argument("--timeout", type=float, default=30, help="Response timeout in seconds (default: 30)")
    p_probe.add_argument("--challenge", default="DEADBEEF", help="Test challenge in hex (default: DEADBEEF)")
    p_probe.set_defaults(handler=cmd_probe)

    p_balance = subp.add_parser("balance", help="Show balances")
    p_balance.add_argument("account", nargs="?", help="Only show this account")
    p_balance.set_defaults(handler=cmd_balance)

    p_send = subp.add_parser("send", help="Queue a transfer for the next block")
    p_send.add_argument("sender")
    p_send.add_argument("recipient")
    p_send.add_argument("amount", type=positive_int)
    p_send.set_defaults(handler=cmd_send)

    subp.add_parser("show", help="Print the blocks").set_defaults(handler=cmd_show)
    subp.add_parser("verify", help="Re-validate the whole chain").set_defaults(handler=cmd_verify)
    return parser

def main():
    args = build_parser().parse_args()
    try:
        args.handler(args)
    except (LedgerError, TimeoutError, ValueError, OSError) as error:
        print(f"error: {error}", file=sys.stderr)
        sys.exit(1)

if __name__ == "__main__":
    main()
