from cryptography.fernet import Fernet, InvalidToken
import random
import os


# ID for printed logs coming from this file
ME = "SENDER"
# For long encrypted values, just print the suffix of defined length
SUFFIX_LEN = 10

class Gate:
    def __init__(self, gate_type, input1, input2=None, output=None):
        self.gate_type = gate_type
        self.input1 = input1
        self.input2 = input2
        self.output = output

def define_circuit():
    return [
        #Starting inputs, 0-4, not output 5, 
        Gate("NOT", 0, output=5),
        Gate("AND", 3, 5, output=6),
        Gate("XOR", 2, 6, output=7),
        Gate("OR", 4, 6, output=8),
        Gate("AND", 7, 8, output=9),
        Gate("OR", 6, 9, output=10),
    ]

def generate_truth_table(gate_type):
    if gate_type == "AND":
        return [(0, 0, 0), (0, 1, 0), (1, 0, 0), (1, 1, 1)]
    elif gate_type == "OR":
        return [(0, 0, 0), (0, 1, 1), (1, 0, 1), (1, 1, 1)]
    elif gate_type == "XOR":
        return [(0, 0, 0), (0, 1, 1), (1, 0, 1), (1, 1, 0)]
    elif gate_type == "NOT":
        return [(0, None, 1), (1, None, 0)]
    else:
        raise ValueError("Unsupported gate type:")
    
def encrypt(a: bytes, b: bytes, out: bytes):
    """
    Encrypts a single row in a truth table where `a` and `b` are the inputs and `out` is the output.
    To decrypt the `enc_out` returned by this function, you would need both `a` and `b`

    Args:
        a: a 32-length key corresponding to the first input
        b: a 32-length key corresponding to the second input
        out: bytes representing the output (this will be the result post-decryption)

    Returns:
        enc_out: the doubly-encrypted output of the row
    """
    assert type(a) is bytes
    assert type(b) is bytes
    assert type(out) is bytes
    return Fernet(a).encrypt(Fernet(b).encrypt(out))

def encrypt_gate(truth_table: list[tuple]):
    """
    Encrypts the gate output for all possible combinations of input keys.

    Args:
        truth_table: list of tuples where each tuple in the format (input1, input2, output)
                     describes a row in the truth table of the gate

    Returns:
        enc_zero: encrypted input key for 0
        enc_one: encrypted input key for 1
        encrypted_gate: A list of encrypted gate outputs for all possible combinations of input keys.
    """
    # Initialize some variables
    # gate_key = Fernet.generate_key()
    enc_zero = Fernet.generate_key()
    enc_one = Fernet.generate_key()
    encrypted_inputs = [enc_zero, enc_one]
    encrypted_gate = []  # holds each encrypted row of truth table
    # Iterate over and encrypt each row in the truth table
    for wa, wb, wc in truth_table:
        enc_a = encrypted_inputs[wa]
        enc_b = encrypted_inputs[wa]
        if wb:
            enc_b = encrypted_inputs[wb]
        enc_row = encrypt(enc_a, enc_b, bytes(str(wc), encoding="utf-8"))
        encrypted_gate.append(enc_row)
        print(f"[{ME}] Encrypting inputs wa={wa}, wb={wb} | encrypted output row: {enc_row[-SUFFIX_LEN:]}")
    # Shuffle the order of the encrypted rows, otherwise one can deduce the truth table by convention
    random.shuffle(encrypted_gate)  # the shuffling occurs in-place
    return enc_zero, enc_one, encrypted_gate # gate_key

def garble_circuit(circuit_input):
    garbled_circuit = []
    for gate in circuit_input:
        truth_table = generate_truth_table(gate.gate_type)
        print(truth_table)
        enc_zero, enc_one, enc_gate = encrypt_gate(truth_table)
        garbled_circuit.append((enc_zero, enc_one, enc_gate))
    return garbled_circuit