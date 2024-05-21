# sender.py (Party P_A)
from cryptography.fernet import Fernet, InvalidToken
import otc
import pickle
import random
import socket


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
    enc_zero = Fernet.generate_key()
    enc_one = Fernet.generate_key()
    encrypted_gate = []  # holds each encrypted row of truth table
    # Iterate over and encrypt each row in the truth table
    for row in truth_table:
        wa, wb, wc = row
        enc_a = enc_zero if wa == 0 else enc_one
        enc_b = enc_zero if wb == 0 else enc_one if wb is not None else b''
        enc_row = Fernet(enc_a).encrypt(Fernet(enc_b).encrypt(bytes(str(wc), encoding="utf-8")))
        encrypted_gate.append(enc_row)
        print(f"[{ME}] Encrypting inputs wa={wa}, wb={wb} | encrypted output row: {enc_row[-SUFFIX_LEN:]}")
    # Shuffle the order of the encrypted rows, otherwise one can deduce the truth table by convention
    random.shuffle(encrypted_gate)  # the shuffling occurs in-place
    return enc_zero, enc_one, encrypted_gate


def garble_circuit(circuit_input):
    garbled_circuit = []
    for gate in circuit_input:
        truth_table = generate_truth_table(gate.gate_type)
        enc_zero, enc_one, enc_gate = encrypt_gate(truth_table)
        garbled_circuit.append((gate, enc_zero, enc_one, enc_gate))
    return garbled_circuit


def run(sender_input, host="localhost", port=9999):
    """
    Constructs and sends a garbled circuit to a receiver.

    Args:
        sender_input: 0 or 1; the intended input for the sender
        host (str): The host address to listen on. Defaults to "localhost".
        port (int): The port number to listen on. Defaults to 9999.
    """

    circuit_definition = define_circuit()
    garbled_circuit = garble_circuit(circuit_definition)

    s = otc.send()

    print(f"[{ME}] Initiating contact with the receiver...")

    # Create a socket connection to the receiver
    with socket.create_connection((host, port)) as server:

        # Send the public key to initiate OT
        serialized_data = pickle.dumps({"pub_key": s.public})
        server.sendall(serialized_data)

        # Receive response from receiver with their requested input
        # Note that sender cannot deduce which input the receiver selected due to OT properties
        serialized_data = b''
        while serialized_data == b'':
            serialized_data = server.recv(4096)
    
        # Reply with both inputs, only one of which the receiver will be able to decrypt
        # Since this is the last message, also send the garbled circuit
        data = pickle.loads(serialized_data)

        inputs = []
        for gate, enc_zero, enc_one, _ in garbled_circuit:
            inputs.append(s.reply(data["selection"], enc_zero, enc_one))

        enc_rows_to_send = []
        for gate, enc_zero, enc_one, enc_gate in garbled_circuit:
            enc_sender_input = enc_zero if sender_input == 0 else enc_one
            for enc_row in enc_gate:
                try:
                    partial_decryption = Fernet(enc_sender_input).decrypt(enc_row)
                    enc_rows_to_send.append(partial_decryption)
                    print(f"[{ME}] Successful partial decryption of row {enc_row[-SUFFIX_LEN:]} to {partial_decryption[-SUFFIX_LEN:]}")
                except InvalidToken:
                    continue

        data = {
            "inputs": inputs,
            "garbled_circuit": garbled_circuit,
            "input_size": 44
        }
        serialized_data = pickle.dumps(data)
        server.sendall(serialized_data)
        print(f"[{ME}] Garbled circuit and receiver inputs sent.")

