# sender.py (Party P_A)
from cryptography.fernet import Fernet, InvalidToken
import pickle
import random
import socket


# ID for printed logs coming from this file
ME = "SENDER"
# For long encrypted values, just print the suffix of defined length
SUFFIX_LEN = 10


def encrypt(a: bytes, b: bytes, out: bytes):
    """
    Encrypts a single row in a truth table where `a` and `b` are the inputs and `out` is the output.
    To decrypt the `enc_out` returned by this function, you would need both `enc_a` and `enc_b`

    Args:
        a: bytes
        b: bytes
        out: bytes

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
        enc_truth_table: list of tuples where each tuple in the format (encrypted_input1, enc

        enc_zero: encrypted input key for 0
        enc_one: encrypted input key for 1
        encrypted_gate: A list of encrypted gate outputs for all possible combinations of input keys.
    """
    # Initialize some variables
    enc_zero = Fernet.generate_key()
    enc_one = Fernet.generate_key()
    encrypted_inputs = [enc_zero, enc_one]
    encrypted_gate = []  # holds each encrypted row of truth table
    # Iterate over and encrypt each row in the truth table
    for wa, wb, wc in truth_table:
        enc_a = encrypted_inputs[wa]
        enc_b = encrypted_inputs[wb]
        enc_row = encrypt(enc_a, enc_b, bytes(str(wc), encoding="utf-8"))
        encrypted_gate.append(enc_row)
        print(f"[{ME}] Encrypting inputs wa={wa}, wb={wb} | encrypted output row: {enc_row[-SUFFIX_LEN:]}")
    # Shuffle the order of the encrypted rows, otherwise one can deduce the truth table by convention
    random.shuffle(encrypted_gate)  # the shuffling occurs in-place
    return enc_zero, enc_one, encrypted_gate


def garble_circuit():
    """
    TODO
    This function will have to take in some circuit and garble each gate
    while keeping track of how each element is linked together.
    """
    raise NotImplementedError


def run(sender_input, host="localhost", port=9999):
    """
    Sends a garbled circuit to a receiver.

    Args:
        input_A (int): The value of input wire A (0 or 1).
        input_B (int): The value of input wire B (0 or 1).
        host (str): The host address of the receiver. Defaults to "localhost".
        port (int): The port number of the receiver. Defaults to 9999.
    """
    # TODO: this is just a single "and" gate, for now
    # Generate the garbled gate
    combinations = [(0, 0, 0), (0, 1, 0), (1, 0, 0), (1, 1, 1)]  # in the format (input1, input2, output)
    enc_zero, enc_one, enc_gate = encrypt_gate(combinations)

    # Partially decrypt the gate so that the receiver only needs their key
    # For a simple truth table of 4 rows, only 2 will be possible for the receiver to complete
    enc_sender_input = enc_zero if sender_input == 0 else enc_one
    enc_rows_to_send = []
    for enc_row in enc_gate:
        try:
            partial_decryption = Fernet(enc_sender_input).decrypt(enc_row)
            enc_rows_to_send.append(partial_decryption)
            print(f"[{ME}] Successful partial decryption of row {enc_row[-SUFFIX_LEN:]} to {partial_decryption[-SUFFIX_LEN:]}")
        except InvalidToken:
            continue

    # Serialize the circuit data
    data = {
        "receiver_inputs": [enc_zero, enc_one],
        "encrypted_rows": enc_rows_to_send
    }
    serialized_data = pickle.dumps(data)

    print(f"[{ME}] Sending garbled circuit to receiver...")

    # Create a socket connection to the receiver
    with socket.create_connection((host, port)) as s:
        # Send the serialized circuit data
        s.sendall(serialized_data)
    print(f"[{ME}] Garbled circuit sent.")

if __name__ == "__main__":
    run(int(input("Enter the value for the sender's input (0 or 1): ")))

