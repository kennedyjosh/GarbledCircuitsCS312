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
<<<<<<< HEAD
    """
    raise NotImplementedError


def run(sender_input, host="localhost", port=9999):
    """
    Constructs and sends a garbled circuit to a receiver.

    Args:
        sender_input: 0 or 1; the intended input for the sender
        host (str): The host address to listen on. Defaults to "localhost".
        port (int): The port number to listen on. Defaults to 9999.
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

    # Initialize oblivious transfer protocol
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
        data = pickle.loads(serialized_data)
        # Reply with both inputs, only one of which the receiver will be able to decrypt
        # Since this is the last message, also send the garbled circuit
        data = {
            # the otc library dictates that the inputs must be of length 16
            # since the Fernet keys are of length 44, we must send it in parts
            # since 44 is not divisible by 16 we must also add arbitrary data to the end of the last part
            # the receiver can concatenate these 3 messages and then trim to input_size to get the full key
            1: s.reply(data["selection"], enc_zero[:16], enc_one[:16]),
            2: s.reply(data["selection"], enc_zero[16:32], enc_one[16:32]),
            3: s.reply(data["selection"], enc_zero[32:] + b'1234', enc_one[32:] + b'1234'),
            "input_size": 44,
            "garbled_circuit": enc_rows_to_send
        }
        serialized_data = pickle.dumps(data)
        server.sendall(serialized_data)
        print(f"[{ME}] Garbled circuit and receiver inputs sent.")

