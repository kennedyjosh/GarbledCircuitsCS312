# sender.py (Party P_A)
from cryptography.fernet import Fernet, InvalidToken
import otc
import pickle
import random
import socket
from circuit import define_circuit, garble_circuit
import struct

# ID for printed logs coming from this file
ME = "SENDER"
# For long encrypted values, just print the suffix of defined length
SUFFIX_LEN = 10

def pad_input(input_data, size=32):
    """
    Pad each element in the input tuple to the specified size.
    """
    return tuple(element.ljust(size, b'0') for element in input_data if isinstance(element, bytes))

def run(sender_input, host="localhost", port=9999):
    """
    Constructs and sends a garbled circuit to a receiver.

    Args:
        sender_input: 0-3; the intended 2-bit input for the sender
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
        for gate, ot_enc_zero, ot_enc_one, enc_zero, enc_one, _ in garbled_circuit:
            inputs.append(s.reply(data["selection"], ot_enc_zero, ot_enc_one))

        enc_rows_to_send = []
        for gate, ot_enc_zero, ot_enc_one, enc_zero, enc_one, enc_gate in garbled_circuit:
            enc_sender_input = enc_zero if sender_input == 0 else enc_one
            for enc_row in enc_gate:
                try:
                    partial_decryption = Fernet(enc_sender_input).decrypt(enc_row)
                    enc_rows_to_send.append(partial_decryption)
                    print(f"[{ME}] Successful partial decryption of row {enc_row[-SUFFIX_LEN:]} to {partial_decryption[-SUFFIX_LEN:]}")
                except InvalidToken:
                    continue

        padded_inputs = [pad_input(enc_input) for enc_input in inputs]
        data = {
            "inputs": padded_inputs,
            "garbled_circuit": garbled_circuit,
            "input_size": 44
        }
        serialized_data = pickle.dumps(data)
        
        # Send data length first
        server.sendall(struct.pack('!I', len(serialized_data)))
        # Then send actual data
        server.sendall(serialized_data)
        print(f"[{ME}] Garbled circuit and receiver inputs sent.")
