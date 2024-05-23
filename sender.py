# sender.py (Party P_A)
from cryptography.fernet import Fernet, InvalidToken
import otc
import pickle
import random
import socket
from circuit import define_circuit, garble_circuit
import struct
import sys

# ID for printed logs coming from this file
ME = "SENDER"
# For long encrypted values, just print the suffix of defined length
SUFFIX_LEN = 10




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

        serialized_data = b''
        while serialized_data == b'':
            serialized_data = server.recv(4096)
        data = pickle.loads(serialized_data)


        enc_rows_to_send = []
        enc_1 = []
        enc_2 = []
        enc_3 = []
        for index, (enc_zero, enc_one, enc_gate) in enumerate(garbled_circuit):
            new_gate = []
            enc_sender_input = enc_zero if sender_input == 0 else enc_one
            for enc_row in enc_gate:
                try:
                    enc_1.append(s.reply(data["selection"], enc_zero[:16], enc_one[:16]))
                    enc_2.append(s.reply(data["selection"], enc_zero[16:32], enc_one[16:32]))
                    enc_3.append(s.reply(data["selection"], enc_zero[32:] + b'1234', enc_one[32:] + b'1234'))
                    partial_decryption = Fernet(enc_sender_input).decrypt(enc_row)
                    new_gate.append(partial_decryption)
                    print(f"[{ME}] Successful partial decryption of row {enc_row[-SUFFIX_LEN:]} to {partial_decryption[-SUFFIX_LEN:]}")
                except InvalidToken:
                    continue
            enc_rows_to_send.append(new_gate)


        # # Receive response from receiver with their requested input
        # # Note that sender cannot deduce which input the receiver selected due to OT properties
        # serialized_data = b''
        # while serialized_data == b'':
        #     serialized_data = server.recv(4096)
        # data = pickle.loads(serialized_data)
        # Reply with both inputs, only one of which the receiver will be able to decrypt
        # Since this is the last message, also send the garbled circuit
        data = {
            # the otc library dictates that the inputs must be of length 16
            # since the Fernet keys are of length 44, we must send it in parts
            # since 44 is not divisible by 16 we must also add arbitrary data to the end of the last part
            # the receiver can concatenate these 3 messages and then trim to input_size to get the full key
            1: enc_1,
            2: enc_2,
            3: enc_3,
            "input_size": 44,
            "garbled_circuit": enc_rows_to_send
        }
        serialized_data = pickle.dumps(data)
        server.sendall(serialized_data)
        print(f"[{ME}] Garbled circuit and receiver inputs sent.")

