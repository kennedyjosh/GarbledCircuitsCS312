# sender.py (Party P_A)
from common import SUFFIX_LEN
from oblivious_transfer.ot import Alice
import pickle
from pprint_custom import CustomPrettyPrinter as CPP
import socket
from circuit import Circuit, Gate
import struct

# ID for printed logs coming from this file
ME = "[SENDER] "


def get_comparator_circuit():
    # this circuit will compare two 2-bit inputs a, b, and return 1 a < b
    # Inputs are 0-3, output is 12
    return [
        Gate("NOT", 0, None, 4),
        Gate("AND", 2, 4, 5),  # b1 & a1'
        Gate("AND", 3, 2, 6),
        Gate("NOT", 1, None, 7),
        Gate("AND", 6, 7, 8),  # b0 & b1 & a0'
        Gate("AND", 4, 7, 9),
        Gate("AND", 9, 3, 10),  # a1' & a0' & b0
        Gate("OR", 5, 8, 11),
        Gate("OR", 11, 10, 12)  # final result
    ]


def run(sender_input, host="localhost", port=9999):
    """
    Constructs and sends a garbled circuit to a receiver.

    Args:
        sender_input: 0-3; the intended 2-bit input for the sender
        host (str): The host address to listen on. Defaults to "localhost".
        port (int): The port number to listen on. Defaults to 9999.
    """
    assert 0 <= sender_input <= 3 and int(sender_input) == sender_input, \
        "Input must be a positive integer less than 4"

    gates = get_comparator_circuit()
    circuit = Circuit(gates)
    garbled_circuit = circuit.garble()
    print("Initial garbled circuit:")
    CPP(indent=1).pprint(garbled_circuit)

    # Choose sender's input w0,w1 where w0 ** 2^1 + w1 ** 2^0 == input
    print(ME + f"My input is {sender_input}")
    garbled_circuit[0]["value"] = garbled_circuit[0]["value"][int(sender_input >= 2)]
    print(ME + f"Chose value for bit 0: {garbled_circuit[0]['value'][-SUFFIX_LEN:]}")
    garbled_circuit[1]["value"] = garbled_circuit[1]["value"][sender_input & 0b1]
    print(ME + f"Chose value for bit 1: {garbled_circuit[1]['value'][-SUFFIX_LEN:]}")

    print(ME + "Initiating contact with the receiver...")

    # Create a socket connection to the receiver
    with socket.create_connection((host, port)) as server:

        # Send first set of data for OT
        # Allow receiver to choose 2 inputs, 1 from the first 2 and 1 from the last 2
        alice = Alice([garbled_circuit[2]["value"][0], garbled_circuit[2]["value"][1],
                       garbled_circuit[3]["value"][0], garbled_circuit[3]["value"][1]], 2)
        data = alice.setup()
        serialized_data = pickle.dumps(data)
        print(ME + f"Sending initial OT data to the receiver...")
        server.sendall(serialized_data)

        # Get OT message back from Bob and send him the final info
        serialized_data = b''
        while serialized_data == b'':
            serialized_data = server.recv(4096)
        data = pickle.loads(serialized_data)
        print(ME + f"Received selection from receiver")
        f = data["f"]
        G = alice.transmit(f)
        data = {
            "G": G,
            "garbled_circuit": garbled_circuit
        }
        print(ME + "Sending final msg for OT and the garbled circuit...")
        serialized_data = pickle.dumps(data)
        
        # Send data length first
        server.sendall(struct.pack('!I', len(serialized_data)))
        # Then send actual data
        server.sendall(serialized_data)
        print(ME + "Done")

