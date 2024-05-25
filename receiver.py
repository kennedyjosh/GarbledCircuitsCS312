# receiver.py (Party P_B)
from common import SUFFIX_LEN
from cryptography.fernet import Fernet, InvalidToken
from oblivious_transfer.ot import Bob
import pickle
from pprint_custom import CustomPrettyPrinter as CPP
import socket
import struct

# ID for printed logs coming from this file
ME = "[RECEIVER] "


def solve_circuit(garbled_circuit):
    """
    Approach: start from the gate with the highest value label, assuming that is the last gate.
              Recursively decrypt the gates that are its inputs.
    Args:
        garbled_circuit: garbled circuit sent by receiver (more info in Circuit.garble)
    Returns:
        decrypted output
    """
    last_gate = max(garbled_circuit.keys())
    print(ME + f"Starting to solve circuit from gate {last_gate}")
    return _solve_circuit(last_gate, garbled_circuit)


def _solve_circuit(gate, garbled_circuit):
    """
    Private recursive function that will recursively solve all gates
    Args:
        gate: label for the gate to solve in this step
        garbled_circuit: garbled circuit sent by receiver (more info in Circuit.garble)
    Returns:
        decrypted output of the gate
    """
    # Base case: gate is None (this happens in case of 'not' gate which requires only 1 input
    if gate is None:
        return None
    # Base case: this gate has a value
    if "value" in garbled_circuit[gate]:
        value = garbled_circuit[gate]["value"]
        print(ME + f"Gate {gate} already has a value: {value[-SUFFIX_LEN:]}")
        return value
    # Otherwise, try to solve gates needed to solve this one
    assert "inputs" in garbled_circuit[gate], f"Gate {gate} has no value and does not list inputs"
    input1 = _solve_circuit(garbled_circuit[gate]["inputs"][0], garbled_circuit)
    input2 = _solve_circuit(garbled_circuit[gate]["inputs"][1], garbled_circuit)
    # Use these inputs to solve for an encrypted row
    value = None
    for row in garbled_circuit[gate]["rows"]:
        try:
            # input2 may not exist if we are decrypting the not gate
            if input2:
                value = Fernet(input2).decrypt(Fernet(input1).decrypt(row))
                break
            else:
                value = Fernet(input1).decrypt(row)
                break
        except InvalidToken:
            value = None
    assert value is not None, f"Unable to decrypt gate {gate}"
    # Insert this value into the garbled circuit, so we don't need to re-calculate later
    garbled_circuit[gate]["value"] = value
    print(ME + f"Decrypted gate {gate} at row = {row[-SUFFIX_LEN:]}: {value[-SUFFIX_LEN:]}")
    return value


# Receive garbled circuit from sender and evaluate
def run(receiver_input, host="localhost", port=9999, store_output=None):
    """
    Receives a garbled circuit from the sender and evaluates it.

    Args:
        receiver_input: 0-3; the intended 2-bit input for the receiver
        host (str): The host address to listen on. Defaults to "localhost".
        port (int): The port number to listen on. Defaults to 9999.
    """
    assert 0 <= receiver_input <= 3 and int(receiver_input) == receiver_input, \
        "Input must be a positive integer less than 4"

    # Create a server socket and start listening for connections
    with socket.create_server((host, port)) as server:
        print(ME + f"Waiting to receive connection from sender...")
        # Accept initial connection from sender
        connection, _ = server.accept()
        with connection:
            print(ME + "Connected with sender")
            # First message from sender contains the public key for OT
            serialized_data = b''
            while serialized_data == b'':
                serialized_data = connection.recv(4096)
            data = pickle.loads(serialized_data)
            print(ME + f"Received first message from sender")

            # Bob must choose 2 keys for the 2 bits in his number
            # bit1 * 2^1 + bit2 * 2^0 = receiver_input
            bit1 = 1 if receiver_input >= 2 else 0
            bit2 = (receiver_input & 0b1) + 2
            bob = Bob([bit1, bit2])
            f = bob.setup(data["pubkey"]["e"], data["pubkey"]["n"], data["hashes"], data["secret_length"])
            serialized_data = pickle.dumps({"f": f})
            connection.sendall(serialized_data)
            print(ME + f"Sending selections to the sender...")

            # Receive the size of the incoming data first
            raw_msglen = connection.recv(4)
            if not raw_msglen:
                raise ValueError("Invalid message length received")
            msglen = struct.unpack('!I', raw_msglen)[0]

            # Receive the actual data based on the length
            serialized_data = b''
            while len(serialized_data) < msglen:
                packet = connection.recv(4096)
                if not packet:
                    break
                serialized_data += packet
            print(ME + "Received garbled circuit from the sender")

            data = pickle.loads(serialized_data)
            G = data["G"]
            garbled_circuit = data["garbled_circuit"]
            key2, key3 = bob.receive(G)
            # Find where these keys belong in the garbled circuit
            print(ME + f"My input is {receiver_input}")
            found = [False, False]
            for gate_label in garbled_circuit:
                if "value" in garbled_circuit[gate_label]:
                    if key2 in garbled_circuit[gate_label]["value"]:
                        print(ME + f"Chose value for bit 0: {key2[-SUFFIX_LEN:]}")
                        garbled_circuit[gate_label]["value"] = key2
                        found[0] = True
                    elif key3 in garbled_circuit[gate_label]["value"]:
                        print(ME + f"Chose value for bit 1: {key3[-SUFFIX_LEN:]}")
                        garbled_circuit[gate_label]["value"] = key3
                        found[1] = True
                if found == [True, True]:
                    break
            assert found == [True, True], "Decrypted keys were not found in garbled circuit"

            print("Garbled circuit just before solving:")
            CPP(indent=1).pprint(garbled_circuit)

            # Try to solve the circuit
            output = solve_circuit(garbled_circuit)
            print(f"[{ME}] Decrypted output: {output}")

            # Store output (used to verify solution in tests)
            if store_output is not None:
                store_output[0] = output

