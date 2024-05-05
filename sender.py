# sender.py (Party P_A)
import socket
import json
import hmac
import hashlib
import os

# Generate encryption keys for wires (0 and 1)
def generate_wire_keys():
    """
    Generates two random wire keys.

    Returns:
        key_0, key_1: A tuple containing two randomly generated wire keys.
    """
    key_0 = os.urandom(16)
    key_1 = os.urandom(16)
    print(f"Generated wire keys: Key 0 = {key_0.hex()}, Key 1 = {key_1.hex()}")
    return key_0, key_1

# Encrypt a gate based on input wire values using HMAC
def encrypt_gate(input_key1, input_key2, output_key_0, output_key_1):
    """
    Encrypts the gate output for all possible combinations of input keys.

    Args:
        input_key1 (bytes): The first input key.
        input_key2 (bytes): The second input key.
        output_key_0 (bytes): The output key when the gate logic evaluates to 0.
        output_key_1 (bytes): The output key when the gate logic evaluates to 1.

    Returns:
        encrypted_gate: A list of encrypted gate outputs for all possible combinations of input keys.
    """
    encrypted_gate = []
    for wa in [0, 1]:
        for wb in [0, 1]:
            wc = wa & wb  # AND gate logic
            output_key = output_key_0 if wc == 0 else output_key_1

            # Use HMAC for encryption
            derived_key = hmac.new(input_key1 + input_key2, output_key, hashlib.sha256).digest()
            encrypted_value = hmac.new(derived_key, output_key, hashlib.sha256).digest()
            encrypted_gate.append(encrypted_value.hex())

            print(f"Encrypted gate output for inputs (wa={wa}, wb={wb}): {encrypted_value.hex()}")

    return encrypted_gate

# Garble the circuit
def garble_circuit():
    """
    Garbles the circuit by generating garbled gates and keys for input wires.

    Returns:
        garbled_circuit: A dictionary representing the garbled circuit, containing the garbled gates and input keys.
    """
    print("Garbling circuit...")

    input_keys = {
        "A": generate_wire_keys(),
        "B": generate_wire_keys()
    }
    gate_keys = {
        "G1": generate_wire_keys()
    }

    garbled_gate = encrypt_gate(input_keys["A"][0], input_keys["B"][0], gate_keys["G1"][0], gate_keys["G1"][1])

    garbled_circuit = {
        "gates": {
            "G1": garbled_gate
        },
        "inputs": {
            "A": [key.hex() for key in input_keys["A"]],
            "B": [key.hex() for key in input_keys["B"]]
        },
        "outputs": {
            "G1": [key.hex() for key in gate_keys["G1"]]
        }
    }

    print("Circuit garbled successfully.")
    return garbled_circuit

# Send garbled circuit to receiver
def send_garbled_circuit(host="localhost", port=9999):
    """
    Sends a garbled circuit to a receiver.

    Args:
        host (str): The host address of the receiver. Defaults to "localhost".
        port (int): The port number of the receiver. Defaults to 9999.
    """
    circuit = garble_circuit()
    serialized_data = json.dumps(circuit)

    print("Sending garbled circuit to receiver...")
    with socket.create_connection((host, port)) as s:
        s.sendall(serialized_data.encode("utf-8"))
    print("Garbled circuit sent.")

if __name__ == "__main__":
    send_garbled_circuit()
