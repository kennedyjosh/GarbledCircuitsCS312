# sender.py (Party P_A)
import socket
import json
from run_garbled_circuit import simple_hash
import os

# Generate encryption keys for wires (0 and 1)
def generate_wire_keys():
    """
    Generates two random wire keys.

    This function generates two random wire keys using the os.urandom() function.
    Each wire key is a 16-byte (128-bit) random value.

    Returns:
        key_0, key_1: A tuple containing two randomly generated wire keys.
    """
    # Generate a random 16-byte key for wire 0
    key_0 = os.urandom(16)

    # Generate a random 16-byte key for wire 1
    key_1 = os.urandom(16)
    print(f"Generated wire keys: Key 0 = {key_0.hex()}, Key 1 = {key_1.hex()}")

    # Return the generated wire keys as a tuple
    return key_0, key_1

# Encrypt a gate based on input wire values
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
    # Initialize an empty list to store the encrypted gate values
    encrypted_gate = []
    combinations = [(0, 0), (0, 1), (1, 0), (1, 1)]
    # Iterate over all possible combinations of inputs (wa and wb)
    for wa, wb in combinations:
        wc = wa & wb  # AND gate logic
        # Determine the output key based on the value of wc
        output_key = output_key_1 if wc == 1 else output_key_0
        hashed_output = simple_hash(output_key)
        # Convert the encrypted value to its hexadecimal representation and append it to the list
        encrypted_gate.append(hashed_output.hex())
        print(f"Encrypting inputs (wa={wa}, wb={wb}): Using output key={output_key.hex()} results in hash={hashed_output.hex()}")

    # Return the list of encrypted gate values
    return encrypted_gate

# Garble the circuit
def garble_circuit(input_A, input_B):
    """
    Garbles the circuit by generating garbled gates and keys for input wires.

    Args:
        input_A (int): The value of input wire A (0 or 1).
        input_B (int): The value of input wire B (0 or 1).

    Returns:
        garbled_circuit: A dictionary representing the garbled circuit, containing the garbled gates and input keys.
    """
    print("Garbling circuit...")
    # Set the input values
    input_keys_A = [b'\x00'*15 + bytes([input_A]), os.urandom(16)]  # Ensuring clear distinction
    input_keys_B = [b'\x00'*15 + bytes([input_B]), os.urandom(16)]
    # Generate gate keys for gate G1
    gate_keys = [os.urandom(16), os.urandom(16)]

    print(f"Input A keys: {input_keys_A[0].hex()}, {input_keys_A[1].hex()}")
    print(f"Input B keys: {input_keys_B[0].hex()}, {input_keys_B[1].hex()}")

    # Encrypt gate G1 using input keys and gate keys
    garbled_gate = encrypt_gate(input_keys_A[0], input_keys_B[0], gate_keys[0], gate_keys[1])

    # Create the garbled circuit dictionary
    garbled_circuit = {
        "gates": {
            "G1": garbled_gate
        },
        "inputs": {
            "A": [key.hex() for key in input_keys_A],  # Ensure both input keys are converted to hex
            "B": [key.hex() for key in input_keys_B]
        },
        "outputs": {
            "G1": [key.hex() for key in gate_keys]  # Convert gate output keys to hex
        }
    }

    # Print success message and return the garbled circuit
    print("Circuit garbled successfully.")
    return garbled_circuit

# Send garbled circuit to receiver
def send_garbled_circuit(input_A, input_B, host="localhost", port=9999):
    """
    Sends a garbled circuit to a receiver.

    Args:
        input_A (int): The value of input wire A (0 or 1).
        input_B (int): The value of input wire B (0 or 1).
        host (str): The host address of the receiver. Defaults to "localhost".
        port (int): The port number of the receiver. Defaults to 9999.
    """
    # Generate the garbled circuit
    circuit = garble_circuit(input_A, input_B)

    # Serialize the circuit data
    serialized_data = json.dumps(circuit)

    print("Sending garbled circuit to receiver...")

    # Create a socket connection to the receiver
    with socket.create_connection((host, port)) as s:
        # Send the serialized circuit data
        s.sendall(serialized_data.encode("utf-8"))
    print("Garbled circuit sent.")

if __name__ == "__main__":
    input_A = int(input("Enter the value for input A (0 or 1): "))
    input_B = int(input("Enter the value for input B (0 or 1): "))
    send_garbled_circuit(input_A, input_B)