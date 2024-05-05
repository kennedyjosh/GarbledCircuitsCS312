# receiver.py (Party P_B)
import socket
import json
import hmac
import hashlib

# Decrypt a single gate using the input keys and HMAC
def decrypt_gate(garbled_gate, input_key1, input_key2):
    """
    Decrypts a garbled gate output using the given input keys.

    Args:
        garbled_gate (list): The list of encrypted gate outputs.
        input_key1 (bytes): The first input key.
        input_key2 (bytes): The second input key.

    Returns:
        decrypted_value: The decrypted value of the gate output.
    """
    # Create a derived key using HMAC
    derived_key = hmac.new(input_key1 + input_key2, input_key1 + input_key2, hashlib.sha256).digest()

    for encrypted_output in garbled_gate:
        try:
            decrypted_value = hmac.new(derived_key, bytes.fromhex(encrypted_output), hashlib.sha256).digest()
            return decrypted_value
        except Exception:
            continue
    raise ValueError("Decryption failed.")

# Evaluate the garbled circuit
def evaluate_circuit(garbled_circuit, input_keys):
    """
    Evaluates the garbled circuit using the provided input keys.

    Args:
        garbled_circuit (dict): The dictionary representing the garbled circuit.
        input_keys (dict): The input keys for the circuit.

    Returns:
        gate_results: A dictionary containing the decrypted gate results.
    """
    gates = garbled_circuit["gates"]
    gate_results = {}

    print("Evaluating the garbled circuit...")
    garbled_gate = gates["G1"]
    input_key_a, input_key_b = input_keys["A"], input_keys["B"]

    result = decrypt_gate(garbled_gate, input_key_a, input_key_b)
    gate_results["G1"] = result

    print("Gate G1 evaluated successfully.")
    return gate_results

# Decrypt the final output using known output keys
def decrypt_output(encrypted_output, output_keys):
    """
    Decrypts the final garbled output to reveal the clear value (0 or 1).

    Args:
        encrypted_output (bytes): The encrypted output value.
        output_keys (list): The list containing the two output keys for comparison.

    Returns:
        clear_value: The clear value of the output, either 0 or 1.
    """
    for i, key in enumerate(output_keys):
        derived_key = hmac.new(key, key, hashlib.sha256).digest()
        try:
            decrypted_value = hmac.new(derived_key, encrypted_output, hashlib.sha256).digest()
            return i  # Return 0 or 1 based on the correct decryption
        except Exception:
            continue
    raise ValueError("Decryption of final output failed.")

# Receive garbled circuit from sender and evaluate
def receive_garbled_circuit(host="localhost", port=9999):
    """
    Receives a garbled circuit from the sender and evaluates it.

    Args:
        host (str): The host address to listen on. Defaults to "localhost".
        port (int): The port number to listen on. Defaults to 9999.
    """
    print("Waiting to receive garbled circuit...")
    with socket.create_server((host, port)) as server:
        connection, _ = server.accept()
        with connection:
            received_data = connection.recv(4096).decode("utf-8")
            garbled_circuit = json.loads(received_data)

            print("Garbled circuit received.")

            input_keys = {
                "A": bytes.fromhex(garbled_circuit["inputs"]["A"][0]),
                "B": bytes.fromhex(garbled_circuit["inputs"]["B"][0])
            }
            output_keys = [bytes.fromhex(key) for key in garbled_circuit["outputs"]["G1"]]

            results = evaluate_circuit(garbled_circuit, input_keys)
            encrypted_output = results["G1"]

            # Decrypt the final output to obtain the clear value
            clear_value = decrypt_output(encrypted_output, output_keys)

            print("Final Output (Clear Value):", clear_value)

if __name__ == "__main__":
    receive_garbled_circuit()
