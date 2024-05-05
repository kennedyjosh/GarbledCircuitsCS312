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
        decrypted_value (bytes): The decrypted value of the gate output.

    Raises:
        ValueError: If decryption fails for all encrypted outputs.
    """
    # Create a derived key using HMAC
    derived_key = hmac.new(input_key1 + input_key2, input_key1 + input_key2, hashlib.sha256).digest()

    # Iterate over each encrypted output
    for encrypted_output in garbled_gate:
        try:
            # Decrypt the encrypted output using the derived key
            decrypted_value = hmac.new(derived_key, bytes.fromhex(encrypted_output), hashlib.sha256).digest()
            return decrypted_value
        except Exception:
            # If decryption fails, continue
            continue

    # If decryption fails, raise an exception
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
    # Extract the gates from the garbled circuit
    gates = garbled_circuit["gates"]

    # Create a dictionary to store the results of gate evaluations
    gate_results = {}

    print("Evaluating gate G1...")
    
    # Get the encrypted gate output and input keys
    garbled_gate = gates["G1"]
    input_key_a, input_key_b = input_keys["A"], input_keys["B"]

    # Decrypt the gate output using the input keys
    result = decrypt_gate(garbled_gate, input_key_a, input_key_b)

    # Store the decrypted gate output in the results dictionary
    gate_results["G1"] = result

    print("Gate G1 evaluated successfully.")

    # Return the dictionary of gate results
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
    # Iterate over each output key and try to decrypt the encrypted output
    for i, key in enumerate(output_keys):
        # Create a derived key using HMAC
        derived_key = hmac.new(key, key, hashlib.sha256).digest()
        try:
            # Decrypt the encrypted output using the derived key
            decrypted_value = hmac.new(derived_key, encrypted_output, hashlib.sha256).digest()
            return i  # Return 0 or 1 based on the correct decryption
        except Exception:
            # If decryption fails, continue
            continue

    # If decryption fails, raise an exception
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
    # Create a server socket and start listening for connections
    with socket.create_server((host, port)) as server:
        # Accept a connection from sender
        connection, _ = server.accept()
        with connection:
            # Receive the garbled circuit data from the sender
            received_data = connection.recv(4096).decode("utf-8")
            garbled_circuit = json.loads(received_data)

            print("Garbled circuit received.")

            # Extract the input keys from the received garbled circuit
            input_keys = {
                "A": bytes.fromhex(garbled_circuit["inputs"]["A"][0]),
                "B": bytes.fromhex(garbled_circuit["inputs"]["B"][0])
            }

            # Extract the output keys from the received garbled circuit
            output_keys = [bytes.fromhex(key) for key in garbled_circuit["outputs"]["G1"]]

            # Evaluate the garbled circuit using the input keys
            results = evaluate_circuit(garbled_circuit, input_keys)
            encrypted_output = results["G1"]

            # Decrypt the final output to obtain the clear value
            clear_value = decrypt_output(encrypted_output, output_keys)

            # Print the clear value of the final output
            print("Final Output (Clear Value):", clear_value)

            print("Final Output (Clear Value):", clear_value)

if __name__ == "__main__":
    receive_garbled_circuit()
