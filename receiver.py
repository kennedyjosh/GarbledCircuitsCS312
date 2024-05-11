# receiver.py (Party P_B)
from cryptography.fernet import Fernet, InvalidToken
import pickle
import socket


# ID for printed logs coming from this file
ME = "RECEIVER"
# For long encrypted values, just print the suffix of defined length
SUFFIX_LEN = 10


def try_decrypt(enc_input, enc_rows):
    """
    Try and decrypt a row using the receiver's input.

    Args:
        enc_input: the encrypted input key which should decrypt a single row
        enc_rows: encrypted rows to try and decrypt

    Returns:
        the decrypted output if one of the rows can be successfully decrypted, None otherwise
    """
    print(f"[{ME}] Trying to decrypt one of these encrypted rows: {[r[-SUFFIX_LEN:] for r in enc_rows]}")
    for enc_row in enc_rows:
        try:
            output = Fernet(enc_input).decrypt(enc_row)
            print(f"[{ME}] Successful decryption of row: {enc_row[-SUFFIX_LEN:]}")
            return output
        except InvalidToken:
            continue
    return None

    
# Receive garbled circuit from sender and evaluate
def run(receiver_input, host="localhost", port=9999):
    """
    Receives a garbled circuit from the sender and evaluates it.

    Args:
        receiver_input: 0 or 1; the input that the receiver intends to choose
        host (str): The host address to listen on. Defaults to "localhost".
        port (int): The port number to listen on. Defaults to 9999.
    """
    print(f"[{ME}] Waiting to receive garbled circuit...")
    # Create a server socket and start listening for connections
    with socket.create_server((host, port)) as server:
        # Accept a connection from sender
        connection, _ = server.accept()
        with connection:
            # Receive the garbled circuit data from the sender and deserialize it
            received_data = connection.recv(4096)
            garbled_circuit = pickle.loads(received_data)
            print(f"[{ME}] Garbled circuit received.")

            # TODO: this should be done using oblivious transfer
            # From the encrypted inputs sent by sender, choose the one that corresponds to receiver input
            inputs = garbled_circuit["receiver_inputs"]
            print(f"[{ME}] Possible inputs 0, 1: {[i[-SUFFIX_LEN:] for i in inputs]}")
            enc_input = inputs[0] if receiver_input == 0 else inputs[1]
            print(f"[{ME}] Choose encrypted input: {enc_input[-SUFFIX_LEN:]}")

            # Try to decrypt from the rows the sender sent
            output = try_decrypt(enc_input, garbled_circuit["encrypted_rows"])
            if output is None:
                print(f"[{ME}] Failed to decrypt")
            else:
                print(f"[{ME}] Decrypted output: {output}")


if __name__ == "__main__":
    run(int(input("Enter the value for the receiver's input (0 or 1): ")))

