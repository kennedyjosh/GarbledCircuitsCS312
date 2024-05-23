# receiver.py (Party P_B)
from cryptography.fernet import Fernet, InvalidToken
import otc
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
        receiver_input: 0 or 1; the intended input for the receiver
        host (str): The host address to listen on. Defaults to "localhost".
        port (int): The port number to listen on. Defaults to 9999.
    """
    print(f"[{ME}] Waiting to receive connection from sender...")
    # Create a server socket and start listening for connections
    with socket.create_server((host, port)) as server:
        # Accept initial connection from sender
        connection, _ = server.accept()
        with connection:
            # First message from sender contains the public key for OT
            serialized_data = connection.recv(4096)
            data = pickle.loads(serialized_data)
            pub_key = data["pub_key"]
            print(f"[{ME}] Public key received.")

            # Initialize OT and respond to sender with desired input
            # Note that sender will not be able to deduce the input the receivers wants due to OT properties
            r = otc.receive()
            input_selection = r.query(pub_key, receiver_input)

            # Send this response back to the sender
            serialized_data = pickle.dumps({"selection": input_selection})
            connection.sendall(serialized_data)
            print(f"[{ME}] Selection ({receiver_input}) sent")

            # Receive the inputs and the garbled circuit from the sender
            # Receiver now has enough info to decrypt both
            serialized_data = b''
            while serialized_data == b'':
                serialized_data = connection.recv(4096)
            data = pickle.loads(serialized_data)
            garbled_circuit = data["garbled_circuit"]
            # otc only allows the inputs to be of length 16, but the Fernet keys are length 44
            # so we will have to reconstruct them after decryption
            inputs = (data[1], data[2], data[3])
            input_size = data["input_size"]
            print(f"[{ME}] Received and parsed inputs and garbled circuit from sender")

            # Decrypt the receiver input and reconstruct the full key
            enc_input = b''
            for sub_input in inputs:
                sub_enc_input = r.elect(pub_key, receiver_input, *sub_input)
                enc_input += sub_enc_input
            enc_input = enc_input[:input_size]
            print(f"[{ME}] My encrypted input: {enc_input[-SUFFIX_LEN:]}")

            # Try to decrypt from the rows the sender sent
            output = try_decrypt(enc_input, garbled_circuit)
            if output is None:
                print(f"[{ME}] Failed to decrypt")
            else:
                print(f"[{ME}] Decrypted output: {output}")

