# receiver.py (Party P_B)
from cryptography.fernet import Fernet, InvalidToken
import otc
import pickle
import socket
import struct
import base64

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
        if not isinstance(enc_row, bytes):
            print(f"[{ME}] Invalid type for enc_row: {type(enc_row)}")
            continue
        try:
            output = Fernet(enc_input).decrypt(enc_row)
            print(f"[{ME}] Successful decryption of row: {enc_row[-SUFFIX_LEN:]} to {output[-SUFFIX_LEN:]}")
            return output
        except InvalidToken:
            print(f"[{ME}] Invalid token for row: {enc_row[-SUFFIX_LEN:]}")
            continue
    return None

def unpad_input(input_data):
    """
    Remove padding from each element in the input tuple.
    """
    return tuple(element.rstrip(b'0') for element in input_data if isinstance(element, bytes))

# Ensure the key is a valid base64-encoded 32-byte key
def ensure_fernet_key(key):
    padded_key = key.ljust(32, b'\0')[:32]
    encoded_key = base64.urlsafe_b64encode(padded_key)
    print(f"[{ME}] Constructed Fernet key: {encoded_key}")
    return encoded_key

# Receive garbled circuit from sender and evaluate
def run(receiver_input, host="localhost", port=9999):
    """
    Receives a garbled circuit from the sender and evaluates it.

    Args:
        receiver_input: 0-3; the intended 2-bit input for the receiver
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

            if len(serialized_data) < msglen:
                raise ValueError("Incomplete data received")

            data = pickle.loads(serialized_data)
            garbled_circuit = data["garbled_circuit"]
            inputs = data["inputs"]
            input_size = data["input_size"]
            print(f"[{ME}] Received and parsed inputs and garbled circuit from sender")

            # Decrypt the receiver input and reconstruct the full key
            enc_input = b''
            for sub_input in inputs:
                sub_enc_input = r.elect(pub_key, receiver_input, *sub_input)
                if isinstance(sub_enc_input, bytes):
                    enc_input += unpad_input((sub_enc_input,))[0]
                else:
                    enc_input += sub_enc_input
            enc_input = enc_input[:32]  # Ensure the key is exactly 32 bytes
            enc_input = ensure_fernet_key(enc_input)
            print(f"[{ME}] My encrypted input: {enc_input[-SUFFIX_LEN:]}")

            # Extract encrypted rows from garbled circuit and try to decrypt
            all_enc_rows = []
            for gate_tuple in garbled_circuit:
                all_enc_rows.extend(gate_tuple[-1])  # Extracting the last element which contains encrypted rows

            # Try to decrypt from the rows the sender sent
            output = try_decrypt(enc_input, all_enc_rows)
            if output is None:
                print(f"[{ME}] Failed to decrypt")
            else:
                print(f"[{ME}] Decrypted output: {output}")
