# receiver.py (Party P_B)
from cryptography.fernet import Fernet, InvalidToken
import otc
import pickle
import socket
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
    # print(f"[{ME}] Trying to decrypt one of these encrypted rows: {[r[-SUFFIX_LEN:] for r in enc_rows]}")
    # for row in range(len(enc_input)):
    #     for row2 in range(len(enc_rows)):
    #         try:
    #             print(Fernet(enc_input[row]).decrypt(enc_rows[row2]))
    #             output = Fernet(enc_input[row]).decrypt(enc_rows[row2])

    #             print(f"[{ME}] Successful decryption of row: {enc_rows[row][-SUFFIX_LEN:]}")
    #             return output
    #         except InvalidToken:
    #             continue

    for row in range(len(enc_input)):
        try:
            print(Fernet(enc_input[row]).decrypt(enc_rows))
            output = Fernet(enc_input[row]).decrypt(enc_rows)

            print(f"[{ME}] Successful decryption of row: {enc_input[-SUFFIX_LEN:]}")
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
                    # data = b''
        # while True:
        #     packet = server.recv(4096)
        #     if not packet: break
        #     data += packet
        # data = pickle.loads(data)

            serialized_data = b''
            while True:
                packet = connection.recv(4096)
                if not packet: break
                serialized_data += packet
            data = pickle.loads(serialized_data)
            garbled_circuit = data["garbled_circuit"]
            # otc only allows the inputs to be of length 16, but the Fernet keys are length 44
            # so we will have to reconstruct them after decryption
            inputs = [data[1], data[2], data[3]]
            input_size = data["input_size"]
            print(f"[{ME}] Received and parsed inputs and garbled circuit from sender")

            # Decrypt the receiver input and reconstruct the full key
            all_enc_input = []
            for i in range(len(inputs[0])):
                enc_input = b''
                sub_enc_input1 = r.elect(pub_key, receiver_input, *inputs[0][i])
                sub_enc_input2 = r.elect(pub_key, receiver_input, *inputs[1][i])
                sub_enc_input3 = r.elect(pub_key, receiver_input, *inputs[2][i])
                enc_input = sub_enc_input1 + sub_enc_input2 + sub_enc_input3
                enc_input = enc_input[:input_size]
                # print(enc_input)
                print(f"[{ME}] My encrypted input: {enc_input[-SUFFIX_LEN:]}")
                all_enc_input.append(enc_input)

            
            # for sub_input in inputs:
            #     enc_input = b''
            #     for sub_sub_input in range(1, 4):
            #         sub_enc_input = r.elect(pub_key, receiver_input, *sub_input)
            #         enc_input += sub_enc_input
            # enc_input = enc_input[:input_size]
            # print(f"[{ME}] My encrypted input: {enc_input[-SUFFIX_LEN:]}")

            # Try to decrypt from the rows the sender sent
            # print(garbled_circuit)
            # all_enc_rows = []
            # for gate_tuple in garbled_circuit:
            #     all_enc_rows.extend(gate_tuple[-1]) 
            
            for i in garbled_circuit:
                o = try_decrypt(all_enc_input, i)
                if o:
                    output = o
            # output = o
            # print(len(all_enc_input))
            # print(len(garbled_circuit))
            # output = try_decrypt(all_enc_input, garbled_circuit)
            if output is None:
                print(f"[{ME}] Failed to decrypt")
            else:
                print(f"[{ME}] Decrypted output: {output}")

