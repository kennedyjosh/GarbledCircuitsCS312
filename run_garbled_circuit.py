# run_garbled_circuit.py
import receiver
import sender
import subprocess
from threading import Thread
import time


if __name__ == "__main__":
    # Choose inputs
    sender_input = int(input("Enter the value for the sender's input (0 or 1): "))
    receiver_input = int(input("Enter the value for the receiver's input (0 or 1): "))

    # Create a thread to start the receiver process first
    receiver_thread = Thread(target=receiver.run, args=(receiver_input,))
    receiver_thread.start()

    # Wait a second, then start the sender process
    time.sleep(1)
    sender.run(sender_input)

    # Wait for the receiver thread to finish
    receiver_thread.join()
    print("Garbled circuit process completed.")

