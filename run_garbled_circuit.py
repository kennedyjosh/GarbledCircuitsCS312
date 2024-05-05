# run_garbled_circuit.py
import subprocess
import threading
import time

# Run receiver in a separate thread
def run_receiver():
    """
    Runs the receiver script.
    """
    print("Starting receiver...")
    subprocess.run(["python", "receiver.py"])

# Run sender in the main thread after a short delay
def run_sender():
    """
    Runs the sender program after a delay of 1 second.
    """
    time.sleep(1)
    print("Starting sender...")
    subprocess.run(["python", "sender.py"])

if __name__ == "__main__":
    # Create a thread to start the receiver first
    receiver_thread = threading.Thread(target=run_receiver)
    receiver_thread.start()

    # Execute the sender
    run_sender()

    # Wait for the receiver thread to finish
    receiver_thread.join()
    print("Garbled circuit process completed.")
