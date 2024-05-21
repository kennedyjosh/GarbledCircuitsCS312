import receiver
import sender
from threading import Thread
import time

if __name__ == "__main__":
    sender_input = int(input("Enter the value for the sender's input (0-3): "))
    receiver_input = int(input("Enter the value for the receiver's input (0-3): "))

    receiver_thread = Thread(target=receiver.run, args=(receiver_input,))
    receiver_thread.start()

    time.sleep(1)
    sender.run(sender_input)

    receiver_thread.join()
    print("Garbled circuit process completed.")
