import pytest
import receiver
import sender
from threading import Thread


testdata = [(i, j) for i in range(4) for j in range(4)]


@pytest.mark.parametrize("sender_input, receiver_input", testdata)
def test_2bit_comparator(sender_input, receiver_input):
    truth = b'1' if sender_input < receiver_input else b'0'
    output = [None]

    receiver_thread = Thread(target=receiver.run, args=(receiver_input,), kwargs={'store_output': output})
    receiver_thread.start()

    sender.run(sender_input)

    receiver_thread.join()

    assert truth == output[0], f"Invalid: {sender_input} < {receiver_input}"

