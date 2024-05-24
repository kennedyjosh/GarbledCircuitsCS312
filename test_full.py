import pytest
import receiver
import sender
from threading import Thread


testdata = [(i, j) for i in range(4) for j in range(4)]


@pytest.mark.parametrize("input1,input2", testdata)
def test_2bit_comparator(input1, input2):
    truth = b'1' if input1 < input2 else b'0'
    output = [None]

    receiver_thread = Thread(target=receiver.run, args=(input1,), kwargs={'store_output': output})
    receiver_thread.start()

    sender.run(input2)

    receiver_thread.join()

    assert truth == output[0], f"Invalid: {input1} < {input2}"

