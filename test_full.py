import receiver
import sender
from threading import Thread
import time


# Need this to check output of receiver function
class ThreadWithReturnValue(Thread):
    def __init__(self, group=None, target=None, name=None,
                 args=(), kwargs={}):
        Thread.__init__(self, group, target, name, args, kwargs)
        self._return = None
    def run(self):
        if self._Thread__target is not None:
            self._return = self._Thread__target(*self._Thread__args,
                                                **self._Thread__kwargs)
    def join(self):
        Thread.join(self)
        return self._return


def test_all_2bit_combinations():
    # `truth` is a dict where (input1, input2): output
    truth = {(i, j): b'1' if i < j else b'0' for i in range(4) for j in range(4)}
    input1 = 1
    input2 = 2
    # for input1 in range(4):
    #     for input2 in range(4):
    output = [None]
    receiver_thread = Thread(target=receiver.run, args=(input1,), kwargs={'store_output': output})
    receiver_thread.start()

    time.sleep(1)
    sender.run(input2)

    receiver_thread.join()

    assert truth[(input1, input2)] == output[0]

