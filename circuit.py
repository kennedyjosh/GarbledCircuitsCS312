# circuit.py
from common import SUFFIX_LEN
from cryptography.fernet import Fernet
import random
from queue import PriorityQueue


class Gate:
    def __init__(self, type, input1, input2=None, output=None):
        self.type = type
        self.input1 = input1
        self.input2 = input2
        self.output = output

    def get_input_wires(self, include_none=False):
        return list(filter(lambda i: True if include_none else i is not None, [self.input1, self.input2]))

    def get_truth_table(self):
        if self.type == "AND":
            return [(0, 0, 0), (0, 1, 0), (1, 0, 0), (1, 1, 1)]
        elif self.type == "OR":
            return [(0, 0, 0), (0, 1, 1), (1, 0, 1), (1, 1, 1)]
        elif self.type == "XNOR":
            return [(0, 0, 1), (0, 1, 0), (1, 0, 0), (1, 1, 1)]
        elif self.type == "XOR":
            return [(0, 0, 0), (0, 1, 1), (1, 0, 1), (1, 1, 0)]
        elif self.type == "NOT":
            return [(0, None, 1), (1, None, 0)]
        else:
            raise ValueError(f"Unsupported gate type: {self.type}")

    def encrypt(self, enc_zero_a: bytes = None, enc_one_a: bytes = None,
                      enc_zero_b: bytes = None, enc_one_b: bytes = None, out_zero: bytes = b'0',
                      out_one: bytes = b'1'):
        """
        Encrypts the gate output for all possible combinations of input keys.

        Args:
            truth_table: list of tuples where each tuple in the format (input1, input2, output)
                         describes a row in the truth table of the gate
            enc_zero_a: input key for 0 for the first wire
            enc_one_a: input key for 1 for the first wire
            enc_zero_b: input key for 0 for the second wire
            enc_one_b: input key for 1 for the second wire
            out_zero: value to use for output of 0
            out_one: value to use for output of 1

        Returns:
            enc_zero_a: input key for 0 for the first wire
            enc_one_a: input key for 1 for the first wire
            enc_zero_b: input key for 0 for the second wire
            enc_one_b: input key for 1 for the second wire
            encrypted_rows: A list of encrypted gate outputs for all possible combinations of input keys.
        """
        print(f"Encrypting truth table: {self.get_truth_table()}")
        # Initialize some variables; a is the first wire, b is the second wire
        enc_zero_a = Fernet.generate_key() if enc_zero_a is None else enc_zero_a
        enc_one_a = Fernet.generate_key() if enc_one_a is None else enc_one_a
        enc_zero_b = Fernet.generate_key() if enc_zero_b is None else enc_zero_b
        enc_one_b = Fernet.generate_key() if enc_one_b is None else enc_one_b
        print(f"Encrypted keys:")
        print(f"\t0a = {enc_zero_a[-SUFFIX_LEN:]}\n\t1a = {enc_one_a[-SUFFIX_LEN:]}")
        print(f"\t0b = {enc_zero_b[-SUFFIX_LEN:]}\n\t1b = {enc_one_b[-SUFFIX_LEN:]}")
        encrypted_rows = []  # holds each encrypted row of truth table
        # Iterate over and encrypt each row in the truth table
        for row in self.get_truth_table():
            wa, wb, wc = row
            enc_a = enc_zero_a if wa == 0 else enc_one_a
            enc_b = enc_zero_b if wb == 0 else enc_one_b if wb is not None else b''
            enc_c = out_zero if wc == 0 else out_one
            if wb is None:
                enc_row = Fernet(enc_a).encrypt(enc_c)
            else:
                enc_row = Fernet(enc_a).encrypt(Fernet(enc_b).encrypt(enc_c))
            encrypted_rows.append(enc_row)
            print(f"Encrypting inputs wa={wa}, wb={wb}, wc={wc} | encrypted output row: {enc_row[-SUFFIX_LEN:]}")
        # Shuffle the order of the encrypted rows, otherwise one can deduce the truth table by convention
        random.shuffle(encrypted_rows)  # the shuffling occurs in-place
        return enc_zero_a, enc_one_a, enc_zero_b, enc_one_b, encrypted_rows


class Circuit:
    def __init__(self, gates: [Gate]):
        """
        Args:
            gates: list of Gate objects that comprise the circuit
        """
        self.gates = dict()  # store the gates by their output labels
        output_wires = set()  # keep track of all wires used as outputs
        input_wires = set()  # keep track of all wires used as inputs
        self.input_combos = dict()  # keep track of all input combinations; used for starting wires
        for gate in gates:
            input_wires.update(gate.get_input_wires())
            output_wires.add(gate.output)
            self.input_combos[frozenset(gate.get_input_wires(include_none=True))] = gate.output
            self.gates[gate.output] = gate

        self.last_gate = output_wires.difference(input_wires)
        assert len(self.last_gate) == 1, \
            "More than one gate is an output of other gates but an input to none"
        self.last_gate = self.last_gate.pop()

    def garble(self):
        """
        Approach:
            1. Start with the last gate – aka the gate whose output is never used an input elsewhere
            2. Encrypt a truth table for this gate
            3. Use the encrypted inputs for this gate as the output for the neighbor gates
            4. Evaluate steps 2 and 3 for all neighbor gates

        Essentially, consider the circuit as a directed acyclic graph, and we will encrypt
        in a breadth-first approach from the final output node to the initial input nodes

        Returns:
            garbled_circuit: a dictionary where the key is the gate label and the value is another
            dictionary: one key `inputs` that specifies the labels of the inputs (key will not exist if
            the gate has no inputs), and another key `rows` that has a list of the encrypted rows. The
            `rows` keys should be replaced with `value` once the gate is evaluated.
        """
        garbled_circuit = dict()
        enc_outputs = dict()  # gate_label: (out_zero, out_one)
        visited = {self.last_gate}
        pq = PriorityQueue()  # (level, gate_label, out_zero, out_one)
        pq.put((0, self.last_gate, b'0', b'1'))
        while not pq.empty():
            # Get the next gate and its output values
            level, curr_label, out_zero, out_one = pq.get()
            # If this label isn't registered as a gate, then it is one of the original inputs
            if curr_label not in self.gates:
                # Store the zero and one keys at this label's index in the garbled circuit dict
                garbled_circuit[curr_label] = {"value": (out_zero, out_one)}
                enc_outputs[curr_label] = (out_zero, out_one)
                continue
            else:
                curr_gate = self.gates[curr_label]
            if curr_label in enc_outputs:
                assert enc_outputs[curr_label] == (out_zero, out_one), \
                    f"Gate {curr_label} was assigned different output keys"
            enc_outputs[curr_label] = (out_zero, out_one)

            # Check if either of the inputs have output values already, use those if so
            if (i := curr_gate.input1) in enc_outputs:
                enc_zero_a = enc_outputs[i][0]
                enc_one_a = enc_outputs[i][1]
            else:
                enc_zero_a = None
                enc_one_a = None
            if (i := curr_gate.input2) in enc_outputs:
                enc_zero_b = enc_outputs[i][0]
                enc_one_b = enc_outputs[i][1]
            else:
                enc_zero_b = None
                enc_one_b = None

            # Encrypt the gate
            enc_zero_a, enc_one_a, enc_zero_b, enc_one_b, enc_rows = curr_gate.encrypt(
                                                                                   enc_zero_a=enc_zero_a,
                                                                                   enc_one_a=enc_one_a,
                                                                                   enc_zero_b=enc_zero_b,
                                                                                   enc_one_b=enc_one_b,
                                                                                   out_zero=out_zero,
                                                                                   out_one=out_one)
            garbled_circuit[curr_label] = {
                "inputs": [curr_gate.input1, curr_gate.input2],
                "rows": enc_rows
            }

            # Add neighbors to queue if not already visited
            for zero, one, input in [(enc_zero_a, enc_one_a, curr_gate.input1),
                                     (enc_zero_b, enc_one_b, curr_gate.input2)]:
                if input is not None and input not in visited:
                    visited.add(input)
                    pq.put((level + 1, input, zero, one))
                    enc_outputs[input] = (zero, one)

        self.garbled = garbled_circuit
        return garbled_circuit

