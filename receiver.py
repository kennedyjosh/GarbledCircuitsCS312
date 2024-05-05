# followed this? https://hackmd.io/@matan/garbled_circuits#The-Full-Algorithm

global garbled_circuit 
global wire_table

# this function handles getting the values from the sender (i.e., all the socket stuff)
# in this implementation (probably should be changed later) I'll set the global values here
def receive():
    return

# this function should send the garbled output back to the sender
def sendback():
    return

# (???) this function should theoretically apply the gate operation on the two inputs but I'm not sure (?)
def apply(op, input_a, input_b):
    return

# in this function, evaluate every gate in the circuit
def evaluate():
    garbled_output = []
    # go through each of the garbled gates
    for gate in garbled_circuit.items():
        # for each gate, get the key for the inputs (assuming only two for now) and output 
        key_a, key_b = gate.inputs
        key_c = gate.output 

        # get the garbled inputs from the wire table
        dec_input_a = wire_table[key_a]
        dec_input_b = wire_table[key_b]

        # (???) get the garbled output value (?)
        wire_table[key_c] = apply(gate.func, dec_input_a, dec_input_b)
        garbled_output.append(wire_table[key_c])

    return garbled_output

def main():
    receive()
    evaluate()
    sendback()

if __name__ == '__main__':
	main()
