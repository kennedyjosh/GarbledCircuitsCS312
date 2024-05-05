import json
from cryptography.fernet import Fernet

def get_keys():
    key1 = Fernet.generate_key()
    key2 = Fernet.generate_key()
    return key1,key2

def encrypt_entry(data, keys):
    fernet1, fernet2 = Fernet(keys[0]), Fernet(keys[1])
    return fernet2.encrypt(fernet1.encrypt(data.encode())) #double encrypt the value

def createTruthTable(gate, wire_keys):
    
    #only using 'and' and 'or' gate circuit for now
    if gate['type'] == "AND":
        outputs = ["0", "0", "0", "1"]
    elif gate['type'] == "OR":
        outputs = ["0", "1", "1", "1"]
    else:
        return "ERROR"

    encrypted_table = []
    
    input_keys = [wire_keys[input_wire] for input_wire in gate['inputs']]
    
    #create table
    for i in range(2):
        for j in range(2):
            entry = outputs[i*2 + j]
            encrypted_entry = encrypt_entry(entry, (input_keys[0][i], input_keys[1][j]))
            encrypted_table.append(encrypted_entry)
    
    return encrypted_table

def sender():
    with open("circuit.json", "r") as file:
        circuit = json.load(file)
    
    wireKeys = {}
    
    for gate in circuit['gates']:
        for wire in gate['inputs'] + [gate['output']]:
            if wire not in wireKeys:
                wireKeys[wire] = get_keys()
                
    circuits = {}
    for gate in circuit['gates']:
        output = gate['output']
        circuits[output] = createTruthTable(gate, wireKeys)
    
    print(circuits)

sender()