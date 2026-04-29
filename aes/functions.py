from aes import boxes
from aes.mix_column import mix_columns,inverse_mix_columns



Row = list[int]
State = list[Row]
def bytes_to_state(data: bytes) -> State:
    if len(data) != 16:
        raise ValueError("input must be 16 bytes")
    state: State = [[0]*4 for _ in range(4)]
    for col in range(4):
        for row in range(4):
            state[row][col] = data[4*col + row]
    return state





def state_to_bytes(state: State) -> bytes:
    out = bytearray(16)
    for col in range(4):
        for row in range(4):
            out[4*col + row] = state[row][col]
    return bytes(out)

def add_round_key(key: State, state: State):
    for row in range(4):
        for col in range(4):
            state[row][col] ^= key[row][col]

def substitute_bytes(state: State):
    for row in range(4):
        for col in range(4):
            state[row][col] = boxes.substitute_box[state[row][col]]

def inverse_substitute_bytes(state: State):
    for row in range(4):
        for col in range(4):
            state[row][col] = boxes.inv_substitute_box[state[row][col]]

def shift_rows(state:State):
    for row in range(1,4):
        for i in range(row):
            state[row].append(state[row].pop(0))

def inverse_shift_rows(state: State):
    for row in range(1, 4):
        for i in range(row):
            state[row].insert(0,state[row].pop())

def g(word:Row, round:int) -> Row:
    w:Row = word[:]
    w = w[1:]+ w[:1]
    result: Row = [boxes.substitute_box[b] for b in w]
    result[0] ^= boxes.r_con[round]
    return result

def switch_state(matrix:State) -> State:
    result:State = [[0]*4 for n in range(4)]
    for row in range(4):
        for col in range(4):
            result[row][col] = matrix[col][row]
    return result

def expand_key(key: State) -> list[State]:
    result:list[State] = []
    words:State = switch_state(key)
    result.append(switch_state(words))
    for i in range(1, 11):
        gword:Row = g(words[-1],i)
        words[0] = [words[0][n]^ gword[n] for n in range(4)]
        for j in range(1,4):
            words[j] = [words[j-1][n] ^ words[j][n] for n in range(4)]
        result.append(switch_state(words))
    return result

def aes128_encrypt(key: bytes, plaintext: bytes) -> bytes:
    state:State = bytes_to_state(plaintext)
    master_key: State = bytes_to_state(key)
    round_keys = expand_key(master_key)
    add_round_key(round_keys[0],state)
    for i in range(1,10):
        substitute_bytes(state)
        shift_rows(state)
        state = mix_columns(state)
        add_round_key(round_keys[i],state)
    substitute_bytes(state)
    shift_rows(state)
    add_round_key(round_keys[-1], state)
    return state_to_bytes(state)



def aes128_decrypt(key: bytes, ciphertext: bytes) -> bytes:
    state: State = bytes_to_state(ciphertext)
    master_key: State = bytes_to_state(key)
    round_keys = expand_key(master_key)
    add_round_key(round_keys[10], state)
    inverse_shift_rows(state)
    inverse_substitute_bytes(state)
    for r in range(9, 0, -1):
        add_round_key(round_keys[r], state)
        state = inverse_mix_columns(state)
        inverse_shift_rows(state)
        inverse_substitute_bytes(state)
    add_round_key(round_keys[0], state)
    return state_to_bytes(state)

