Row = list[int]
State = list[Row]

MUL_ARRAY = [
    [2, 3, 1, 1],
    [1, 2, 3, 1],
    [1, 1, 2, 3],
    [3, 1, 1, 2]
]

INVERSE_MUL_ARRAY = [
    [0x0E, 0x0B, 0x0D, 0x09],
    [0x09, 0x0E, 0x0B, 0x0D],
    [0x0D, 0x09, 0x0E, 0x0B],
    [0x0B, 0x0D, 0x09, 0x0E]
]

def mul2(element: int) -> int: # multiplies element by 2 in GF(2^8)
    prod = element
    prod = (prod << 1) & 0xFF # multiply by 2 and limit to one byte
    if element & 0x80 != 0: # checks if msb is 1 to know if to xor
        prod ^= 0x1B # xor with the irreducible polynomial ( without x^8 )
    return prod

def mul3(element: int) -> int: # multiplies element by 3 in GF(2^8) # 2 + 1
    prod = mul2(element)
    return prod ^ element


def mul9(element: int) -> int: # multiplies element by 9 in GF(2^8) # 2**3 + 1
    prod = mul2(mul2(mul2(element)))
    return prod ^ element


def mul11(element: int) -> int: # multiplies element by 11 in GF(2^8) # 2**3 + 2 + 1
    prod = mul2(mul2(mul2(element))) ^ mul2(element)
    return prod ^ element


def mul13(element: int) -> int: # multiplies element by 13 in GF(2^8) # 2**3 + 2**2 + 1
    prod = mul2(mul2(mul2(element))) ^ mul2(mul2(element))
    return prod ^ element


def mul14(element: int) -> int: # multiplies element by 14 in GF(2^8) # 2**3 + 2**2 + 2
    prod = mul2(mul2(mul2(element))) ^ mul2(mul2(element)) ^ mul2(element)
    return prod


def check_mul(num: int, element: int): # this function is very straightforward, I don't think this requires explanation
    match num:
        case 1:
            return element
        case 2:
            return mul2(element)
        case 3:
            return mul3(element)
        case 9:
            return mul9(element)
        case 11:
            return mul11(element)
        case 13:
            return mul13(element)
        case 14:
            return mul14(element)
    raise ValueError("num value must be one of the following: [1, 2, 3]") # this error message is unprofessional but some members of the group refuse to part with it, so I guess we're keeping it

def xor_arr(arr: list[int]) -> int: # returns result of xor with every element
    num = arr[0]
    for i in arr[1:]:
        num ^= i
    return num

def column_mixer(column: list[int], mull_array: State): # performs matrix multiplication between input column and AES multiplication matrix
    new_list = list()
    for i in range(0, 4):
        arr_xor = list()
        for j in range(0, 4):
            value = column[j]
            num = mull_array[i][j]
            cm = check_mul(num, value)
            arr_xor.append(cm)
        new_list.append(xor_arr(arr_xor))
    return new_list

def inverse_mix_columns(state: State) -> State:
    final_state: State = [[], [], [], []]
    for i in range(0, 4):
        temp = [state[0][i], state[1][i], state[2][i], state[3][i]]
        cm = column_mixer(temp,INVERSE_MUL_ARRAY)
        for j in range(0, 4):
            final_state[j].append(cm[j])
    return final_state

def mix_columns(state: State) -> State: # transposes state, then performs column_mixer on each column, but inserts the result as a row so basically reverses the transpose
    final_state: State = [[], [], [], []]
    for i in range(0, 4):
        temp = [state[0][i], state[1][i], state[2][i], state[3][i]]
        cm = column_mixer(temp,MUL_ARRAY)
        for j in range(0, 4):
            final_state[j].append(cm[j])
    return final_state

