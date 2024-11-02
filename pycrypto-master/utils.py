import subprocess

def run_zokrates_command(*args, input_data=None):
    try:
        result = subprocess.run(args, input=input_data, capture_output=True, text=True, check=True)
        return result.stdout.strip()
    except subprocess.CalledProcessError as e:
        print(f"Error: {e}")
        return None

def split_256_to_32_bits(number):
    number &= (2**256 - 1)
    result = [0] * 8
    for i in range(8):
        temp = (number >> (32 * (7 - i))) & 0xFFFFFFFF
        result[i] = (str(temp)).encode()
    return result


def hash_2p(Xt,h):    # Xt is an array of size 5, h is a 256 bit number
    tl1 = []
    for x in Xt:
        tl2 = split_256_to_32_bits(x)
        tl1 = tl1+tl2
    tl3 = split_256_to_32_bits(h)
    print("tl1, ", tl1)
    print("tl3, ", tl3)
    compiled_output = run_zokrates_command("zokrates", "compile", "--debug", "--input", "computation.zok")

    cw = run_zokrates_command("zokrates", "compute-witness", "-a", tl1[0], tl1[1], tl1[2], tl1[3], tl1[4], tl1[5], tl1[6], tl1[7], tl1[8], tl1[9], tl1[10],tl1[11], tl1[12], tl1[13], tl1[14], tl1[15],tl1[16], tl1[17], tl1[18], tl1[19], tl1[20],tl1[21], tl1[22], tl1[23], tl1[24], tl1[25],tl1[26], tl1[27], tl1[28], tl1[29], tl1[30], tl1[31], tl1[32], tl1[33], tl1[34], tl1[35], tl1[36], tl1[37], tl1[38], tl1[39],
                               tl3[0], tl3[1], tl3[2], tl3[3], tl3[4], tl3[5], tl3[6], tl3[7])
    print(cw)

hash_2p([1,2,3,4,5], 6)