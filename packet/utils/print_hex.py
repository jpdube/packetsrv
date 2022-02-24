def print_hex(byte_array):
    array_len = len(byte_array)

    count = 0
    str_array = []
    byte_count = 0
    result = ""
    for i in range(array_len):
        if count == 0:
            result += f"{byte_count:04x}: "

        result += f"{byte_array[i]:02x} "
        str_array.append(byte_array[i])
        count += 1
        byte_count += 1

        if count == 8:
            result += " "

        if count == 16:
            result += "  " + get_char(str_array)
            result += "\n"
            count = 0
            str_array = []

    spacing = ((16 - count) * 3) + 2
    if count <= 8:
        spacing += 1

    result += (" " * spacing) + get_char(str_array)
    result += "\n"
    print(f"\n{result}")


def get_char(byte_array):
    result = ""
    for i in range(len(byte_array)):
        char_ord = byte_array[i]
        if char_ord >= 0x21 and char_ord <= 0x7E:
            result += chr(byte_array[i])
        else:
            result += "\u00b7"

    return result


# b = [0xe8,0x1c,0xba,0x35,0x55,0xc6,0xc0,0x74,0xad,0x24,0xdd,0x3a,0x08,0x00,0x45,0x68,0x02,0x52,0xd3,0xb1,0x00,0x00,0x40,0x11,0x56,0xe4,0xc0,0xa8,0x99,0x42,0xc0,0xa8]
# ba = bytearray(b)
# ba[1] = 0x65
# ba[2] = 0x41
# ba[3] = 0x44
# ba[4] = 0x24
# print_hex(ba)
