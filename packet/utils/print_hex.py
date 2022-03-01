def format_hex(byte_array):
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
    # print(f"\n{result}")
    return result

def print_hex(byte_array):
    print(f"\n{format_hex(byte_array)}")

def get_char(byte_array):
    result = ""
    for i in range(len(byte_array)):
        char_ord = byte_array[i]
        if char_ord >= 0x21 and char_ord <= 0x7E:
            result += chr(byte_array[i])
        else:
            result += "\u00b7"

    return result

