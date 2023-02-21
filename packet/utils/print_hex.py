# from rich import print


class HexDump:

    # def __init__(self):
    color = "green"
    prev_color = ""
    color_changed = False

    @classmethod
    def format_hex(cls, byte_array, color_ranges=None) -> str:
        array_len = len(byte_array)

        count = 0
        # str_array = ""
        str_array = []
        byte_count = 0
        result = ""
        for i in range(array_len):
            if count == 0:
                result += f"[white]{byte_count:04x}: [{cls.color}]"

            if color_ranges:
                cls.color = cls.get_color(color_ranges, byte_count)
                if cls.color != cls.prev_color:
                    cls.prev_color = cls.color
                    result += f"[{cls.color}]"

            result += f"{byte_array[i]:02x} "
            # result += f"[{cls.color}]{byte_array[i]:02x} "
            str_array.append(byte_array[i])
            # str_array += cls.get_color_char(byte_array[i])
            count += 1
            byte_count += 1

            if count == 8:
                result += " "

            if count == 16:
                result += "  " + cls.get_char(str_array)
                # result += "  " + cls.get_char(str_array)
                result += "\n"
                count = 0
                # str_array = ""
                str_array = []

        spacing = ((16 - count) * 3) + 2
        if count <= 8:
            spacing += 1

        # result += (" " * spacing) + str_array
        result += (" " * spacing) + cls.get_char(str_array)
        # result += "\n"
        # print(f"\n{result}")
        return result

    @classmethod
    def get_color(cls, color_ranges, index):
        for c in color_ranges:
            if index >= c[0] and index < c[1]:
                return c[2]
        return "[white]"

    @classmethod
    def print_hex(cls, byte_array, color_ranges=None):
        print(f"{cls.format_hex(byte_array, color_ranges)}")

    def get_color_char(self, char_ord) -> str:
        ret_value = ""
        if char_ord >= 0x21 and char_ord <= 0x7E:
            if char_ord == 0x5b or char_ord == 0x5c:
                ret_value = f"\\{chr(char_ord)}"
            else:
                ret_value = f"{chr(char_ord)}"
        else:
            ret_value = f"\u00b7"

        # if self.color_changed:
        #     self.color_changed = False
        #     return f"[{self.color}]{ret_value}"
        # else:
        return ret_value

    @classmethod
    def get_char(cls, byte_array):
        result = "[white]"
        for i in range(len(byte_array)):
            char_ord = byte_array[i]
            if char_ord >= 0x21 and char_ord <= 0x7E:
                result += chr(byte_array[i])
            else:
                result += "\u00b7"

        return result
