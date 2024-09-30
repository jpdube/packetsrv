def str_bytes_to_hex_array(str_bytes):
    print('packet = [')
    sb = ''
    count = 0
    per_line = 0
    for i,s in enumerate(str_bytes):
        sb += s
        count += 1
        if count == 2:
            print(f'0x{sb}',end='')
            if i < len(str_bytes) - 1:
                print(', ', end='')
            per_line += 1
            if per_line == 16:
                per_line = 0 
                print('')

            sb = ''
            count = 0

    print(']')

if __name__ == '__main__':
    str_bytes_to_hex_array('4500015d758b40007f06002ec0a806a9c0a8fce7ca6608ae18175257c25c925b50180402cf63000016030101300100012c0303772897e3f6d6b11a2c129270f6b3a10920fc5c75f8dbbd66979ad09148c7a1cd203c98462e0fdca48757a2ba54ba2ef92e68470f67e5cad47dc83fce3cef7d57af003c13021303c02cc030009fcca9cca8ccaac02bc02f009ec024c028006bc023c0270067c00ac0140039c009c0130033009d009c003d003c0035002f00ff010000a700000012001000000d6d746c2d7372762d6d6e676d74000b000403000102000a000c000a001d0017001e00190018002300000016000000170000000d0030002e040305030603080708080809080a080b080408050806040105010601030302030301020103020202040205020602002b00050403040303002d00020101003300260024001d0020cfe480f773cf5c5f7d518450cd02ba873bc83c086f2f9f7bbee58dc6a2b3e343')
