def str_bytes_to_hex_array(str_bytes):
    print('packet = [')
    sb = ''
    for i,s in enumerate(str_bytes):
        sb += s
        if i % 2 == 0:
            print(f'0x{sb},')

    print(']')
