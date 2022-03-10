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
    str_bytes_to_hex_array('a57c85800001000100000001055f6c646170045f74637003706463065f6d73646373076c616c6c696572056c6f63616c0000210001c00c002100010000025800210000006401850b6d746c2d7372762d616432076c616c6c696572056c6f63616c00c0470001000100000e100004c0a802e6')
