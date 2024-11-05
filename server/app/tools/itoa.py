
itoa_counter = 0


def itoa(reset=False) -> int:
    global itoa_counter
    if reset:
        itoa_counter = 0
    result = itoa_counter
    itoa_counter += 1
    return result
