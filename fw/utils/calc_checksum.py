from struct import *


# --- Compute the 16bit one complement of a buffer
def calc_checksum(packet):
    total = 0

    # Add up 16-bit words
    num_words = len(packet) // 2
    for chunk in unpack("!%sH" % num_words, packet[0:num_words*2]):
        total += chunk

    # Add any left over byte
    if len(packet) % 2:
        total += ord(packet[-1]) << 8

    # Fold 32-bits into 16-bits
    total = (total >> 16) + (total & 0xffff)
    total += total >> 16
    return ~total + 0x10000 & 0xffff
