import os
import sys


def image_to_hex(filename):
    """
    Convert image to hex string
    :param filename: Image filename
    :return: Hex string
    """
    with open(filename, 'rb') as f:
        content = f.read()
    return content.hex()


def split_hex(hex_string):
    """
    Split hex string into 16 byte chunks
    :param hex_string: Hex string
    :return: List of hex chunks
    """
    data = []
    for i in range(0, len(hex_string), 32):
        if len(hex_string[i:i+32]) < 32:
            data.append(hex_string[i:i+32] + "0" * (32 - len(hex_string[i:i+32])))
        else:
            data.append(hex_string[i:i+32])
    return data


def main():
    """
    Main function for encoding an image into hex chunks and sending them as ICMP packets in order to do a traffic capture
    :return: None
    """
    if len(sys.argv) != 2:
        print("Usage: python3 main.py <image>")
        sys.exit(1)
    image = sys.argv[1]
    if not os.path.exists(image):
        print("Image does not exist")
        sys.exit(1)
    hex_string = image_to_hex(image)
    for hex_chunk in split_hex(hex_string):
        os.system(f'ping -c 1 -s 32 -p {hex_chunk} 1.1.1.1')


if __name__ == "__main__":
    main()
