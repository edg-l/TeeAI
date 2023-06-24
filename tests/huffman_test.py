from engine.huffman import huffman

def test_huffman():
    compressed = b'\x4a\x42\x88\x4a\x6e\x16\xba\x31\x46\xa2\x84\x9e\xbf\xe2\x06'
    decompressed = huffman.decompress(compressed)
    expected = b'\x40\x02\x02\x02\x00\x40\x07\x03\x22\x01\x00\x01\x00\x01\x08\x40\x01\x04\x0b'
    assert decompressed == expected

def test_huffman2():
    compressed = b"\x00\x02.\x07\x00\x12!\xbc\'\xbd\'(\x00\x8a\x06\x84\x01\x00\x00\x00\x01\x00\x00\x00"
    huffman.decompress(compressed)

# TODO: this currently hangs
# def test_huffman_empty():
#     huffman.decompress(b'')
