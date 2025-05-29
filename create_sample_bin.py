import pefile
import os

# Create a minimal PE file structure
def create_sample_pe():
    # Minimal PE header (simplified, not fully functional but parseable)
    pe_data = bytearray([
        0x4D, 0x5A,  # MZ signature
        *[0x00] * 58,  # Placeholder for DOS header
        0x50, 0x45, 0x00, 0x00,  # PE signature
        0x4C, 0x01,  # Machine (x86)
        0x01, 0x00,  # Number of sections
        *[0x00] * 20,  # Placeholder for optional header
        0xE0, 0x00,  # Size of optional header
        0x03, 0x00,  # Characteristics
        *[0x00] * 200,  # Minimal section data
        0x90, 0xC3  # Simple x86 instructions: NOP, RET
    ])
    with open("sample.bin", "wb") as f:
        f.write(pe_data)
    print("Created sample.bin")

if __name__ == "__main__":
    create_sample_pe()
