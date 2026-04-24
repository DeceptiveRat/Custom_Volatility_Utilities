target_PID = self.config.get('pid')

for process in ps():
	if process.UniqueProcessId == target_PID:
		peb_address = process.Peb
		break

peb = self.context.object(self.current_symbol_table + "!_PEB", layer_name = self.current_layer, offset = peb_address)
print(f"Number of heaps: {peb.NumberOfHeaps}")
print(f"Process heaps at:")
for _ in range(peb.NumberOfHeaps):
	raw_bytes = self.context.layers[self.current_layer].read(peb.ProcessHeaps + _*8, 8)
	print("0x", end="")
	for byte in reversed(raw_bytes):
		print(f"{byte:02x}", end="")
	print()
