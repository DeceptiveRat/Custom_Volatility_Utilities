import logging
from volatility3.framework import renderers, interfaces, exceptions
from volatility3.framework.configuration import requirements
from volatility3.plugins.windows import pslist
from volatility3.plugins.windows import vadinfo

vollog = logging.getLogger(__name__)

def verify_address(content_pointer_VAD, layer):
	try: 
		# offset 8 contains valid pointer
		content_pointer_bytes = layer.read(content_pointer_VAD+8, 8, pad=True)

		# offset 24 contains valid pointer and points to "Consolas block"
		consolas_pointer_bytes = layer.read(content_pointer_VAD+24, 8, pad=True)
		consolas_pointer = int.from_bytes(consolas_pointer_bytes, byteorder="little")
		consolas_bytes = layer.read(consolas_pointer, 96, pad=True)
		if consolas_bytes[64:96] != b"\x43\x00\x6f\x00\x6e\x00\x73\x00\x6f\x00\x6c\x00\x61\x00\x73\x00\x00\x00\x6e\x00\x73\x00\x6f\x00\x6c\x00\x65\x00\x00\x00\x00\x00":
			return False

		# offset 40 contains valid pointer and points to block starting with 0x64
		temp_pointer_bytes = layer.read(content_pointer_VAD+40, 8, pad=True)
		temp_pointer = int.from_bytes(temp_pointer_bytes, byteorder="little")
		temp_byte = layer.read(temp_pointer, 1, pad=True)
		if temp_byte != b'\x64':
			return False

		# offset 56 contains valid pointer and points to block starting with 0x90
		temp_pointer_bytes = layer.read(content_pointer_VAD+56, 8, pad=True)
		temp_pointer = int.from_bytes(temp_pointer_bytes, byteorder="little")
		temp_byte = layer.read(temp_pointer, 1, pad=True)
		if temp_byte != b'\x90':
			return False

		# offset 72 contains valid pointer and points to block starting with 0x1c
		temp_pointer_bytes = layer.read(content_pointer_VAD+72, 8, pad=True)
		temp_pointer = int.from_bytes(temp_pointer_bytes, byteorder="little")
		temp_byte = layer.read(temp_pointer, 1, pad=True)
		if temp_byte != b'\x1c':
			return False
	except:
		print(f"Address unavailable: {hex(content_pointer_VAD)}")
		return False
	
	content_virtual_address = int.from_bytes(content_pointer_bytes, byteorder="little")
	return content_virtual_address

def get_content(content_virtual_address, layer):
	# read content
	content = ""
	raw_content = b""
	read_bytes = layer.read(content_virtual_address,256 , pad=True)
	offset = 0
	while b'\x00\x00' not in read_bytes:
		offset+=256
		content += read_bytes.decode('utf-16', errors = 'replace')
		raw_content += read_bytes
		read_bytes = layer.read(content_virtual_address + offset,256 , pad=True)

	final_bytes = read_bytes.split(b'\x00\x00')[0] + b'\x00'
	content += final_bytes.decode('utf-16', errors = 'replace')
	raw_content += final_bytes 
	return content, raw_content

class NoteExtractor(interfaces.plugins.PluginInterface):
	_required_framework_version = (2, 0, 0)
	_version = (1, 0, 0)


	@classmethod
	def get_requirements(cls):
		return [
			requirements.ModuleRequirement(name='kernel', description='Windows kernel', architectures=["Intel32", "Intel64"]),
			requirements.VersionRequirement(name='pslist', component=pslist.PsList, version=(3, 0, 0)),
			requirements.SymbolTableRequirement(name="nt_symbols", description="Windows kernel symbols"),
			requirements.IntRequirement(name='pid', description="PID to extract notes from", optional=False)
		]

	def find_static_cache_vad(self, vad_node):
		if vad_node.get_file_name() != "\\Windows\\Fonts\\StaticCache.dat":
			return True

		# Keep everything else
		return False

	def find_content_pointer_vad(self, vad_node):
		kernel = self.context.modules[self.config['kernel']]
		protect_vals = vadinfo.VadInfo.protect_values(
			self.context,
			kernel.layer_name,
			kernel.symbol_table_name
		)
		winnt_vals = vadinfo.winnt_protections

		if vad_node.get_tag() != "VadS":
			#print(f"{hex(vad_node.get_start())}: wrong tag!")
			return True

		if vad_node.get_protection(protect_vals, winnt_vals) != "PAGE_READWRITE":
			#print(f"{hex(vad_node.get_start())}: wrong protection!")
			return True

		if vad_node.get_private_memory() != 1:
			#print(f"{hex(vad_node.get_start())}: wrong private memory config!")
			return True

		# Keep everything else
		return False

	def _generator(self):
		target_pid = self.config.get('pid')
		
		for task in pslist.PsList.list_processes(self.context, self.config['kernel']):
			if task.UniqueProcessId != target_pid:
				continue
			
			layer_name = task.add_process_layer()
			layer = self.context.layers[layer_name]
			StaticCache_vad_end = -1
			for vad in vadinfo.VadInfo.list_vads(task, filter_func=self.find_static_cache_vad):
				StaticCache_vad_end = vad.get_end() + 1

			for vad in vadinfo.VadInfo.list_vads(task, filter_func=self.find_content_pointer_vad):
				# method 1. VAD directly after StaticCache.dat
				if vad.get_start() == StaticCache_vad_end:
					content_virtual_address = verify_address(vad.get_start(), layer)
					if content_virtual_address == False:
						continue
					else:
						print(f"Content found after StaticCache.dat VAD at {hex(content_virtual_address)}")
						content, raw_content = get_content(content_virtual_address, layer)
						yield(0, [hex(content_virtual_address), content, raw_content])
						continue

				# method 2. VAD contains valid address at offset 8
				content_virtual_address = verify_address(vad.get_start(), layer)
				if content_virtual_address == False:
					continue
				else:
					print(f"valid VAD found at {hex(content_virtual_address)}")
					content, raw_content = get_content(content_virtual_address, layer)
					yield(0, [hex(content_virtual_address), content, raw_content])
					continue

	def run(self):
		return renderers.TreeGrid([
			("Virtual Address", str),
			("Content", str),
			("Content as Bytes", bytes)
		], self._generator())
