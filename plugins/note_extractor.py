import logging
from volatility3.framework import renderers, interfaces, exceptions
from volatility3.framework.configuration import requirements
from volatility3.plugins.windows import pslist
from volatility3.plugins.windows import vadinfo

import re
import math

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
	if len(raw_content)%2 == 1:
		raw_content=raw_content[:-1]
		content = content[:-1]
	return content, raw_content

def find_undo_text(start_address, end_address, layer):
	# get address of content VAD in little endian
	raw_address_bytes = start_address.to_bytes(8, byteorder='little')
	address_MS5bytes = raw_address_bytes[3:]
	escaped_address_bytes = re.escape(address_MS5bytes)

	# compile pointer pattern
	pattern_bytes = b'\x03\x00{7}.{3}' + escaped_address_bytes
	pattern = re.compile(pattern_bytes, re.DOTALL)

	address_list = []
	undo_text_list = []
	raw_undo_text_list = []
	for address in range(start_address, end_address, 16):
		address_data = layer.read(address, 16, pad=True)
		if not pattern.match(address_data):
			continue
		undo_text_address = int.from_bytes(address_data[8:], byteorder='little')	
		if not verify_undo_text_address(start_address, end_address, undo_text_address, layer):
			continue
		undo_text, raw_undo_text = get_content(undo_text_address, layer)
		if undo_text != "":
			undo_text_list.append(undo_text)
			raw_undo_text_list.append(raw_undo_text)
			address_list.append(undo_text_address)
	
	return address_list, undo_text_list, raw_undo_text_list

def verify_undo_text_address(start_address, end_address, undo_text_address, layer):
	# verify address range
	if undo_text_address < start_address or undo_text_address > end_address:
		return False
	# get 8 byte pattern before undo_text
	before_text = layer.read(undo_text_address-8, 8, pad=True)

	# get end of undo_text
	undo_text_length = 0
	while True:
		next_word = layer.read(undo_text_address+undo_text_length, 2, pad=False)
		if next_word == b'\x00\x00':
			# include length of null terminator
			undo_text_length+=2
			break
		undo_text_length+=2
	
	# get 8 byte pattern after undo_text
	if undo_text_length <= 16:
		after_text = layer.read(undo_text_address+24, 8, pad=True)
		after_text2 = -1
	else:
		next_pattern_offset = 8 + math.ceil((undo_text_length - 8)/16)*16
		after_text = layer.read(undo_text_address+next_pattern_offset, 8, pad=True)
		# not sure what happens when text is 23 bytes long, so may have to check next one as well
		#after_text2 = layer.read(undo_text_address+next_pattern_offset+16, 8, pad=True)
	
	# verify pattern before and after text
	# byte 2 should match
	if before_text[1] != after_text[1]:
		return False
	# byte 4 should match
	if before_text[3] != after_text[3]:
		return False
	# byte 5 should be 0
	if before_text[4] != 0 or after_text[4] != 0:
		return False
	# byte 6 should be incremented 
	if before_text[5] + 1 != after_text[5]:
		return False
	# byte 7 should be 0
	if before_text[6] != 0 or after_text[6] != 0:
		return False
	
	return True

def get_vad_for_address(task, target_address):
	for vad in vadinfo.VadInfo.list_vads(task):
		start_addr = vad.get_start()
		end_addr = vad.get_end()
		
		if start_addr <= target_address <= end_addr:
			return start_addr, end_addr
			
	return None

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
		notepad_task = []
		
		for task in pslist.PsList.list_processes(self.context, self.config['kernel']):
			if task.UniqueProcessId != target_pid:
				continue

			notepad_task.append(task)
			
		for task in notepad_task:
			layer_name = task.add_process_layer()
			layer = self.context.layers[layer_name]
			StaticCache_vad_end = -1
			for vad in vadinfo.VadInfo.list_vads(task, filter_func=self.find_static_cache_vad):
				StaticCache_vad_end = vad.get_end() + 1

			for vad in vadinfo.VadInfo.list_vads(task, filter_func=self.find_content_pointer_vad):
				# method 1. VAD directly after StaticCache.dat
				if vad.get_start() == StaticCache_vad_end:
					method="StaticCacheVad"
				# method 2. VAD contains valid address at offset 8
				else:
					method="Bruteforce"

				# find content
				content_type = "content"
				content_virtual_address = verify_address(vad.get_start(), layer)
				if content_virtual_address == False:
					continue
				else:
					content, raw_content = get_content(content_virtual_address, layer)
					yield(0, [hex(content_virtual_address), content_type, method, content, raw_content])

				# find undo text
				content_type = "undo text"
				content_VAD_start, content_VAD_end = get_vad_for_address(task, content_virtual_address)
				undo_text_address_list, undo_text_list, raw_undo_text_list = find_undo_text(content_VAD_start, content_VAD_end, layer)
				for index in range(len(undo_text_list)):
					yield(0, [hex(undo_text_address_list[index]), content_type, "-", undo_text_list[index], raw_undo_text_list[index]])

	def run(self):
		return renderers.TreeGrid([
			("Virtual Address", str),
			("Content Type", str),
			("Method", str),
			("Content", str),
			("Raw Content", bytes)
		], self._generator())
