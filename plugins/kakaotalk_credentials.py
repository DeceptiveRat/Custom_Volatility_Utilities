import logging
from volatility3.framework import renderers, interfaces, exceptions
from volatility3.framework.exceptions import VolatilityException
from volatility3.framework.configuration import requirements
from volatility3.plugins.windows import pslist, vadinfo, vadyarascan
from volatility3.plugins import yarascan
from volatility3.plugins.yarascan import USE_YARA_X

import re
import math

vollog = logging.getLogger(__name__)

def find_password_pointer(start_address, end_address, layer):
	password_pointer_rule = r"""
	rule pattern1 {
		strings:
			$a = /\x00{16}\x10\xc1\x5a\x42\x01\x00{3}\xf8\xc1\x5a\x42\x01\x00{7}\xff{8}\x00{52}.{16}\x00{32}/
		condition:
			$a
	}
	"""

	if USE_YARA_X:
		import yara_x
		compiled_rules = yara_x.compile(password_pointer_rule)
	else:
		import yara
		compiled_rules = yara.compile(source=password_pointer_rule)
	
	scanner = yarascan.YaraScanner(rules=compiled_rules)
	chunk = layer.read(start_address, end_address-start_address+1, pad=True)

	password_list = []
	address_list = []

	for offset, rule_name, name, value in scanner(chunk, start_address):
		password_address_bytes = layer.read(offset+160, 8, pad=False)

		password_address = int.from_bytes(password_address_bytes, byteorder="little")
		password = get_password(password_address, layer)
		if password:
			password_list.append(password)
			address_list.append(password_address)

	return password_list, address_list

def find_email_pointer(start_address, end_address, layer):
	email_pointer_rule = r"""
	rule pattern1 {
		strings:
			$a = /\xc8\x1d\x65\x42\x01\x00{11}\x04\x12\x34\x00\x21\x2b\x00{10}.{32}\x14\x00{7}\x17\x00{7}/
		condition:
			$a
	}
	rule pattern2 {
		strings:
			$a = /\x0f\x00{31}.{32}\x27\x00{7}\x2f\x00{7}.{16}\x14\x00{7}\x17\x00{7}\x69\x00\x6f\x00\x73\x00{11}\x03\x00{7}\x07\x00{7}\x32\x00\x36\x00\x2e\x00\x33\x00\x2e\x00\x35\x00{5}\x06\x00{7}\x07\x00{7}/
		condition:
			$a
	}
	rule pattern3 {
		strings:
			$a = /\x28\x03\x7b\x42\x01\x00{27}.{16}\x00{16}.{64}\x00{8}\x01\x00{3}\x0a\x73\xdc\x00/
		condition:
			$a
	}
	"""

	if USE_YARA_X:
		import yara_x
		compiled_rules = yara_x.compile(email_pointer_rule)
	else:
		import yara
		compiled_rules = yara.compile(source=email_pointer_rule)
	
	scanner = yarascan.YaraScanner(rules=compiled_rules)
	chunk = layer.read(start_address, end_address-start_address+1, pad=True)

	email_list = []
	address_list = []
	pattern_list = []

	for offset, rule_name, name, value in scanner(chunk, start_address):
		if rule_name == "pattern1":
			email_address_bytes = layer.read(offset+48, 8, pad=False)
			pattern = 1

		elif rule_name == "pattern2":
			email_address_bytes = layer.read(offset+80, 8, pad=False)
			pattern = 2

		else:
			email_address_bytes = layer.read(offset+88, 8, pad=False)
			pattern = 3
		
		email_address = int.from_bytes(email_address_bytes, byteorder="little")
		email = get_email(email_address, layer)
		if email:
			email_list.append(email)
			address_list.append(email_address)
			pattern_list.append(pattern)

	return email_list, address_list, pattern_list

def get_email(email_address, layer):
	email_bytes = b""
	while True:
		word = layer.read(email_address, 2, pad=True)
		email_address+=2
		if word == b"\x00\x00":
			break
		email_bytes += word
	
	email = email_bytes.decode('utf-16')
	if "@" not in email:
		return None
	else:
		return email

def get_password(password_address, layer):
	password_bytes = b""
	while True:
		word = layer.read(password_address, 2, pad=True)
		password_address+=2
		if word == b"\x00\x00":
			break
		password_bytes += word
	
	password_disallowed_characters = r"[^a-zA-Z0-9!@#$%^&*()\-_+=]"
	password = password_bytes.decode('utf-16')
	if re.findall(password_disallowed_characters, password):
		return None
	else:
		return password

class KakaotalkCredentials(interfaces.plugins.PluginInterface):
	_required_framework_version = (2, 0, 0)
	_version = (1, 0, 0)

	@classmethod
	def get_requirements(cls):
		return [
			requirements.ModuleRequirement(name='kernel', description='Windows kernel', architectures=["Intel32", "Intel64"]),
			requirements.VersionRequirement(name='pslist', component=pslist.PsList, version=(3, 0, 0)),
			requirements.SymbolTableRequirement(name="nt_symbols", description="Windows kernel symbols"),
			requirements.IntRequirement(name='pid', description="PID of KakaoTalk", optional=False)
		]

	def find_pointer_vad(self, vad_node):
		kernel = self.context.modules[self.config['kernel']]
		protect_vals = vadinfo.VadInfo.protect_values(
			self.context,
			kernel.layer_name,
			kernel.symbol_table_name
		)
		winnt_vals = vadinfo.winnt_protections

		if vad_node.get_tag() != "VadS":
			return True

		if vad_node.get_protection(protect_vals, winnt_vals) != "PAGE_READWRITE":
			return True

		if vad_node.get_private_memory() != 1:
			return True

		# Keep everything else
		return False

	def _generator(self):
		target_pid = self.config.get('pid')
		target_tasks = []
		
		for task in pslist.PsList.list_processes(self.context, self.config['kernel']):
			if task.UniqueProcessId != target_pid:
				continue
			else:
				target_tasks.append(task)
			
		for task in target_tasks:
			layer_name = task.add_process_layer()
			layer = self.context.layers[layer_name]

			for vad in vadinfo.VadInfo.list_vads(task, filter_func=self.find_pointer_vad):
				try: 
					start_address = vad.get_start()
					# filter out VADs that are not qualitifed
					if layer.read(start_address, 8, pad=False) != b"\x00"*8:
						continue
					if layer.read(start_address+14, 12, pad=False) != b"\x01\x01\xee\xff\xee\xff\x02\x00\x00\x00\x18\x00":
						continue
					
					# find email
					email_list, address_list, pattern_list = find_email_pointer(vad.get_start(), vad.get_end(), layer)
					for index in range(len(email_list)):
						yield(0, [hex(address_list[index]), str(pattern_list[index]), "Email address", email_list[index]])

					# find password
					password_list, address_list = find_password_pointer(vad.get_start(), vad.get_end(), layer)
					for index in range(len(password_list)):
						yield(0, [hex(address_list[index]), "-" , "password", password_list[index]])
				
				except VolatilityException:
					pass

	def run(self):
		return renderers.TreeGrid([
			("Virtual Address", str),
			("Pattern Number", str),
			("Content type", str),
			("Content", str)
		], self._generator())
