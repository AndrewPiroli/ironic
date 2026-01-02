import shlex
from typing import List

from hexdump import hexdump
from pyronic.httpclient import RemoteDebugClient, Width, ArmThumbOption, AccessKind
from requests.exceptions import *


class DebugREPL:
	def __init__(self) -> None:
		self.client: RemoteDebugClient | None = None
		self.repeat = False
		self.last: str | None = None

	def connect(self, url: str = "http://localhost:9999") -> None:
		self.client = RemoteDebugClient(url)
		print(f"connected to {url}")

	def do_registers(self, args: List[str]) -> None:
		if not self.client:
			print("not connected")
			return
		regs = self.client.get_registers()
		names = [f"  r{i}" for i in range(10)] + [f" r{i}" for i in range(10, 13, 1)] + ["  sp", "  lr", "  pc", "cpsr"]
		for i, v in enumerate(regs):
			name = names[i] if i < len(names) else f"r{i}"
			print(f"{name}: 0x{v:08X}")

	def do_setreg(self, args: List[str]) -> None:
		if not self.client:
			print("not connected")
			return
		if len(args) != 2:
			print("usage: setreg <index> <value_hex_or_dec>")
			return
		idx = None
		name_map = {f"r{i}": i for i in range(13)}
		name_map.update({"sp": 13, "lr": 14, "pc": 15, "cpsr": 16})
		try:
			idx = int(args[0])
		except ValueError:
			idx = name_map.get(args[0].lower())
		if idx is None:
			print("unknown register")
			return
		val = int(args[1], 16)
		regs = self.client.get_registers()
		if idx < 0 or idx >= len(regs):
			print("index out of range")
			return
		regs[idx] = val
		self.client.set_registers(regs)
		print(f"r{idx} <- 0x{val:08X}")

	def do_step(self, args: List[str]) -> None:
		if not self.client:
			print("not connected")
			return
		n = 1
		if args:
			n = int(args[0])
		try:
			for i in range(n):
				self.client.step(1)
				print(f"stepped {i+1}/{n}", end='\r')
		except KeyboardInterrupt:
			pass
		finally:
			print()

	def do_resume(self, args: List[str]) -> None:
		if not self.client:
			print("not connected")
			return
		self.client.resume()
		print("resumed")

	def do_interrupt(self, args: List[str]) -> None:
		if not self.client:
			print("not connected")
			return
		self.client.interrupt()
		print("sent interrupt")

	def help(self) -> None:
		print(" Debugger Control")
		print("------------------")
		print("connect [url] (default = http://localhost:9999)")
		print("quit")
		print("repeat")
		print()
		print(" Basic Commands")
		print("----------------")
		print("step [n]")
		print("interrupt")
		print("continue")
		print("bkpt list|add|rm <addr|reg>")
		print()
		print(" Register Info")
		print("---------------")
		print("regs")
		print("setreg <i> <val>")
		print()
		print(" Memory Inspection")
		print("-------------------")
		print("mem view <addr> <size> [B|H|W]")
		print("dis <addr|reg> [arm|thumb]")
		print("translate <addr> [r|w|d]")
		print()
		print(" Misc")
		print("------")
		print("consoledbg [on|off|toggle]")

	def do_mem_view(self, args: List[str]) -> None:
		if not self.client:
			print("not connected")
			return
		if len(args) < 2:
			print("usage: mem view <addr> <size> [B|H|W]")
			return
		addr_arg = args[0]
		addr = None
		name_map = {f"r{i}": i for i in range(13)}
		name_map.update({"sp": 13, "lr": 14, "pc": 15, "cpsr": 16})
		try:
			addr = int(addr_arg, 16)
		except ValueError:
			if addr_arg.lower() in name_map:
				if not self.client:
					print("not connected")
					return
				regs = self.client.get_registers()
				addr = regs[name_map[addr_arg.lower()]]
			else:
				print("invalid address or register")
				return
		size = int(args[1], 16)
		org = Width.B
		if len(args) >= 3:
			w = args[2].upper()
			if w == "B":
				org = Width.B
			elif w == "H":
				org = Width.H
			elif w == "W":
				org = Width.W
			else:
				print("width must be one of B, H, W")
				return
		try:
			data = self.client.mem_read(addr, org, size)
		except Exception as e:
			print(f"mem read failed: {e}")
			return
		print(hexdump(data))

	def do_mem_write(self, args: List[str]) -> None:
		if not self.client:
			print("not connected")
			return
		if len(args) < 2:
			print("usage: mem write <addr> <hex-bytes> [B|H|W]")
			return
		addr_arg = args[0]
		addr = None
		name_map = {f"r{i}": i for i in range(13)}
		name_map.update({"sp": 13, "lr": 14, "pc": 15, "cpsr": 16})
		try:
			addr = int(addr_arg, 16)
		except ValueError:
			if addr_arg.lower() in name_map:
				if not self.client:
					print("not connected")
					return
				regs = self.client.get_registers()
				addr = regs[name_map[addr_arg.lower()]]
			else:
				print("invalid address or register")
				return
		hexstr = args[1].replace(" ", "")
		if hexstr.startswith("0x"):
			hexstr = hexstr[2:]
		if len(hexstr) % 2 != 0:
			hexstr = "0" + hexstr
		try:
			data = bytes.fromhex(hexstr)
		except ValueError:
			print("invalid hex bytes")
			return
		org = Width.B
		if len(args) >= 3:
			w = args[2].upper()
			if w == "B":
				org = Width.B
			elif w == "H":
				org = Width.H
			elif w == "W":
				org = Width.W
			else:
				print("width must be one of B, H, W")
				return
		try:
			self.client.mem_write(addr, org, data)
		except Exception as e:
			print(f"mem write failed: {e}")
			return
		print(f"wrote {len(data)} bytes to 0x{addr:08X}")

	def do_bkpt(self, args: List[str]) -> None:
		if not self.client:
			print("not connected")
			return
		client = self.client
		if len(args) < 2:
			print("usage: bkpt list|add|rm <addr|reg>")
			return
		sub = args[0]
		# helper to resolve address or register name
		def resolve_addr(a: str):
			name_map = {f"r{i}": i for i in range(13)}
			name_map.update({"sp": 13, "lr": 14, "pc": 15, "cpsr": 16})
			try:
				return int(a, 16)
			except ValueError:
				if a.lower() in name_map:
					regs = client.get_registers()
					return regs[name_map[a.lower()]]
				raise
		if sub == "list":
			try:
				res = self.client.list_breakpoints()
				if not res:
					print("no breakpoints")
				else:
					for b in res:
						print(f"0x{int(b):08X}")
			except Exception as e:
				print(f"bkpt list failed: {e}")
		elif sub == "add":
			if len(args) < 2:
				print("usage: bkpt add <addr|reg>")
				return
			try:
				addr = resolve_addr(args[1])
			except Exception:
				print("invalid address or register")
				return
			try:
				self.client.add_breakpoint(addr)
				print(f"added breakpoint 0x{addr:08X}")
			except Exception as e:
				print(f"bkpt add failed: {e}")
		elif sub in ("rm", "remove"):
			if len(args) < 2:
				print("usage: bkpt rm <addr|reg>")
				return
			try:
				addr = resolve_addr(args[1])
			except Exception:
				print("invalid address or register")
				return
			try:
				self.client.remove_breakpoint(addr)
				print(f"removed breakpoint 0x{addr:08X}")
			except Exception as e:
				print(f"bkpt rm failed: {e}")
		else:
			print("unknown bkpt subcommand")
	
	def do_disassemble(self, args: List[str]) -> str | None:
		if len(args) < 1:
			print("Usage: disassemble <addr|reg> [arm|thumb]")
			return
		addr_arg = args[0]
		addr = None
		name_map = {f"r{i}": i for i in range(13)}
		name_map.update({"sp": 13, "lr": 14, "pc": 15, "cpsr": 16})
		try:
			addr = int(addr_arg, 16)
		except ValueError:
			if addr_arg.lower() in name_map:
				if not self.client:
					print("not connected")
					return
				regs = self.client.get_registers()
				addr = regs[name_map[addr_arg.lower()]]
			else:
				print("invalid address or register")
				return
		mode = ArmThumbOption.ByCpsr
		try:
			mode_arg = args[1]
			if mode_arg.lower() == "arm":
				mode = ArmThumbOption.Arm
			elif mode_arg.lower() == "thumb":
				mode = ArmThumbOption.Thumb
			elif mode_arg.lower() == "bycpsr":
				pass
			else:
				print("Invalid disasembly mode. [arm, thumb, bycpsr]")
				return None
		except IndexError:
			pass
		except Exception:
			print("Failed to parse disassembly mode. [arm, thumb, bycpsr]")
			return None
		try:
			print(self.client.disassembly(addr, mode))
		except Exception as e:
			print(f"Failed: {e}")

	def do_consoledbg(self, args: List[str]) -> None:
		p = None
		if len(args) == 0:
			if self.client.get_consoledbg():
				p = True
			else:
				p = False
		elif args[0] in ("true", "on"):
			self.client.set_consoledbg(True)
			p = True
		elif args[0] in ("false", "off"):
			self.client.set_consoledbg(False)
			p = False
		elif args[0] in ("t", "toggle"):
			p = not self.client.get_consoledbg()
			self.client.set_consoledbg(p)
		if p:
			print("Console Debug Print: On")
		else:
			print("Console Debug Print: Off")

	def translate(self, args: List[str]) -> None:
		if not self.client:
			print("Not connected")
			return
		if len(args) < 1:
			print("Usage: translate <addr> [r|w|d]")
			return
		access = AccessKind.Debug
		if len(args) > 1:
			if args[1].lower() in ("r", "read"):
				access = AccessKind.Read
			elif args[1].lower() in ("w", "write"):
				access = AccessKind.Write
			elif args[1].lower() not in ("d", "debug"):
				print("Usage: translate <addr> [r|w|d]")
				return
		addr = None
		name_map = {f"r{i}": i for i in range(13)}
		name_map.update({"sp": 13, "lr": 14, "pc": 15, "cpsr": 16})
		if args[0].lower() in name_map:
				regs = self.client.get_registers()
				addr = regs[name_map[args[0].lower()]]
		else:
			try:
				addr = int(args[0], 16)
			except ValueError:
				print("Invalid address format: {}".format(args[0]))
				return
		res = self.client.translate(addr, access)
		if res.status_code < 300:
			print(hex(int(res.text)))
		else:
			print(res.text)

	def repl(self) -> None:
		while True:
			try:
				line = input("dbg> ")
				if not line:
					if self.repeat and self.last is not None and not self.last.lower().startswith("repeat"):
						line = self.last
					else:
						continue
				else:
					self.last = line
				parts = shlex.split(line)
				cmd = parts[0]
				args = parts[1:]
				if cmd in ("q", "quit", "exit"):
					break
				elif cmd == "connect":
					if not args:
						self.connect()
					else:
						self.connect(args[0])
				elif cmd == "mem":
					if not args:
						print("usage: mem view <addr> <size> [B|H|W]")
						print("usage: mem write <addr> <hex-bytes> [B|H|W]")
						continue
					sub = args[0]
					if sub == "view":
						self.do_mem_view(args[1:])
					elif sub == "write":
						self.do_mem_write(args[1:])
					else:
						print("unknown mem command")
				elif cmd in ("bkpt", "breakpoints"):
					self.do_bkpt(args)
				elif cmd in ("h", "help"):
					self.help()
				elif cmd in ("regs", "registers"):
					self.do_registers(args)
				elif cmd == "setreg":
					self.do_setreg(args)
				elif cmd == "step":
					self.do_step(args)
				elif cmd in ("continue", "resume"):
					self.do_resume(args)
				elif cmd in ("int", "interrupt", "break"):
					self.do_interrupt(args)
				elif cmd == "repeat":
					self.repeat = not self.repeat
					print("Repeat mode: {}".format("On" if self.repeat else "Off"))
				elif cmd in ("dis", "disassemble"):
					self.do_disassemble(args)
				elif cmd == "consoledbg":
					self.do_consoledbg(args)
				elif cmd == "translate":
					self.translate(args)
				else:
					print("unknown command")
			except (EOFError, KeyboardInterrupt):
				break
			except ConnectionError:
				print(f"Connection Failed {self.client.base}")
			except IndexError:
				raise


if __name__ == "__main__":
	repl = DebugREPL()
	repl.repl()

