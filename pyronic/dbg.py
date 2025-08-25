import shlex
from dataclasses import dataclass
from typing import List, Callable, Sequence, Any

from hexdump import hexdump
from pyronic.httpclient import RemoteDebugClient, Width, ArmThumbOption, AccessKind
from requests.exceptions import ConnectionError


@dataclass
class Command:
	names: Sequence[str]
	handler: Callable[["DebugREPL", List[str]], Any]
	help: str = ""
	usage: str = ""
	category: str = ""


COMMANDS: List[Command] = []


def register_command(names: Sequence[str], help: str = "", usage: str = "", category: str = ""):
	def _decorator(fn: Callable[["DebugREPL", List[str]], Any]):
		COMMANDS.append(Command(names=names, handler=fn, help=help, usage=usage, category=category))
		return fn

	return _decorator


class DebugREPL:
	def __init__(self) -> None:
		self.client: RemoteDebugClient | None = None
		self.repeat = False
		self.last: str | None = None
		# Build dispatch map from registered commands
		self._cmd_map = {}
		for c in COMMANDS:
			for n in c.names:
				self._cmd_map[n] = c

	def connect(self, url: str = "http://localhost:9999") -> None:
		self.client = RemoteDebugClient(url)
		print(f"connected to {url}")

	def help(self) -> None:
		# dynamic help grouped by category
		from collections import defaultdict
		groups = defaultdict(list)
		for c in COMMANDS:
			cat = c.category or "Misc"
			groups[cat].append(c)
		for cat in sorted(groups.keys()):
			print(f"{cat}:")
			for c in sorted(groups[cat], key=lambda x: x.names[0]):
				print(f"  {', '.join(c.names)}: {c.help}")
				if c.usage:
					print(f"    Usage: {c.usage}")
			print()
		print("connect [url] (default = http://localhost:9999)")
		print("quit, exit")
		print("repeat")

	def repl(self) -> None:
		while True:
			try:
				line = input("dbg> ")
				original_line = None
				if not line:
					if self.repeat and self.last is not None and not self.last.lower().startswith("repeat"):
						line = self.last
					else:
						continue
				else:
					original_line = line
				parts = shlex.split(line)
				cmd = parts[0]
				args = parts[1:]
				if cmd in ("q", "quit", "exit"):
					break
				# special handling for 'connect' and 'mem'
				if cmd == "connect":
					if not args:
						self.connect()
					else:
						self.connect(args[0])
					if original_line is not None:
						self.last = original_line
					continue
				if cmd == "mem":
					if not args:
						print("usage: mem view <addr> <size> [B|H|W]")
						print("usage: mem write <addr> <hex-bytes> [B|H|W]")
						continue
					sub = args[0]
					if sub == "view":
						handler = self._cmd_map.get("mem.view")
						if handler:
							handler.handler(self, args[1:])
							if original_line is not None:
								self.last = original_line
						else:
							print("unknown mem command")
					elif sub == "write":
						handler = self._cmd_map.get("mem.write")
						if handler:
							handler.handler(self, args[1:])
							if original_line is not None:
								self.last = original_line
						else:
							print("unknown mem command")
					else:
						print("unknown mem command")
					continue
				entry = self._cmd_map.get(cmd)
				if entry:
					entry.handler(self, args)
					# record last command unless it was 'repeat'
					if original_line is not None and cmd != "repeat":
						self.last = original_line
				else:
					print("unknown command")
			except (EOFError, KeyboardInterrupt):
				break
			except ConnectionError:
				assert self.client
				print(f"Connection Failed {self.client.base}")
			except IndexError:
				raise

@register_command(["regs", "registers"], help="Show registers", category="Registers")
def cmd_regs(repl: DebugREPL, args: List[str]) -> None:
	if not repl.client:
		print("not connected")
		return
	regs = repl.client.get_registers()
	names = [f"  r{i}" for i in range(10)] + [f" r{i}" for i in range(10, 13, 1)] + ["  sp", "  lr", "  pc", "cpsr"]
	for i, v in enumerate(regs):
		name = names[i] if i < len(names) else f"r{i}"
		print(f"{name}: 0x{v:08X}")


@register_command(["setreg"], help="Set register value", usage="setreg <index> <value_hex_or_dec>", category="Registers")
def cmd_setreg(repl: DebugREPL, args: List[str]) -> None:
	if not repl.client:
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
	regs = repl.client.get_registers()
	if idx < 0 or idx >= len(regs):
		print("index out of range")
		return
	regs[idx] = val
	repl.client.set_registers(regs)
	print(f"r{idx} <- 0x{val:08X}")


@register_command(["step"], help="Step instruction(s)", usage="step [n]", category="Basic Commands")
def cmd_step(repl: DebugREPL, args: List[str]) -> None:
	if not repl.client:
		print("not connected")
		return
	n = 1
	if args:
		n = int(args[0])
	try:
		for i in range(n):
			repl.client.step(1)
			print(f"stepped {i+1}/{n}", end='\r')
	except KeyboardInterrupt:
		pass
	finally:
		print()


@register_command(["resume", "continue"], help="Resume execution", category="Basic Commands")
def cmd_resume(repl: DebugREPL, args: List[str]) -> None:
	if not repl.client:
		print("not connected")
		return
	repl.client.resume()
	print("resumed")


@register_command(["int", "interrupt", "break"], help="Send interrupt", category="Basic Commands")
def cmd_interrupt(repl: DebugREPL, args: List[str]) -> None:
	if not repl.client:
		print("not connected")
		return
	repl.client.interrupt()
	print("sent interrupt")


@register_command(["mem.view", "mem.view"], help="View memory", usage="mem view <addr> <size> [B|H|W]", category="Memory")
def cmd_mem_view(repl: DebugREPL, args: List[str]) -> None:
	if not repl.client:
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
			if not repl.client:
				print("not connected")
				return
			regs = repl.client.get_registers()
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
		data = repl.client.mem_read(addr, org, size)
	except Exception as e:
		print(f"mem read failed: {e}")
		return
	print(hexdump(data))


@register_command(["mem.write", "mem.write"], help="Write memory", usage="mem write <addr> <hex-bytes> [B|H|W]", category="Memory")
def cmd_mem_write(repl: DebugREPL, args: List[str]) -> None:
	if not repl.client:
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
			if not repl.client:
				print("not connected")
				return
			regs = repl.client.get_registers()
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
		repl.client.mem_write(addr, org, data)
	except Exception as e:
		print(f"mem write failed: {e}")
		return
	print(f"wrote {len(data)} bytes to 0x{addr:08X}")


@register_command(["bkpt", "breakpoints"], help="Manage breakpoints", usage="bkpt list|add|rm <addr|reg>", category="Basic Commands")
def cmd_bkpt(repl: DebugREPL, args: List[str]) -> None:
	if not repl.client:
		print("not connected")
		return
	client = repl.client
	if len(args) < 1:
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
			res = repl.client.list_breakpoints()
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
			repl.client.add_breakpoint(addr)
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
			repl.client.remove_breakpoint(addr)
			print(f"removed breakpoint 0x{addr:08X}")
		except Exception as e:
			print(f"bkpt rm failed: {e}")
	else:
		print("unknown bkpt subcommand")


@register_command(["dis", "disassemble"], help="Disassemble code", usage="disassemble <addr|reg> [arm|thumb]", category="Memory")
def cmd_disassemble(repl: DebugREPL, args: List[str]) -> str | None:
	if not repl.client:
		print("Not Connected")
		return
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
			if not repl.client:
				print("not connected")
				return
			regs = repl.client.get_registers()
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
		print(repl.client.disassembly(addr, mode))
	except Exception as e:
		print(f"Failed: {e}")


@register_command(["consoledbg"], help="Console debug prints on/off/toggle")
def cmd_consoledbg(repl: DebugREPL, args: List[str]) -> None:
	if not repl.client:
		print("Not Connected")
		return
	p = None
	if len(args) == 0:
		if repl.client.get_consoledbg():
			p = True
		else:
			p = False
	elif args[0] in ("true", "on"):
		repl.client.set_consoledbg(True)
		p = True
	elif args[0] in ("false", "off"):
		repl.client.set_consoledbg(False)
		p = False
	elif args[0] in ("t", "toggle"):
		p = not repl.client.get_consoledbg()
		repl.client.set_consoledbg(p)
	if p:
		print("Console Debug Print: On")
	else:
		print("Console Debug Print: Off")


@register_command(["h", "help"], help="Show help for commands", usage="help [command]")
def cmd_help(repl: DebugREPL, args: List[str]) -> None:
	if args:
		# try exact match
		key = args[0]
		entry = repl._cmd_map.get(key)
		if not entry:
			# support space -> dot for mem view/write
			entry = repl._cmd_map.get(key.replace(" ", "."))
		if entry:
			print(f"{', '.join(entry.names)}: {entry.help}")
			if entry.usage:
				print(f"Usage: {entry.usage}")
		else:
			print(f"no help for '{args[0]}'")
	else:
		repl.help()


@register_command(["repeat"], help="Toggle repeat mode", category="Settings")
def cmd_repeat(repl: DebugREPL, args: List[str]) -> None:
	repl.repeat = not repl.repeat
	print("Repeat mode: {}".format("On" if repl.repeat else "Off"))


@register_command(["translate"], help="Translate address", usage="translate <addr> [r|w|d]", category="Memory")
def cmd_translate(repl: DebugREPL, args: List[str]) -> None:
	if not repl.client:
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
		regs = repl.client.get_registers()
		addr = regs[name_map[args[0].lower()]]
	else:
		try:
			addr = int(args[0], 16)
		except ValueError:
			print("Invalid address format: {}".format(args[0]))
			return
	res = repl.client.translate(addr, access)
	if res.status_code < 300:
		print(hex(int(res.text)))
	else:
		print(res.text)

@register_command(["status"], help="Print Status Info")
def get_status(repl: DebugREPL, args: List[str]) -> None:
	if not repl.client:
		print("Not connected")
		return
	print(repl.client.getstatus())


if __name__ == "__main__":
	repl = DebugREPL()
	repl.repl()
