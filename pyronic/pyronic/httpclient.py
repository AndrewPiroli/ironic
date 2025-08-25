import json
from enum import Enum, auto
from typing import List, Sequence, Tuple, Union

import requests


class Width(Enum):
	"""Memory access width"""
	B = auto()
	H = auto()
	W = auto()
	def __str__(self):
		return f'{self.name}'

class ArmThumbOption(Enum):
	"""Select between Arm and Thumb mode"""
	Arm = auto()
	Thumb = auto()
	ByCpsr = auto()
	def __str__(self):
		return f'{self.name}'

class AccessKind(Enum):
	"""Memory Access Permission for Tranlation Requests"""
	Debug = auto()
	"""Ignores Permission Checks - You probably want this one"""
	Read = auto()
	Write = auto()
	def __str__(self):
		return f'{self.name}'


class RemoteDebugError(Exception):
	"""The emulator rejected a request. `reason` is the message it sent back."""
	def __init__(self, status: int, reason: str) -> None:
		super().__init__(f"HTTP {status}: {reason}" if reason else f"HTTP {status}")
		self.status = status
		self.reason = reason


def _check(r: requests.Response) -> requests.Response:
	"""Like raise_for_status, but keeps the body (the emulator's reason) in the exception."""
	if 400 <= r.status_code < 600:
		raise RemoteDebugError(r.status_code, r.text.strip())
	return r


class RemoteDebugClient:
	def __init__(self, base_url: str, timeout: float = 5.0) -> None:
		self.base = base_url.rstrip("/")
		self.session = requests.Session()
		self.timeout = timeout

	def get_registers(self) -> List[int]:
		r = self.session.get(f"{self.base}/registers", timeout=self.timeout)
		_check(r)
		regs = r.json()
		# ensure ints
		return [int(x) for x in regs]

	def set_registers(self, regs: Sequence[int]) -> None:
		if len(regs) != 17:
			raise ValueError("registers must be a sequence of 17 integers")
		r = self.session.put(f"{self.base}/registers", json=list(regs), timeout=self.timeout)
		_check(r)


	def step(self, n: int = 1) -> None:
		if n < 1:
			raise ValueError("n must be >= 1")
		# API only accepts single-step (the server rejects >1), but forward the value
		r = self.session.post(f"{self.base}/step", json=n, timeout=self.timeout)
		_check(r)

	def resume(self) -> None:
		r = self.session.post(f"{self.base}/resume", timeout=self.timeout)
		_check(r)

	def interrupt(self) -> None:
		r = self.session.post(f"{self.base}/break", timeout=self.timeout)
		_check(r)


	def list_breakpoints(self) -> List[int]:
		r = self.session.get(f"{self.base}/breakpoints", timeout=self.timeout)
		_check(r)
		return [int(x) for x in r.json()]

	def add_breakpoint(self, addr: int) -> None:
		r = self.session.post(f"{self.base}/breakpoints/add", json=addr, timeout=self.timeout)
		_check(r)

	def remove_breakpoint(self, addr: int) -> None:
		r = self.session.post(f"{self.base}/breakpoints/remove", json=addr, timeout=self.timeout)
		_check(r)


	def mem_read(self, addr: int, org: Width, size: int) -> bytes:
		"""Read `size` bytes."""
		opts = {"addr": int(addr), "org": str(org), "size": int(size)}
		r = self.session.post(f"{self.base}/mem/read", json=opts, timeout=self.timeout)
		_check(r)
		return r.content

	def mem_read_chunked(self, addr: int, org: Width, size: int, chunk: int = 0x1000) -> List[Tuple[int, int, Union[bytes, str]]]:
		"""Best-effort read: splits the span into `chunk`-aligned pieces and returns a
		list of (addr, len, bytes) for readable pieces and (addr, len, reason) for
		unreadable ones. Adjacent pieces of the same kind are coalesced."""
		width = {Width.B: 1, Width.H: 2, Width.W: 4}[org]
		runs: List[Tuple[int, int, Union[bytes, str]]] = []
		cur = addr
		end = addr + size
		while cur < end:
			n = min(chunk - (cur % chunk), end - cur)
			# Keep each piece a multiple of the access width; the server rejects otherwise.
			n -= n % width
			if n == 0:
				n = min(width, end - cur)
			try:
				piece: Union[bytes, str] = self.mem_read(cur, org, n)
			except RemoteDebugError as e:
				piece = e.reason or str(e)
			if runs:
				start, plen, prev = runs[-1]
				if isinstance(prev, bytes) and isinstance(piece, bytes):
					runs[-1] = (start, plen + n, prev + piece)
					cur += n
					continue
				if isinstance(prev, str) and prev == piece:
					runs[-1] = (start, plen + n, prev)
					cur += n
					continue
			runs.append((cur, n, piece))
			cur += n
		return runs

	def mem_write(self, addr: int, org: Width, data: bytes) -> None:
		opts = {"addr": int(addr), "org": str(org), "size": len(data)}
		# multipart: 'options' contains JSON, 'data' contains binary
		files = {
			"options": ("options.json", json.dumps(opts).encode("utf-8"), "application/json"),
			"data": ("data", data, "application/octet-stream"),
		}
		r = self.session.post(f"{self.base}/mem/write", files=files, timeout=self.timeout)
		_check(r)

	def disassembly(self, addr: int, mode: ArmThumbOption) -> str:
		r = self.session.get(f"{self.base}/disassemble/{mode}/{addr:x}", timeout=self.timeout)
		_check(r)
		return r.text

	def get_consoledbg(self) -> bool:
		r = self.session.get(f"{self.base}/consoledbg")
		_check(r)
		return bool(r.json())

	def set_consoledbg(self, toset: bool) -> None:
		r = self.session.put(f"{self.base}/consoledbg", data="{}".format(str(toset).lower()), headers={"Content-Type": "application/json"})
		_check(r)

	def translate(self, addr: int, access: AccessKind = AccessKind.Debug) -> requests.Response:
		r = self.session.get(f"{self.base}/translate/{addr:x}/{access}")
		return r

	def set_icache(self, enabled: bool) -> None:
		r = self.session.put(f"{self.base}/icache", json=enabled, timeout=self.timeout)
		_check(r)

	def getstatus(self) -> str:
		r = self.session.get(f"{self.base}/status")
		_check(r)
		return r.text
