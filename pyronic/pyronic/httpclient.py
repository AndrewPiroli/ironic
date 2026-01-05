import json
from enum import Enum, auto
from typing import List, Sequence

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


class RemoteDebugClient:
	def __init__(self, base_url: str, timeout: float = 5.0) -> None:
		self.base = base_url.rstrip("/")
		self.session = requests.Session()
		self.timeout = timeout

	def get_registers(self) -> List[int]:
		r = self.session.get(f"{self.base}/registers", timeout=self.timeout)
		r.raise_for_status()
		regs = r.json()
		# ensure ints
		return [int(x) for x in regs]

	def set_registers(self, regs: Sequence[int]) -> None:
		if len(regs) != 17:
			raise ValueError("registers must be a sequence of 17 integers")
		r = self.session.put(f"{self.base}/registers", json=list(regs), timeout=self.timeout)
		r.raise_for_status()


	def step(self, n: int = 1) -> None:
		if n < 1:
			raise ValueError("n must be >= 1")
		# API only accepts single-step (the server rejects >1), but forward the value
		r = self.session.post(f"{self.base}/step", json=n, timeout=self.timeout)
		r.raise_for_status()

	def resume(self) -> None:
		r = self.session.post(f"{self.base}/resume", timeout=self.timeout)
		r.raise_for_status()

	def interrupt(self) -> None:
		r = self.session.post(f"{self.base}/break", timeout=self.timeout)
		r.raise_for_status()


	def list_breakpoints(self) -> List[int]:
		r = self.session.get(f"{self.base}/breakpoints", timeout=self.timeout)
		r.raise_for_status()
		return [int(x) for x in r.json()]

	def add_breakpoint(self, addr: int) -> None:
		r = self.session.post(f"{self.base}/breakpoints/add", json=addr, timeout=self.timeout)
		r.raise_for_status()

	def remove_breakpoint(self, addr: int) -> None:
		r = self.session.post(f"{self.base}/breakpoints/remove", json=addr, timeout=self.timeout)
		r.raise_for_status()


	def mem_read(self, addr: int, org: Width, size: int) -> bytes:
		opts = {"addr": int(addr), "org": str(org), "size": int(size)}
		r = self.session.post(f"{self.base}/mem/read", json=opts, timeout=self.timeout)
		r.raise_for_status()
		return r.content

	def mem_write(self, addr: int, org: Width, data: bytes) -> None:
		opts = {"addr": int(addr), "org": str(org), "size": len(data)}
		# multipart: 'options' contains JSON, 'data' contains binary
		files = {
			"options": ("options.json", json.dumps(opts).encode("utf-8"), "application/json"),
			"data": ("data", data, "application/octet-stream"),
		}
		r = self.session.post(f"{self.base}/mem/write", files=files, timeout=self.timeout)
		r.raise_for_status()

	def disassembly(self, addr: int, mode: ArmThumbOption) -> str:
		r = self.session.get(f"{self.base}/disassemble/{mode}/{addr:x}")
		r.raise_for_status()
		return r.text

	def get_consoledbg(self) -> bool:
		r = self.session.get(f"{self.base}/consoledbg")
		r.raise_for_status()
		return bool(r.json())

	def set_consoledbg(self, toset: bool) -> None:
		r = self.session.put(f"{self.base}/consoledbg", data="{}".format(str(toset).lower()), headers={"Content-Type": "application/json"})
		r.raise_for_status()

	def translate(self, addr: int, access: AccessKind = AccessKind.Debug) -> requests.Response:
		r = self.session.get(f"{self.base}/translate/{addr:x}/{access}")
		return r

	def getstatus(self) -> str:
		r = self.session.get(f"{self.base}/status")
		r.raise_for_status
		return r.text
