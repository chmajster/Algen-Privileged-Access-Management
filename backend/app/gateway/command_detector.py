from dataclasses import dataclass, field

from app.session_monitor import detect_sudo_command


CONTROL_PREFIXES = ("\x1b",)
BACKSPACE = {"\b", "\x7f"}
ENTER = {"\r", "\n"}


@dataclass
class CommandDetector:
    buffer: list[str] = field(default_factory=list)
    command_index: int = 0
    _in_escape: bool = False

    def feed(self, data: bytes | str) -> list[dict]:
        text = data.decode(errors="ignore") if isinstance(data, bytes) else data
        detected: list[dict] = []
        for char in text:
            if self._in_escape:
                if char.isalpha() or char in "~":
                    self._in_escape = False
                continue
            if char in CONTROL_PREFIXES:
                self._in_escape = True
                continue
            if char in BACKSPACE:
                if self.buffer:
                    self.buffer.pop()
                continue
            if char in ENTER:
                command = "".join(self.buffer).strip()
                self.buffer.clear()
                if command:
                    self.command_index += 1
                    detected.append(
                        {
                            "command": command,
                            "command_index": self.command_index,
                            "is_sudo": detect_sudo_command(command),
                        }
                    )
                continue
            if char.isprintable() or char == "\t":
                self.buffer.append(char)
        return detected
