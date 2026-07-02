import base64
import hashlib
import json
from pathlib import Path

from app.models import GatewayRecording, Session, utcnow


class GatewayRecorder:
    def __init__(self, base_dir: str = "/data/recordings"):
        self.base_dir = Path(base_dir)
        self.base_dir.mkdir(parents=True, exist_ok=True)

    def path_for(self, session_id: int) -> Path:
        return self.base_dir / f"session_{session_id}.log"

    def append(self, session: Session, stream: str, data: bytes | str, sequence: int) -> None:
        payload = data.encode() if isinstance(data, str) else data
        line = {
            "timestamp": utcnow().isoformat(),
            "stream": stream,
            "data": base64.b64encode(payload).decode(),
            "session_id": session.gateway_session_id or str(session.id),
            "sequence": sequence,
        }
        with self.path_for(session.id).open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(line, ensure_ascii=False) + "\n")

    def checksum(self, path: str | Path) -> tuple[int, str]:
        file_path = Path(path)
        digest = hashlib.sha256()
        size = 0
        if not file_path.exists():
            return 0, digest.hexdigest()
        with file_path.open("rb") as handle:
            for chunk in iter(lambda: handle.read(65536), b""):
                size += len(chunk)
                digest.update(chunk)
        return size, digest.hexdigest()

    def finalize_model(self, recording: GatewayRecording) -> GatewayRecording:
        size, checksum = self.checksum(recording.recording_path)
        recording.size_bytes = size
        recording.checksum_sha256 = checksum
        recording.ended_at = utcnow()
        return recording
