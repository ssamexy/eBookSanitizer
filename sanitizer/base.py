from typing import List, Dict, Any, Callable, Optional
from enum import Enum


class SanitizeMode(Enum):
    """Three-tier sanitization modes (截長補短三級消毒架構)."""
    STANDARD = "standard"   # 🟢 Remove known dangerous content, preserve most features
    STRICT = "strict"       # 🟡 Also neutralize external links and embedded resources
    PARANOID = "paranoid"   # 🔴 Maximum security, rebuild object tree with minimal content


class Threat:
    def __init__(self, threat_type: str, path: str, description: str, severity: str = "High"):
        self.type = threat_type        # e.g., "JavaScript", "AutoAction", "DangerousFile", "ExternalLink"
        self.path = path              # e.g., "OEBPS/content.html" or "Object 12"
        self.description = description
        self.severity = severity      # "High", "Medium", "Low"

    def to_dict(self) -> Dict[str, Any]:
        return {
            "type": self.type,
            "path": self.path,
            "description": self.description,
            "severity": self.severity
        }

    def __str__(self) -> str:
        return f"[{self.severity}] {self.type} in {self.path}: {self.description}"


class SanitizeReport:
    def __init__(self, file_path: str):
        self.file_path = file_path
        self.sha256 = ""
        self.has_threats = False
        self.threats: List[Threat] = []
        self.sanitized_path = ""
        self.success = False
        self.errors: List[str] = []
        self.logs: List[str] = []
        self._log_callback: Optional[Callable[[str], None]] = None

    def add_threat(self, threat: Threat):
        self.threats.append(threat)
        self.has_threats = True

    def log(self, message: str):
        self.logs.append(message)
        if self._log_callback:
            self._log_callback(message)

    def error(self, message: str):
        self.errors.append(message)
        self.logs.append(f"ERROR: {message}")
        if self._log_callback:
            self._log_callback(f"ERROR: {message}")

    def set_log_callback(self, callback: Callable[[str], None]):
        """Set a callback for real-time log streaming to the GUI."""
        self._log_callback = callback

    def threat_summary(self) -> Dict[str, int]:
        """Aggregate threat counts by severity."""
        summary = {"High": 0, "Medium": 0, "Low": 0}
        for t in self.threats:
            if t.severity in summary:
                summary[t.severity] += 1
        return summary

    def to_dict(self) -> Dict[str, Any]:
        return {
            "file_path": self.file_path,
            "sha256": self.sha256,
            "has_threats": self.has_threats,
            "threat_summary": self.threat_summary(),
            "threats": [t.to_dict() for t in self.threats],
            "sanitized_path": self.sanitized_path,
            "success": self.success,
            "errors": self.errors,
            "logs": self.logs
        }


class BaseSanitizer:
    def __init__(self, file_path: str, log_callback: Optional[Callable[[str], None]] = None):
        self.file_path = file_path
        self.report = SanitizeReport(file_path)
        if log_callback:
            self.report.set_log_callback(log_callback)
        self._calculate_sha256()

    def _calculate_sha256(self):
        import hashlib
        sha256 = hashlib.sha256()
        try:
            with open(self.file_path, 'rb') as f:
                while chunk := f.read(8192):
                    sha256.update(chunk)
            self.report.sha256 = sha256.hexdigest()
        except Exception as e:
            self.report.log(f"Warning: Could not calculate SHA-256: {e}")

    def scan(self) -> SanitizeReport:
        """Scan the file for threats and update the report. Do not modify the file."""
        raise NotImplementedError("Subclasses must implement scan()")

    def sanitize(self, output_path: str, mode: SanitizeMode = SanitizeMode.STANDARD, scrub_metadata: bool = False) -> SanitizeReport:
        """Sanitize the file and save the result to output_path.
        
        Args:
            output_path: Path for the sanitized output file.
            mode: One of STANDARD, STRICT, or PARANOID.
            scrub_metadata: If True, anonymizes metadata fields.
        """
        raise NotImplementedError("Subclasses must implement sanitize()")
