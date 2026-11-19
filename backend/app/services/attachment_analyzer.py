import os
import re
from typing import List, Dict, Any
from app.schemas.analysis import AttachmentFinding
from app.services.email_parser import ParsedEmail

DANGEROUS_EXTENSIONS = {
    "exe", "bat", "cmd", "sh", "vbs", "vbe", "js", "jse", "wsf", "wsh",
    "scr", "pif", "hta", "cpl", "jar", "msi", "msp", "dll", "com", "ps1",
    "ps2", "vxd", "reg", "inf", "scf", "lnk", "gadget"
}

MACRO_EXTENSIONS = {
    "docm", "xlsm", "pptm", "dotm", "xltm", "xlam", "ppam", "ppsm", "sldm"
}

ARCHIVE_CONTAINER_EXTENSIONS = {
    "iso", "img", "vhd", "vhdx", "dmg"
}

EXECUTABLE_MIME_TYPES = {
    "application/x-dosexec", "application/x-msdownload", "application/exe",
    "application/x-exe", "application/dos-exe", "vms/exe", "application/x-winexe",
    "application/msdos-windows", "application/x-executable", "application/x-sharedlib",
    "application/x-bat", "application/x-sh", "application/x-csh",
    "application/x-msdos-program"
}

SAFE_MIME_TYPES = {
    "application/pdf", "image/jpeg", "image/png", "image/gif", "text/plain",
    "application/msword", "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
    "application/vnd.ms-excel", "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
}

class AttachmentAnalyzerService:
    @staticmethod
    def analyze_attachments(parsed_email: ParsedEmail) -> List[AttachmentFinding]:
        """Safely inspect email attachments for dangerous executables, macros, double extensions, MIME mismatches, and size anomalies."""
        findings: List[AttachmentFinding] = []

        for att in parsed_email.attachments:
            fname = att.get("filename", "unnamed").strip()
            size = att.get("file_size_bytes", 0)
            ctype = att.get("content_type", "application/octet-stream").lower().split(";")[0].strip()
            ext = att.get("extension", "").lower()
            md5_h = att.get("md5_hash", "")
            sha256_h = att.get("sha256_hash", "")

            # 1. Double extension check (e.g., invoice.pdf.exe)
            fname_clean = fname.rstrip(". ")
            parts = fname_clean.split(".")
            is_double_ext = False
            if len(parts) >= 3:
                second_last = parts[-2].lower()
                last = parts[-1].lower()
                if second_last in ["pdf", "doc", "docx", "xls", "xlsx", "jpg", "png", "txt"]:
                    if last in DANGEROUS_EXTENSIONS or last in ["zip", "rar", "7z", "iso"]:
                        is_double_ext = True

            # 2. Executable / script check
            is_exec = ext in DANGEROUS_EXTENSIONS or ctype in EXECUTABLE_MIME_TYPES

            # 3. Macro check
            is_macro = ext in MACRO_EXTENSIONS

            # 4. Disk image / archive container check
            is_container = ext in ARCHIVE_CONTAINER_EXTENSIONS

            # 5. MIME mismatch check
            # Case A: Executable disguised with a safe file extension (e.g. evil.pdf with application/x-dosexec)
            # Case B: Executable extension claiming safe MIME (e.g. payload.exe with application/pdf)
            is_mime_mismatch = False
            if ext in ["pdf", "jpg", "jpeg", "png", "txt", "docx", "xlsx"] and ctype in EXECUTABLE_MIME_TYPES:
                is_mime_mismatch = True
            elif ext in DANGEROUS_EXTENSIONS and ctype in SAFE_MIME_TYPES:
                is_mime_mismatch = True

            # 6. Size check (>15MB)
            is_large = size > (15 * 1024 * 1024)

            # 7. Suspicious flag
            is_suspicious = is_exec or is_double_ext or is_macro or is_container or is_mime_mismatch

            # Determine risk level and recommendation
            if is_mime_mismatch:
                risk_lvl = "CRITICAL"
                recom = f"CRITICAL MIME MISMATCH: Attachment '{fname}' has extension '.{ext}' but declares executable MIME type '{ctype}'. Deceptive evasion tactic."
            elif is_exec or is_double_ext:
                risk_lvl = "CRITICAL"
                recom = f"DO NOT OPEN OR RUN: Attachment '{fname}' contains executable code or a deceptive extension commonly used to deliver ransomware or trojans."
            elif is_macro:
                risk_lvl = "HIGH"
                recom = f"HIGH RISK: Macro-enabled office document '{fname}' can run VBA scripts upon opening. Open in protected view only."
            elif is_container:
                risk_lvl = "HIGH"
                recom = f"Disk image file '{fname}' detected. Attackers frequently use ISO/IMG files to bypass email gateway filters."
            elif is_large:
                risk_lvl = "MEDIUM"
                recom = f"Oversized attachment ({round(size / (1024*1024), 2)} MB). Verify authenticity with sender before download."
            elif is_suspicious:
                risk_lvl = "MEDIUM"
                recom = f"Suspicious file properties detected for '{fname}'."
            else:
                risk_lvl = "LOW"
                recom = f"Standard non-executable file format ({ext.upper() if ext else 'Unknown'}). Normal caution applies."

            findings.append(AttachmentFinding(
                filename=fname,
                file_size_bytes=size,
                content_type=ctype,
                detected_type=f".{ext}" if ext else "unknown",
                extension=ext,
                is_executable=is_exec,
                is_macro=is_macro,
                is_double_extension=is_double_ext,
                is_mime_mismatch=is_mime_mismatch,
                is_suspicious=is_suspicious,
                md5_hash=md5_h,
                sha256_hash=sha256_h,
                risk_level=risk_lvl,
                recommendation=recom
            ))

        return findings
