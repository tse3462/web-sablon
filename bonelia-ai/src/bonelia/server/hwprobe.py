"""Hardware assessment for the home AI server and a local-model size recommendation.

Recommendations are rough guidance for 4-bit quantised instruct models served by
Ollama. Real performance must be measured on the actual machine.
"""

from __future__ import annotations

import platform
import shutil
import subprocess

import psutil


def _gpus() -> list[dict]:
    exe = shutil.which("nvidia-smi")
    if not exe:
        return []
    try:
        out = subprocess.run([exe, "--query-gpu=name,memory.total", "--format=csv,noheader,nounits"],
                             capture_output=True, text=True, timeout=10, check=False).stdout
    except (OSError, subprocess.TimeoutExpired):
        return []
    gpus = []
    for line in out.strip().splitlines():
        parts = [p.strip() for p in line.split(",")]
        if len(parts) == 2 and parts[1].isdigit():
            gpus.append({"name": parts[0], "vram_mb": int(parts[1])})
    return gpus


def assess(data_path: str = ".") -> dict:
    ram_gb = round(psutil.virtual_memory().total / 1024**3, 1)
    disk_free_gb = round(shutil.disk_usage(data_path).free / 1024**3, 1)
    gpus = _gpus()
    vram_gb = round(max((g["vram_mb"] for g in gpus), default=0) / 1024, 1)
    if vram_gb >= 22:
        rec, note = "~32B (e.g. qwen2.5:32b-instruct)", "GPU with >=24 GB VRAM"
    elif vram_gb >= 11:
        rec, note = "~14B (e.g. qwen2.5:14b-instruct)", "GPU with >=12 GB VRAM"
    elif vram_gb >= 7 or ram_gb >= 16:
        rec, note = "~7-8B (e.g. qwen2.5:7b-instruct, llama3.1:8b)", "8 GB VRAM or >=16 GB RAM (CPU will be slow)"
    elif ram_gb >= 8:
        rec, note = "~3B (e.g. qwen2.5:3b-instruct)", "small model; limited reasoning quality"
    else:
        rec, note = "cloud-only mode recommended", "insufficient RAM for a useful local model"
    warnings = []
    if disk_free_gb < 20:
        warnings.append("less than 20 GB free disk — model files need 2-20 GB each")
    if not gpus:
        warnings.append("no NVIDIA GPU detected (AMD/Apple/Intel GPUs are not probed in v0.1)")
    return {
        "os": f"{platform.system()} {platform.release()}",
        "cpu": platform.processor() or platform.machine(),
        "cpu_cores_logical": psutil.cpu_count(logical=True),
        "ram_gb": ram_gb,
        "gpus": gpus,
        "disk_free_gb": disk_free_gb,
        "recommended_local_model": rec,
        "reason": note,
        "warnings": warnings,
        "disclaimer": "Guidance only; local model performance is not guaranteed and must be measured.",
    }
