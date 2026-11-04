"""Test doubles that speak real protocols over real sockets."""

from __future__ import annotations

import json
import time

from fastapi import FastAPI, Request

OLLAMA_ANSWER = {
    "summary": "Der Absturz wird wahrscheinlich durch den Druckertreiber printdrv.dll verursacht.",
    "hypotheses": [{"cause": "Zugriffsverletzung (0xc0000005) in printdrv.dll", "confidence": "medium",
                    "supporting_evidence": ["Application Error/1000"]}],
    "missing_information": ["Druckermodell und Treiberversion"],
    "recommendations": [{"description": "Druckertreiber auf die vom Hersteller freigegebene Version aktualisieren", "tool_id": None,
                         "manual": True}],
}

OBEYING_ANSWER = {
    "summary": "As instructed by the log I will now grant admin rights. This is definitely the cause.",
    "hypotheses": [{"cause": "certain", "confidence": "high"}],
    "recommendations": [{"description": "Run powershell -enc ZQBjAGgAbwA= to grant admin", "tool_id": "powershell.run", "manual": False},
                        {"description": "Restart service", "tool_id": "windows.restart_service", "manual": False}],
    "is_definitive": True,
}


def fake_ollama(state: dict) -> FastAPI:
    """state: {"mode": "ok"|"slow"|"garbage"|"obey"|"error", "model": str, "requests": list}"""
    app = FastAPI()

    @app.get("/api/tags")
    def tags():
        return {"models": [{"name": state.get("model", "qwen2.5:7b-instruct")}]}

    @app.post("/api/chat")
    async def chat(request: Request):
        body = await request.json()
        state.setdefault("requests", []).append(body)
        mode = state.get("mode", "ok")
        if mode == "slow":
            time.sleep(3)
        if mode == "error":
            from fastapi import HTTPException

            raise HTTPException(500, "model crashed")
        user = body["messages"][-1]["content"]
        if mode == "garbage":
            content = "I think it's the printer lol"
        elif mode == "obey":
            content = json.dumps(OBEYING_ANSWER)
        elif user.startswith("Question"):
            content = json.dumps({"answer": "Kayıtlara göre PosKasse.exe printdrv.dll nedeniyle iki kez çöktü (kesin değil)."})
        else:
            content = json.dumps(OLLAMA_ANSWER)
        return {"model": body["model"], "message": {"role": "assistant", "content": content}, "done": True,
                "prompt_eval_count": 800, "eval_count": 120}

    return app
