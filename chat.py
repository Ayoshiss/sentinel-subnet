#!/usr/bin/env python3
"""
TAO Gateway: interactive terminal chat (streaming)
"""

import json
import os
import re
import urllib.request
import urllib.error
import socket
import ssl
import sys

API_KEY  = os.getenv("TAO_API_KEY", "")
BASE_URL = os.getenv("TAO_GATEWAY_URL", "https://tao-gateway.fly.dev") + "/v1/chat/completions"
MODEL    = "gpt-4o"

DIM   = "\033[90m"
CYAN  = "\033[36m"
GREEN = "\033[32m"
RED   = "\033[31m"
RESET = "\033[0m"

history = []
total_prompt = 0
total_completion = 0
total_requests = 0


def chat(user_message):
    global total_prompt, total_completion, total_requests

    history.append({"role": "user", "content": user_message})

    payload = json.dumps({
        "model": MODEL,
        "messages": history,
        "stream": True,
    }).encode()

    req = urllib.request.Request(
        BASE_URL,
        data=payload,
        headers={
            "Authorization": f"Bearer {API_KEY}",
            "Content-Type": "application/json",
        },
    )

    full = []
    prompt_tok = completion_tok = total_tok = 0
    model = MODEL
    printed_header = False
    in_think = False  # dim reasoning emitted inline as <think>…</think>

    try:
        with urllib.request.urlopen(req, timeout=90) as resp:
            for raw in resp:
                line = raw.decode("utf-8", "ignore").strip()
                if not line or not line.startswith("data: "):
                    continue
                data = line[6:]
                if data == "[DONE]":
                    break
                try:
                    chunk = json.loads(data)
                except Exception:
                    continue

                u = chunk.get("usage")
                if u:
                    prompt_tok     = u.get("prompt_tokens", prompt_tok)
                    completion_tok = u.get("completion_tokens", completion_tok)
                    total_tok      = u.get("total_tokens", total_tok)

                model = chunk.get("model", model)
                choices = chunk.get("choices") or []
                if not choices:
                    continue
                piece = (choices[0].get("delta") or {}).get("content") or ""
                if not piece:
                    continue

                if not printed_header:
                    sys.stdout.write(f"\n  {CYAN}Assistant{RESET}  ")
                    printed_header = True

                full.append(piece)

                # Reasoning tokens arrive wrapped in <think>…</think>: dim them
                if "<think>" in piece:
                    in_think = True
                    piece = piece.replace("<think>", "")
                    sys.stdout.write(f"{DIM}")
                if "</think>" in piece:
                    piece = piece.replace("</think>", "")
                    sys.stdout.write(f"{piece}{RESET}")
                    in_think = False
                    sys.stdout.flush()
                    continue

                sys.stdout.write(piece)
                sys.stdout.flush()

    except urllib.error.HTTPError as e:
        try:
            body = json.loads(e.read())
            msg = body.get("error", body.get("detail", str(e)))
        except Exception:
            msg = str(e)
        print(f"\n  {RED}❌ Error:{RESET} {msg}\n")
        history.pop()
        return

    except (socket.timeout, TimeoutError, ssl.SSLError, ConnectionResetError, OSError) as e:
        print(f"\n  {RED}❌ Connection error:{RESET} {e}\n  Try again in a moment.\n")
        history.pop()
        return

    except Exception as e:
        print(f"\n  {RED}❌ Unexpected error:{RESET} {e}\n")
        history.pop()
        return

    if not printed_header:
        print(f"\n  {RED}❌ No response received.{RESET}\n")
        history.pop()
        return

    # Strip <think>…</think> reasoning before storing in history
    reply_raw = "".join(full)
    reply = re.sub(r"<think>.*?</think>", "", reply_raw, flags=re.DOTALL).strip()
    history.append({"role": "assistant", "content": reply})

    total_prompt     += prompt_tok
    total_completion += completion_tok
    total_requests   += 1
    cost = (total_prompt * 0.50 + total_completion * 1.50) / 1_000_000

    print(f"\n\n  {DIM}↳ {model} · {total_tok} tokens · session: "
          f"{total_prompt + total_completion} tokens · "
          f"{total_requests} requests · ~${cost:.6f} spent{RESET}\n")


def main():
    if not API_KEY:
        print(f"\n  {RED}❌ TAO_API_KEY not set.{RESET}")
        print("  Run: export TAO_API_KEY=sk_live_...\n")
        sys.exit(1)

    print(f"\n  \033[1mTAO Gateway Chat{RESET}")
    print(f"  {DIM}Streaming · {MODEL} → Bittensor SN64 (auto-fallback across models){RESET}")
    print("  Type your message. Ctrl+C to quit.\n")
    print("  " + "─" * 60 + "\n")

    while True:
        try:
            user_input = input(f"  {GREEN}You{RESET}  ").strip()
        except (KeyboardInterrupt, EOFError):
            print(f"\n\n  Session ended. {total_requests} requests, "
                  f"{total_prompt + total_completion} total tokens.\n")
            sys.exit(0)

        if not user_input:
            continue

        chat(user_input)


if __name__ == "__main__":
    main()
