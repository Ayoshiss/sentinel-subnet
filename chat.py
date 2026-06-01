#!/usr/bin/env python3
"""
TAO Gateway — interactive terminal chat
"""

import json
import os
import urllib.request
import urllib.error
import socket
import ssl
import sys

API_KEY  = os.getenv("TAO_API_KEY", "")
BASE_URL = os.getenv("TAO_GATEWAY_URL", "https://tao-gateway.fly.dev") + "/v1/chat/completions"
MODEL    = "gpt-4o"

history = []
total_prompt = 0
total_completion = 0
total_requests = 0

def chat(user_message):
    global total_prompt, total_completion, total_requests

    history.append({"role": "user", "content": user_message})

    payload = json.dumps({
        "model": MODEL,
        "messages": history
    }).encode()

    req = urllib.request.Request(
        BASE_URL,
        data=payload,
        headers={
            "Authorization": f"Bearer {API_KEY}",
            "Content-Type": "application/json"
        }
    )

    try:
        with urllib.request.urlopen(req, timeout=90) as resp:
            data = json.loads(resp.read())

    except urllib.error.HTTPError as e:
        try:
            body = json.loads(e.read())
            msg = body.get("error", body.get("detail", str(e)))
        except Exception:
            msg = str(e)
        print(f"\n  \033[31m❌ Error:\033[0m {msg}\n")
        history.pop()
        return

    except (socket.timeout, TimeoutError, ssl.SSLError, ConnectionResetError, OSError) as e:
        print(f"\n  \033[31m❌ Connection error:\033[0m {e}\n  Try again in a moment.\n")
        history.pop()
        return

    except Exception as e:
        print(f"\n  \033[31m❌ Unexpected error:\033[0m {e}\n")
        history.pop()
        return

    if "choices" not in data:
        print(f"\n  \033[31m❌ Bad response:\033[0m {data}\n")
        history.pop()
        return

    reply = (data["choices"][0]["message"].get("content") or "").strip()
    usage = data.get("usage", {})
    model = data.get("model", MODEL)

    prompt_tok     = usage.get("prompt_tokens", 0)
    completion_tok = usage.get("completion_tokens", 0)
    total_tok      = usage.get("total_tokens", 0)

    total_prompt     += prompt_tok
    total_completion += completion_tok
    total_requests   += 1

    cost = (total_prompt * 0.50 + total_completion * 1.50) / 1_000_000

    history.append({"role": "assistant", "content": reply})

    print(f"\n  \033[36mAssistant\033[0m  {reply}")
    print(f"\n  \033[90m↳ {model} · {total_tok} tokens · session: "
          f"{total_prompt + total_completion} tokens · "
          f"{total_requests} requests · ~${cost:.6f} spent\033[0m\n")


def main():
    if not API_KEY:
        print("\n  ❌ TAO_API_KEY not set.")
        print("  Run: export TAO_API_KEY=sk_live_...\n")
        sys.exit(1)

    print("\n  \033[1mTAO Gateway Chat\033[0m")
    print(f"  Model: {MODEL} → Bittensor SN64 (DeepSeek V3.2-TEE)")
    print("  Type your message. Ctrl+C to quit.\n")
    print("  " + "─" * 60 + "\n")

    while True:
        try:
            user_input = input("  \033[32mYou\033[0m  ").strip()
        except (KeyboardInterrupt, EOFError):
            print(f"\n\n  Session ended. {total_requests} requests, "
                  f"{total_prompt + total_completion} total tokens.\n")
            sys.exit(0)

        if not user_input:
            continue

        chat(user_input)

if __name__ == "__main__":
    main()
