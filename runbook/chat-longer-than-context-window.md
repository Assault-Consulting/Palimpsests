---
title: Chat longer than the context window on a small local model
slug: chat-longer-than-context-window
group: run
order: 2
updated: 2026-11-22
description: Keep a long conversation going on a model with a small context window. Palimpsests keeps the start and the latest turns, moves the middle to disk, and brings back the parts that matter.
next: local-openai-compatible-server
seo_title: Chat longer than the context window on a local model
seo_description: Keep a long conversation going on a model with a small context window: the start and latest turns stay, the middle moves to disk and returns when needed.
---

A model can read only so much text at once. That limit is its context window, and a small model on modest hardware may have 8,000 tokens or fewer. A long chat outgrows it, and something has to go. Drop the oldest messages and the model forgets what the task was. Drop messages at random and it forgets facts.

Palimpsests fits the conversation into a budget you set, before every reply:

- It always keeps the system prompt and the first two messages. They usually say what the task is.
- It always keeps the latest eight messages.
- When everything together is over the budget, it moves the oldest messages from the middle out, into a small database on your disk.
- Before each reply, it looks for the moved-out messages closest in meaning to your latest message, and puts the three closest back as one note at the start.

The budget is held at 80% of the number you give, because tokens are estimated rather than counted.

## You need

- Python 3.11 or newer.
- [Ollama](https://ollama.com) running, with a chat model and the embedding model that finds old messages again:

```bash
ollama pull qwen2.5:7b
ollama pull nomic-embed-text
```

## Steps

### 1. Install

```bash
pip install 'palimpsests[embeddings]'
export PALIMPSESTS_ALLOW_UNENCRYPTED_AUDIT=1
```

`[embeddings]` adds numpy, which compares messages. Without it the chat still works, but nothing that was moved out comes back. The second line is explained on the [runbook's first page](https://palimpsests.dev/runbook/).

### 2. Try one prompt from the terminal

```bash
palimpsests chat qwen2.5:7b -m "Explain a context window in two sentences." --context-size 4096
```

`palimpsests chat` sends one prompt. For a conversation that keeps going, use the few lines of Python in the next step.

### 3. A chat that keeps going

Save this as `longchat.py`:

```python
from palimpsests.core import chat, init_app

ctx = init_app()
messages = [{"role": "system", "content": "You are a patient tutor."}]

while True:
    text = input("you> ")
    if not text:
        break
    messages.append({"role": "user", "content": text})
    reply = ""
    for chunk in chat(ctx, model="qwen2.5:7b", messages=messages, context_size=4096):
        print(chunk.delta, end="", flush=True)
        reply += chunk.delta
    print()
    messages.append({"role": "assistant", "content": reply})
```

Run `python longchat.py` and keep talking. An empty line ends the chat. Your script keeps the whole conversation in `messages`; before each reply, Palimpsests decides what part of it the model sees.

## Check that it works

Talk past the budget, then ask about something you said near the start, and see whether the answer uses it. The moved-out messages are kept in `~/.config/palimpsests/.context-memory/blocks.db`.

## What it does, and what it does not

- It does not make the model's window bigger. The model still reads only what fits.
- Bringing old messages back is a search by meaning, three at a time. A detail mentioned once, long ago, can still be missed.
- Tokens are estimated at about 3.5 characters each, on the high side, so the budget errs toward sending less.
- The moved-out messages are stored as plain text in that database on your disk. Treat the folder like the chat itself.
- Finding old messages again needs an engine that can make embeddings, and Ollama can. Without one, or without numpy, the chat still works without it.

## Last checked

- The fitting and the recall are covered by the package's tests. The repository has no recorded run of this recipe on a real model yet.
- The commands and Python names on this page are those of palimpsests 0.15.0, checked against the published package on 22 November 2026.

## Reference

- [Usage guide: the context-size setting and the Python API](https://github.com/Assault-Consulting/Palimpsests/blob/v0.15.0/docs/USAGE.md)
- [How the window is kept, in code](https://github.com/Assault-Consulting/Palimpsests/blob/v0.15.0/src/palimpsests/context/window_manager.py)
