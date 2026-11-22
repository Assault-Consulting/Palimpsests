---
title: AI on small devices, and the log they keep
slug: ai-on-small-devices-and-the-log-they-keep
date: 2026-11-22
description: A device that decides things alone needs a record someone else can check later. What makes that hard on a device, what PALA-1 does about each part, and what it does not do yet.
tags: iot, edge-ai, audit-log, pala-1
seo_title: AI on IoT devices, and the log they keep
seo_description: A device that decides alone needs a record others can check. What is hard about logging on a device, and what the PALA-1 format does about each part.
page: /pala-1/
related: pala-1-three-design-principles, llm-on-an-isolated-network, what-makes-an-audit-log-tamper-evident
---

A camera at a gate decides whether to open it. A box in a workshop listens to a motor and decides when to stop the line. A robot in a warehouse chooses its own route. In each of them a model makes the decision, and nobody is standing next to it.

Later someone asks what the device decided, and why. The owner asks, or an insurer, or an inspector. The answer comes from whatever the device wrote down. So the real question is whether that record can be trusted by a person who did not write it.

This note is about that record: why it is harder to keep on a device than on a server, and why we think PALA-1 is the right shape for it.

## What is hard about a device

A server sits in a room with power, a network, a clock and an administrator. A device has none of these for certain.

- **It does not know the time.** A small computer without a clock battery starts in 1970. The network that would correct it may not be there.
- **It loses power in the middle of a sentence.** Somebody pulls the plug while a record is half written.
- **It restarts often,** and each restart is a chance to lose the thread.
- **It has little storage.** Old records have to go, or the device stops.
- **It gets overloaded,** and then something is dropped.
- **It is offline,** for hours or for good. There is no cloud to send the log to as it is written.
- **Its owner holds it in their hands,** with the storage and everything on it.
- **What it sees is private.** A camera sees faces. A device in a home hears the home.
- **It outlives its software.** A machine works for ten years or more. The company that wrote its log code may not.

A log format made for servers assumes most of this away. A plain text file, or one line of JSON per event, says nothing about any of it: a wrong date looks like a right one, a missing hour looks like a quiet hour, and anyone with the file can edit it.

## What PALA-1 does about each

PALA-1 is a format for a log: the exact bytes of each record, and the rules for checking them. Every record carries the hash of the one before it, so a change anywhere shows up in everything after. That part is common. The rest was designed around the list above.

**Time.** Each record has two clocks: a counter since the device started, which is always there, and the date, which may not be. Next to the date is a field saying how far to believe it: unknown, free-running, a battery clock, or set from outside. A device that does not know the date writes zero and says so, and a reader must report a date written next to "unknown" as an error. Order never depends on the date; it comes from the record's number.

**Power cuts.** By default the writer returns only after the record is on storage. If the last record was cut in half, the next start removes the half and writes down that it did.

**Restarts.** Each start writes a record that links to the last record of the previous run. The chain goes through a power cycle unbroken, and a reader can count the restarts. Since version 0.15 a writer also records its own opening and closing, so a run that ended without closing is visible as such.

**Little storage.** The log can be cut into pieces, and old pieces can be deleted. The first record of each new piece states what came before it and what the keeping period was. A reader who has only the recent pieces sees a log whose beginning is gone and which says why, not a log that looks tampered with.

**Overload.** If records are dropped, a record is written saying how many and of what kind. That record is never itself dropped. A gap you can see is survivable. A gap you cannot see is a log that lies.

**Offline.** Checking needs the file and nothing else: no account, no service, no network. The checker's core uses only the Python standard library.

**The owner.** A chain alone cannot stop its owner from writing a new one. What can is a copy of the latest hash kept somewhere the owner cannot change. That copy is 32 bytes, small enough for almost any link a device has.

**Privacy.** The chain is checked from the record headers alone. The contents can be encrypted, and the check does not need the key. So an inspector can confirm that nothing was changed or removed without seeing a single face. If the contents must be erased, the key is destroyed, the contents become noise, and the chain still holds.

**Ten years.** The format is frozen at version 1.0 and published with no rights reserved, together with test files that say byte for byte what a correct reader must produce. Five readers have been written independently, three of them outside this project. A log written today does not depend on our code still running.

## Why this format and not another

Four properties matter more on a device than anywhere else.

It is **binary and fixed.** A record starts with 156 bytes laid out in a table, and the hash is taken over those bytes as they are. There is no text to normalise and no numbers to round, so two programs cannot disagree about what was hashed. On small hardware that is also simply less work.

It **says what it does not know.** The time may be unknown. The level of trust is a field, not a promise. A dropped record is counted. A tool result the recorder could not see is marked as unseen. A log that admits its limits survives questions that a confident one does not.

It **separates the envelope from the meaning.** The chain, the clocks and the checks are the core. What an event means lives in a profile on top. Today there is one profile, for AI systems: tool calls, incidents, human oversight, declared deletions. A profile for sensor readings or actuator commands could be added without touching the core or breaking any reader.

It **can be checked by the other side.** The point of a record is the person who doubts it. They can use their own reader, written from the document.

## What it does not do yet

We would rather say this here than have you find it.

- **There is no writer for a microcontroller.** The writer in this project is Python. It fits a gateway or a single-board computer running Linux, not a chip with kilobytes of memory. What the format asks of such a chip is small: SHA-256 twice per record, a fixed header, a counter that survives a restart, and storage that can be appended to. Nobody has built it and run it, so we claim nothing about it.
- **Nothing ties the log to the hardware out of the box.** The format has a level for a hardware root of trust. This project can keep the anchor in a hardware token, and that path has been tested against a software token only. Saying that one particular device wrote a log needs a real token on that device, and we have not run one. Until then a log proves it was not changed; it does not prove which device wrote it.
- **The log is not the truth.** It proves what the device recorded, unmodified. If the model was wrong, the log keeps the wrong answer faithfully.
- **There is no device profile.** The record kinds that exist are about AI systems.

## A shape that works today

Put the recorder on the gateway, next to the model: the single-board computer that already runs it. Let the gateway write the chain. Send the latest hash, those 32 bytes, somewhere else on a schedule — to the owner's server, to a second device, to paper. Cut the log by size and delete old pieces by the rule you declared. When someone asks, hand them the file and the command:

```
palimpsests pala verify device.pala --anchor-file head.txt
```

They do not need to trust the device, or us.
