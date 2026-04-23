# Launch Responses Log

Running log of substantive replies to launch-thread comments. Append newest entries at the bottom. Source material for the T+7d retrospective post and future launch-response playbook refinements.

Companion to `LAUNCH-KIT.md` (outgoing content). This file tracks the inbound conversation and what was sent back.

## How to append a new entry

Copy this template to the bottom of the file, fill in the fields, keep the `---` separator above it.

```markdown
## YYYY-MM-DD · <channel> · <short title>

**Thread:** <URL>
**Commenter:** <username or handle>
**Status:** draft / posted / awaiting reply / closed
**Context:** 1 or 2 lines on what this is and why it matters.

### Original comment

> paste their comment, using blockquote
> if multi-paragraph use one > per paragraph

### My reply

(paste reply text here, inside a fenced block so it copies cleanly)

### Strategic notes

- optional bullet points on why this framing, what to watch for next, follow-up moves
```

---

## 2026-04-23 · r/cybersecurity · Second-wave LLM bug patterns

**Thread:** `<add r/cybersecurity post URL when confirmed>`
**Commenter:** `<add username>`
**Status:** posted 2026-04-23, awaiting reply
**Context:** First substantive technical reply on the r/cybersecurity launch post. Commenter is clearly in the space, referenced Checkmarx's taint-analysis extension for LLM-integrated code by name. Replying fast establishes credibility with everyone else reading.

### Original comment

> The second wave after prompt injection hardening is usually indirect data exfiltration through legitimate tool calls, model output trusted as safe input downstream without re-validation.
>
> On the SAST gap you flagged, checkmarx has been extending taint analysis specifically for LLM-integrated code, treating model output as an untrusted source in the data flow graph. Still evolving but it's the right architectural framing.

### My reply

```markdown
Both patterns you named are exactly the right next layer, and the Checkmarx framing feels right to me. Treating model output as an untrusted source is the same mental shift as "user input is always untrusted" twenty years ago.

Here's where mythos-agent actually sits today:

**Indirect exfiltration via legitimate tool calls.** Only caught when the tool allowlist is visibly missing or a tool argument is directly user-controlled. The confused-deputy case, where read-file-tool and network-tool get chained within one legitimate session, is a known gap. Right fix is per-conversation tool capability tracking, not a static rule. On the roadmap, not shipping in v4.0.0.

**Model output trusted as safe input downstream.** This is the bigger blind spot. v4.0.0 flags direct `exec(llm.output)` style cases but doesn't yet model taint flow with model output as a source node. That's exactly the data-flow-graph extension you're describing. The hypothesis-generation pipeline actually lines up well for this. A per-function agent can be prompted to ask "does any value in this function originate from an LLM call, and is it re-validated before a sink?" But it needs a first-class notion of "LLM source" in the taint graph, otherwise you drown in false positives.

Quick question, has Checkmarx published anything concrete on their taint-source extension? Or is it something you've seen in the product rather than in papers? The public material I've found is sparse, would love a pointer if there's one.
```

### Strategic notes

- Pattern: validate their point first, mirror their two-pattern structure with matching bold headers, be honest about v4.0.0 gaps, close with a question that treats them as peer rather than as audience.
- No GitHub / Discord / Feishu links in the reply. Those are in the OP already and repeating them reads as marketing.
- No em-dashes. Em-dashes are a recognized AI-text signature in 2026.
- If they reply with Checkmarx material, follow-up is to ask their opinion on the architecture, not defend it. Example: "Given what Checkmarx is doing, would you model the LLM-source node as a separate taint kind, or as a regular Source with a high-mistrust score?"
- If they do not reply, the thread is still a credibility win for anyone else reading the exchange.
