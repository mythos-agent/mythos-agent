# Demo GIF Recording Script

A 15-second demo GIF embedded at the top of README is the single highest-conversion asset for a dev-tool launch. This doc tells you exactly what to record, how, and where to put it.

---

## Why this matters

First 30 seconds of a HN/Reddit/npm visit: readers skim, not read. A looping GIF at the top of the README converts **~3×** better than text-only repos at similar traffic. Continue.dev, Bun, Ollama, Socket.dev all led with demo video/GIF on launch day. **Do not launch without this.**

**Target:** 12–15 seconds. Under 2 MB. Shows one complete value flow in a real terminal, with `10ms` speed as the hero moment.

---

## Tools (Windows-friendly, the only platforms this user cares about)

| Tool | Type | Why |
|---|---|---|
| **[ScreenToGif](https://www.screentogif.com)** | GUI, point-and-click | Free, single `.exe` (no install). Records any window, has built-in editor with text overlays, trim, and crop. **Recommended for v1.** |
| **[VHS](https://github.com/charmbracelet/vhs)** | Scriptable, reproducible | Go tool by Charm. Write a `demo.tape` file, run `vhs demo.tape`, get a deterministic GIF. Use if you want the demo to be re-generatable from source. `scoop install vhs` or `winget install charmbracelet.vhs`. |

~~asciinema + svg-term-cli~~ — **removed** from this guide. asciinema doesn't have reliable native Windows support and requires WSL. If you're ever on macOS/Linux and want crisp SVG output, revisit it then.

---

## Pre-recording checklist

**Terminal setup:**
- Font: **14–16pt** Cascadia Code, Consolas, or Geist Mono. Not 12pt default.
- Theme: dark background, near `#0B0B0F` if you can set it. Tokyo Night or Windows Terminal "One Half Dark" both work.
- Window: resize to **80 columns × 24 rows** (standard, readable on mobile preview).
- Clean prompt: a short `$ ` or `PS>` is better than a multi-line powerline prompt with git branch / timestamps / path. If your prompt is busy, use a fresh terminal with default PS1.

**Fixture setup:**
```
cd E:\Github\sphinx-agent\demo-vulnerable-app
cls
```

Why: `demo-vulnerable-app/` produces **exactly 13 findings** in ~10ms, with 5 high-severity ones visible before the `...and N more` truncation. And running from *inside* the directory means the command on screen is just `npx mythos-agent quick` — identical to what a visitor will type in their own project. No `--path` flag clutter.

**Cache warmup (do NOT record this):**
```
npx mythos-agent quick
```
Run once before recording so the npx cache is warm. Otherwise your GIF accidentally includes 5 seconds of npm downloading.

---

## The 12-second recording sequence (v1 — simple)

Target: someone skimming a README gets the full value in under 15 seconds.

| Time | What happens on screen | Purpose |
|---|---|---|
| 0:00 | Blank terminal, `$ ` prompt | Establishes "this is a real shell" |
| 0:01 | Type `# find security bugs in your code` and press Enter | 1-sec setup — tells cold viewer what problem this solves |
| 0:03 | Type `npx mythos-agent quick` and press Enter | The copy-paste command |
| 0:04 | Output renders instantly (10ms) | Speed is the hero moment |
| 0:04 | 5 findings visible: `🔴 SQL Injection`, `🔴 JWT None Algorithm`, `🔴 Database Connection String`, `🟠 XSS × 2`, `...and 8 more`, `→ mythos-agent fix --severity critical --apply` | The payoff |
| 0:04 → 0:11 | **Hold final frame for ~7 seconds** | Viewer reads everything; the header `10ms` callout sinks in |
| 0:11 → 0:12 | Loop back to 0:00 | Clean restart |

**Don't type fast.** Use ScreenToGif's "type delay" feature or just type at natural human pace — ~80–120ms per keystroke. Machine-speed typing reads as "staged."

---

## Optional: v2 story-arc demo (20–25 seconds)

Higher effort but much more memorable. Shows the **before → transform → after** loop that made Socket.dev and Bun demos famous. Use this version if you have 20 minutes to record + edit; stick with v1 if launch is this week.

| Time | Command | What viewer sees |
|---|---|---|
| 0:00 | `# some vulnerable code…` | Setup |
| 0:02 | `cat src/server.ts \| head -20` | Shows the actual vulnerable lines (SQLi, JWT, etc.) |
| 0:07 | `npx mythos-agent quick` | The scan |
| 0:08 | 5 findings appear, file:line pointing at the lines just shown | "Oh, it found all of them" |
| 0:13 | `npx mythos-agent fix --severity critical --apply` | Auto-fix |
| 0:15 | Patches applied, ~2 critical issues fixed | Transformation |
| 0:18 | `npx mythos-agent quick` (re-run) | Proof |
| 0:20 | Clean output — zero critical | Payoff |
| 0:20 → 0:23 | Hold final frame | Reader absorbs |
| 0:23 | Loop | |

This version needs the auto-fix command to actually produce clean diffs. Test run `mythos-agent fix --severity critical --apply` first; if the patches are ugly or don't compile, fall back to v1.

---

## Post-processing (in ScreenToGif editor)

1. **Trim** leading and trailing dead frames so intro/outro are ≤1s each.
2. **Speed**: if you typed too slowly, use "Playback → Override delay" to tighten gaps. Don't speed up the actual scan output — that's the hero moment.
3. **Text overlay — highly recommended for v1:** during the final held frame (0:05 onward), add a text callout pointing at the `10ms` number. Example: `← 13 bugs found in 10ms`. ScreenToGif's "Drawing" panel supports this. Takes 60 seconds, massive visual win.
4. **Frame rate**: 15 fps is plenty for terminal text. Dropping from 24 → 15 roughly halves filesize.
5. **Color palette**: reduce to 64 colors (terminal output doesn't need 256). Cuts filesize ~40%.
6. **Resize** to max 1200px wide.
7. **Target**: under **2 MB**. GitHub's hard cap is 10 MB, but big GIFs load slowly on the package page.

---

## Save + embed

**Filename:** `E:\Github\sphinx-agent\assets\demo.gif`

**README embed** — add this right below the Cerby banner, above the badges:

```markdown
<p align="center">
  <img alt="mythos-agent — 10-second security check" src="assets/demo.gif" width="720">
</p>
```

**Recommended README order** (top-down):
1. Cerby banner (identity) — already there
2. **Demo GIF** ← this new block
3. Badges row — already there
4. `<h1>` tagline — already there
5. Quick-start links — already there

---

## Verification before launch

- [ ] GIF opens at correct dimensions in browser
- [ ] Filesize under 2 MB
- [ ] Commands shown match current CLI (run them yourself right before recording to confirm)
- [ ] No personal paths, secrets, or stack traces in view
- [ ] Loops cleanly — last frame content matches the blank-prompt first frame
- [ ] Renders inline in GitHub README preview before push (use VS Code's markdown preview or `gh repo view --web`)
- [ ] Readable at README's default rendering width
- [ ] Mobile test — open the repo on your phone after push, confirm the demo is legible

---

## Common mistakes to avoid

- ❌ **Loading a config file / wizard on screen.** First impression killer. Zero-config run or it didn't happen.
- ❌ **API key prompts.** Use `quick` (pattern-only, offline).
- ❌ **Running `hunt`** — it's your most impressive command but takes 30–90 seconds. Save it for YouTube / blog posts.
- ❌ **Stack traces or warnings in the output.** Clear any `WARN` lines before recording.
- ❌ **Your real file paths** (e.g., `/Users/zhijie/secret-project/`). Record from inside the fixture directory.
- ❌ **Huge prompts.** A `PS E:\Github\sphinx-agent\demo-vulnerable-app>` prompt eats screen width. Temporarily set a simpler prompt for the recording.
- ❌ **Cursor blinking forever after output.** Add a `sleep 1` or press `↵` to move the cursor to a new clean line before stopping the recording.

---

## 5-minute recording checklist

1. Open ScreenToGif
2. Navigate terminal to `E:\Github\sphinx-agent\demo-vulnerable-app`
3. Bump font to 15pt, dark theme, resize window to ~80×24
4. `cls`
5. Run `npx mythos-agent quick` once (not recorded — just warms cache)
6. `cls` again
7. ScreenToGif → Recorder → drag frame over terminal window
8. F7 to start
9. Type `# find security bugs in your code` → Enter
10. Type `npx mythos-agent quick` → Enter
11. Wait ~7 seconds on the final frame
12. F8 to stop
13. Editor opens → trim dead frames → add text overlay `← 13 bugs in 10ms` during final frame → File → Save as → GIF → `E:\Github\sphinx-agent\assets\demo.gif`
14. Drag the file into a browser to verify it plays and loops cleanly
15. If happy, ping me to wire the README embed

---

## If you pick VHS instead (scriptable, reproducible)

Save this as `docs/demo.tape` in the repo (not required for launch; nice for future demo iterations):

```
Output assets/demo.gif
Set FontSize 15
Set Width 800
Set Height 480
Set Theme "Tokyo Night"
Set Shell "cmd"
Type "# find security bugs in your code"
Enter
Sleep 1s
Type "npx mythos-agent quick"
Enter
Sleep 8s
```

Then `cd demo-vulnerable-app && vhs ../docs/demo.tape`. The output GIF is deterministic — regenerate it anytime the CLI output format changes.
