# Demo GIF Recording Script

A 15–30 second demo GIF embedded at the top of README is the single highest-conversion asset for a dev-tool launch. This doc tells you exactly what to record, how, and where to put it.

---

## Why this matters

First 30 seconds of a HN/Reddit/npm visit: readers skim, not read. A looping GIF at the top of the README converts **~3×** better than text-only repos at similar traffic. Continue.dev, Bun, Ollama all led with demo video/GIF on launch day. **Do not launch without this.**

**Target:** 15–30 seconds. Under 3 MB. Shows one complete value flow in a real terminal.

---

## Tools

| Platform | Recommended tool | Why |
|---|---|---|
| **Windows** | [ScreenToGif](https://www.screentogif.com) (free, open-source) | Records a window, has built-in editor, exports optimized GIF |
| macOS | [Kap](https://getkap.co) or [Gifox](https://gifox.io) | Native GIF workflow, small filesizes |
| Linux | [Peek](https://github.com/phw/peek) or `byzanz` | GTK-native, simple capture |
| **Terminal-only, crisp** | [asciinema](https://asciinema.org) + [svg-term-cli](https://github.com/marionebl/svg-term-cli) | Produces sharp SVG "animation" — readers can select text from the recording. Best quality for a pure-CLI demo. |

**Strong recommendation: asciinema + svg-term-cli.** SVG output is infinitely crisp, selectable-text (accessibility win), loads fast, and looks modern. Only trade-off: no mouse/window chrome.

```bash
npm install -g asciinema svg-term-cli
asciinema rec demo.cast --idle-time-limit 1
# … run the script below …
# Ctrl-D to stop
cat demo.cast | svg-term --out assets/demo.svg --window --no-cursor --width 80 --height 24
```

---

## Terminal prep (do this before recording)

- **Font:** Geist Mono, JetBrains Mono, or Fira Code at 14–16pt. Never default Consolas.
- **Theme:** dark background near `#0B0B0F` (match brand). Tokyo Night or GitHub Dark Default both work.
- **Window size:** exactly **80 columns × 24 rows** — standard, readable on mobile preview.
- **Clean shell:** `clear` first. Disable any starship/oh-my-zsh clutter. Consider a fresh terminal window with minimal prompt (`$ ` is fine).
- **Fixtures:** have a pre-seeded test project with 3–4 deliberately vulnerable files so findings are realistic and reproducible. Store as `fixtures/demo-vuln-app/` (don't commit to public repo — keep private or .gitignored).

**Caching trick:** run `npx mythos-agent quick` once before recording so npm cache is warm. Otherwise the GIF includes 8 seconds of npm downloading.

---

## The 30-second script (beat by beat)

Target reader: "show me one concrete thing that works, fast."

| Time | Keystroke / output | What the viewer sees |
|---|---|---|
| 0:00 | `$ ` (empty prompt, 1 sec pause) | Clean terminal, establishes we're in a real shell |
| 0:01 | type `npx mythos-agent quick` slowly, press Enter | The one command they'll try |
| 0:02 | (output streams) | `🔐 mythos-agent quick — 10s security check\n` |
| 0:03 | (scanning progress) | `⠋ Scanning 47 files…` spinner for ~1 sec |
| 0:05 | **results header** | `🔐 Trust Score: 2.3/10 · 3C 8H 2M (842 ms)` |
| 0:07 | **3–4 findings list, colored** | `🔴 SQL Injection        src/api.ts:45\n🔴 JWT None Algorithm    src/auth.ts:78\n🔴 Hardcoded Secret      src/config.ts:12\n🟠 Missing Rate Limit    src/routes.ts:91` |
| 0:12 | **next-step hint in dim text** | `→ mythos-agent fix --severity critical --apply` |
| 0:14 | (1 sec pause on final frame) | Viewer reads the findings |
| 0:15 | FADE or loop | Back to 0:00 |

**If you want the 30-second version (more narrative):** extend by running `mythos-agent fix --severity critical --apply` as the second command. Shows the auto-fix feedback loop.

---

## What NOT to show

- ❌ **Loading a config file / wizard.** First impression killer. Zero-config run or it didn't happen.
- ❌ **API key prompts.** Use `quick` or `scan` (pattern-only mode works offline).
- ❌ **`hunt` command.** It's your most impressive command but it takes 30–90 seconds — too long for a loop. Save `hunt` for the blog post / YouTube deep-dive.
- ❌ **Stack traces or warnings.** Rehearse until the run is clean.
- ❌ **Your real file paths** (e.g., `/Users/zhijie/secret-project/…`). Record from a fixture directory.
- ❌ **Slow typing animations.** Keystroke-by-keystroke typing wastes precious seconds. Paste the command or use asciinema's typing-speed option to speed up input.

---

## Post-processing

### For GIF (ScreenToGif / Kap output)

- **Trim** leading/trailing dead frames to ≤1s each.
- **Frame rate:** 15 fps is plenty for terminal text. 24+ fps bloats filesize with no visual gain.
- **Color reduction:** 64 colors is enough for terminal output. Drop from 256 → 64 typically halves size.
- **Resize** to max 1200px wide for README.
- **Target:** under **3 MB**. GitHub's hard cap per image is 10 MB, but large GIFs feel slow.

### For SVG (asciinema + svg-term output)

- No post-processing needed if you captured at 80×24 with clean prompt.
- File will be 30–100 KB. Ships anywhere instantly.

---

## Where to save + how to embed

**Filename:**
- `assets/demo.gif` (if GIF)
- `assets/demo.svg` (if SVG from svg-term)

**README embed** (just below the Cerby banner):

```markdown
<p align="center">
  <img alt="mythos-agent — 10 second security check demo" src="assets/demo.gif" width="720">
</p>
```

For SVG, the same `<img>` tag works — GitHub renders SVG images inline. The SVG from svg-term is self-contained (no external font deps).

**Ship-list order (recommended top of README):**
1. Cerby banner (identity, already shipped)
2. Badges row (already there)
3. **Demo GIF/SVG** ← this new block
4. H1 + tagline + quick-start links (already there)

---

## Verification before launch

- [ ] GIF/SVG opens in browser at correct dimensions
- [ ] Filesize under 3 MB (GIF) or under 200 KB (SVG)
- [ ] Commands shown match current CLI (run them yourself to confirm)
- [ ] No personal paths, secrets, or stack traces visible
- [ ] Loops cleanly (GIF: last frame matches first)
- [ ] Renders inline in GitHub README preview before push
- [ ] Still readable at README's default rendering width (doesn't need horizontal scroll)
- [ ] Test on mobile: open your GitHub repo page on your phone, confirm the demo is readable

---

## Recording checklist (the actual 5-minute version)

1. `clear`; resize terminal to 80×24; Geist Mono 15pt; dark theme
2. `cd` into a pre-seeded fixtures directory
3. Warm up: `npx mythos-agent quick` once (not recorded)
4. Start asciinema: `asciinema rec demo.cast --idle-time-limit 1`
5. Type `npx mythos-agent quick`, press Enter, let finish
6. `Ctrl-D` to stop recording
7. Convert: `cat demo.cast | svg-term --out assets/demo.svg --window --no-cursor --width 80 --height 24`
8. Preview: open `assets/demo.svg` in a browser
9. If happy, add to README above H1
10. Commit as `docs(brand): add demo SVG to README hero`

If asciinema isn't working or you prefer GIF: use ScreenToGif on Windows, record the same flow, export as GIF ≤3 MB, save as `assets/demo.gif`, embed same way.
