#!/usr/bin/env python3
"""Writes the Antidote launch video as a Capturita Studio project (scenes only; no recording).
Open Capturita, find "Antidote launch ..." in your library, and edit it in the Studio preview.
Re-run to get a fresh copy; each run makes a new project and never touches existing ones.
Needs a Capturita build with Studio (Pro) enabled."""
import json, pathlib, random, string, datetime, shutil

ROOT = pathlib.Path.home() / "Movies" / "Capturita"
KIT = dict(  # the app's "hazard placard" look: cool off-white ground, ink text, DANGER red as the accent
    id="antidote3", name="Antidote placard",
    colors=dict(bg="#eceeed", surface="#ffffff", text="#0b0b0c", muted="#41454a", accent="#e4202c"),
    fonts=dict(display="barlow-condensed", body="barlow"), background="gradient")  # needs a Capturita build with the Barlow fonts

def s(scene, props, duration):
    return dict(kind="scene", id="".join(random.choices(string.ascii_lowercase + string.digits, k=8)), scene=scene,
                props=props, duration=duration, transition=dict(type="crossfade", duration=0.5))
lines = lambda *t: [dict(text=x) for x in t]

HERE = pathlib.Path(__file__).resolve().parent
# Numbers come from the corpus on disk, so the video is right whenever it is regenerated.
_entries = [json.loads(f.read_text()) for f in (HERE.parent / "corpus" / "entries").glob("*.json")]
ENTRIES = len(_entries)
_cls = lambda e: (e.get("database_specific") or {}).get("classification")
MALICIOUS = sum(_cls(e) == "malicious" for e in _entries)
VULNERABLE = sum(_cls(e) == "vulnerable" for e in _entries)
INCIDENTS = ENTRIES - MALICIOUS - VULNERABLE
CLI = """$ antidote check npm:claude-all-config@3.8.3

[ ● DANGER  ] critical AGT-2026-0209
  Malicious code in claude-all-config (npm)
  fix:      Remove it

1 finding(s): 1 critical. Do not install or run this."""
shot = lambda name: f"images/{name}.png"  # copied into the project below

SCENES = [
    # 1 hook: the problem
    s("NetworkField", dict(heading="Every agent tool is a stranger's code", subtitle="Skills. MCP servers. Prompts. Packages.", density=36), 4),
    s("KineticStatement", dict(lines=lines("You install it.", "Your agent trusts it.", "Then it phones home."), emphasis="phones home", style="punch"), 4.5),
    s("CodeTyping", dict(heading="One line in a config", fileName=".mcp.json", speed=40,
        code='{\n  "mcpServers": {\n    "helper": {\n      "command": "npx",\n      "args": ["-y", "claude-all-config"]\n    }\n  }\n}'), 5.5),
    # 2 the answer
    s("LogoSting", dict(style="pop", wordmark="Antidote", tagline="Is this agent tool safe to install?", burst=True), 3.5),
    s("ScreenshotShowcase", dict(image=shot("home"), device="browser", placement="side", headline="Look it up. Get a verdict.",
        detail="Type a package, skill or CVE. The worst match comes first, with one instruction.", url="aryan2621.github.io/antidote",
        scroll=False, cursor=False, zoom=False, focusX=50, focusY=40), 6),
    s("CursorDemo", dict(title="Look it up first", typed="claude-all-config", button="Check", result="DANGER: known malicious package"), 5),
    s("CodeTyping", dict(heading="Or ask from your terminal", fileName="terminal", code=CLI, speed=55), 6),
    # 3 how it reads
    s("FeatureGrid", dict(heading="Four signals. Never colour alone.", items=[
        dict(icon="shield", title="DANGER", text="Malicious, or critical. Do not run it."),
        dict(icon="zap", title="WARNING", text="A real bug in honest software. Update it."),
        dict(icon="sparkles", title="CAUTION", text="Looks wrong, not confirmed. Review it."),
        dict(icon="layers", title="NOTICE", text="An incident. Read the report."),
    ]), 5.5),
    s("ScreenshotShowcase", dict(image=shot("entry"), device="browser", placement="center", headline="Every verdict shows its evidence",
        detail="Sources, affected versions and the scanner rules that catch it.", url="aryan2621.github.io/antidote/entry/AGT-2026-0209",
        scroll=False, cursor=False, zoom=False, focusX=50, focusY=30), 5.5),
    # 4 protection
    s("Notifications", dict(heading="antidote guard, in front of your servers", items=[
        dict(title="Hidden instructions", text="A poisoned tool description is hidden before your agent sees it."),
        dict(title="Rug pull", text="A tool that changed since first use is blocked."),
        dict(title="Bad package", text="A known-malicious server is flagged before it runs."),
    ]), 5.5),
    s("Comparison", dict(heading="Why not just trust the README?", us="Antidote", them="Install and hope", rows=[
        dict(feature="Checks before you run it", us="yes", them="no"),
        dict(feature="Works offline", us="yes", them="no"),
        dict(feature="Tells you the fix", us="yes", them="no"),
    ]), 5),
    s("FeatureOrbit", dict(heading="One database. Every surface.", features=lines("Website", "Command line", "Desktop app", "VS Code", "GitHub Action", "GitLab CI")), 5),
    # 5 proof, honesty, roadmap
    s("Chart", dict(heading=f"{ENTRIES} entries in the open database", kind="bars", unit="", points=[
        dict(label="Malicious", value=MALICIOUS), dict(label="Vulnerable", value=VULNERABLE), dict(label="Incidents", value=INCIDENTS)]), 5),
    s("KineticStatement", dict(lines=lines("Not listed is not safe.", "It only means nobody has reported it yet."), emphasis="not safe", style="punch"), 4.5),
    s("Roadmap", dict(heading="Where it is going", milestones=[
        dict(when="Today", title="CLI, desktop app, VS Code", status="done"),
        dict(when="Now", title="Bigger database, more rules", status="now"),
        dict(when="Next", title="Hosted API and badges", status="next"),
        dict(when="Later", title="Reporter sign-in", status="next"),
    ]), 5),
    # 6 close
    s("TextAnimation", dict(text="Free. Open source. Works offline.", style="words", size="l", position="center", color=""), 3.2),
    s("EndCard", dict(headline="Check before you install.", cta="Get Antidote", url="github.com/aryan2621/antidote", showQr=True, socials=[]), 5.5),
]

now = datetime.datetime.now()
pid = now.strftime("Antidote launch %Y-%m-%d at %H.%M.%S")
d = ROOT / pid
d.mkdir(parents=True)

# the brand kit is app-wide; add it once, keeping a backup of the file
kits_file = ROOT / "Brand" / "kits.json"
kits = json.loads(kits_file.read_text()) if kits_file.exists() else []
if kits_file.exists():
    shutil.copy(kits_file, kits_file.with_suffix(".json.antidote-bak"))
kits_file.parent.mkdir(exist_ok=True)
kits_file.write_text(json.dumps([k for k in kits if k.get("id") not in ("antidote1", "antidote2", KIT["id"])] + [KIT], indent=2))

(d / "images").mkdir()
for f in (HERE / "shots").glob("*.png"):
    shutil.copy(f, d / "images" / f.name)

total = sum(i["duration"] for i in SCENES)
(d / "project.json").write_text(json.dumps(dict(
    version=1, kind="studio", id=pid, createdAt=now.astimezone(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"), duration=0,
    source=dict(type="display", name="Studio video", area=dict(x=0, y=0, width=1920, height=1080)),
    tracks=dict(screen=dict(file="", offset=0, duration=0, width=1920, height=1080), systemAudio=None, microphone=None, camera=None, cursor=dict(file=""))), indent=2))

# edit.json: start from any existing project's, so every field the app expects is present, then empty the lists
src = next((p / "edit.json" for p in sorted(ROOT.iterdir()) if (p / "edit.json").exists() and p != d), None)
edit = json.loads(src.read_text()) if src else {}
edit = {k: ([] if isinstance(v, list) else v) for k, v in edit.items()}
edit.update(version=2, aspect="16:9", items=SCENES, brandKit=KIT["id"], background=dict(type="color", color=KIT["colors"]["bg"]))
(d / "edit.json").write_text(json.dumps(edit, indent=2))
print(f"{pid}: {len(SCENES)} scenes, about {total - 0.5 * (len(SCENES) - 1):.0f}s")
