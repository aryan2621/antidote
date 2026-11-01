#!/usr/bin/env python3
"""Writes the Antidote launch video as a Capturita Studio project (scenes only; no recording).
Open Capturita, find "Antidote launch ..." in your library, and edit it in the Studio preview.
Re-run to get a fresh copy; each run makes a new project and never touches existing ones.
Needs a Capturita build with Studio (Pro) enabled."""
import json, pathlib, random, string, datetime, shutil

ROOT = pathlib.Path.home() / "Movies" / "Capturita"
KIT = dict(  # "hazard placard": the website's palette, with the caution yellow as the accent
    id="antidote1", name="Antidote placard",
    colors=dict(bg="#0b0b0c", surface="#171718", text="#f1f1ed", muted="#a9adb0", accent="#ffd400"),
    fonts=dict(display="space-grotesk", body="inter"), background="grain")

def s(scene, props, duration):
    return dict(kind="scene", id="".join(random.choices(string.ascii_lowercase + string.digits, k=8)), scene=scene,
                props=props, duration=duration, transition=dict(type="crossfade", duration=0.5))
lines = lambda *t: [dict(text=x) for x in t]

HERE = pathlib.Path(__file__).resolve().parent
ENTRIES = len(list((HERE.parent / "corpus" / "entries").glob("*.json")))  # always today's count
CLI = """$ antidote check npm:claude-all-config@3.8.3

[ ● DANGER  ] critical AGT-2026-0209
  Malicious code in claude-all-config (npm)
  fix:      Remove it

1 finding(s): 1 critical. Do not install or run this."""
shot = lambda name: f"images/{name}.png"  # copied into the project below

SCENES = [
    s("LogoSting", dict(style="pop", wordmark="Antidote", tagline="Is this agent tool safe to install?", burst=True), 3.5),
    s("KineticStatement", dict(lines=lines("Your agent installs tools.", "Anyone can publish one.", "Some are poisoned."), emphasis="poisoned", style="punch"), 4.5),
    s("CodeTyping", dict(heading="It looks like any other MCP server", fileName=".mcp.json", speed=40,
        code='{\n  "mcpServers": {\n    "helper": {\n      "command": "npx",\n      "args": ["-y", "claude-all-config"]\n    }\n  }\n}'), 6),
    s("ScreenshotShowcase", dict(image=shot("home"), device="browser", placement="side", headline="Look it up. Get a verdict.",
        detail="Type a package, skill or CVE. The worst match comes first, with one instruction.", url="aryan2621.github.io/antidote",
        scroll=False, cursor=False, zoom=False, focusX=50, focusY=40), 6),
    s("CodeTyping", dict(heading="Or ask from your terminal", fileName="terminal", code=CLI, speed=55), 6),
    s("FeatureGrid", dict(heading="Four signals. Never colour alone.", items=[
        dict(icon="shield", title="DANGER", text="Malicious, or critical. Do not run it."),
        dict(icon="zap", title="WARNING", text="A real bug in honest software. Update it."),
        dict(icon="sparkles", title="CAUTION", text="Looks wrong, not confirmed. Review it."),
        dict(icon="layers", title="NOTICE", text="An incident. Read the report."),
    ]), 5.5),
    s("ScreenshotShowcase", dict(image=shot("entry"), device="browser", placement="center", headline="Every verdict shows its evidence",
        detail="Sources, affected versions and the scanner rules that catch it.", url="aryan2621.github.io/antidote/entry/AGT-2026-0209",
        scroll=False, cursor=False, zoom=False, focusX=50, focusY=30), 5.5),
    s("HowItWorks", dict(heading="Use it your way", steps=[
        dict(title="Scan", text="antidote scan checks your skills and MCP configs, fully offline."),
        dict(title="Guard", text="antidote guard hides poisoned tools and blocks rug pulls."),
        dict(title="Stay current", text="A signed feed keeps the database up to date."),
    ]), 6),
    s("Integrations", dict(center="Antidote", items=lines("Claude Code", "Claude Desktop", "Cursor", "VS Code", "GitHub Actions", "GitLab CI")), 5),
    s("KineticStatement", dict(lines=lines("Not listed is not safe.", "It only means nobody has reported it yet."), emphasis="not safe", style="punch"), 4.5),
    s("BigNumber", dict(value=str(ENTRIES), label="malicious and vulnerable agent artifacts, in an open database", glow=True), 4),
    s("EndCard", dict(headline="Check before you install.", cta="Get Antidote", url="github.com/aryan2621/antidote", showQr=False, socials=[]), 5),
]

now = datetime.datetime.now()
pid = now.strftime("Antidote launch %Y-%m-%d at %H.%M.%S")
d = ROOT / pid
d.mkdir(parents=True)

# the brand kit is app-wide; add it once, keeping a backup of the file
kits_file = ROOT / "Brand" / "kits.json"
kits = json.loads(kits_file.read_text()) if kits_file.exists() else []
if not any(k.get("id") == KIT["id"] for k in kits):
    if kits_file.exists():
        shutil.copy(kits_file, kits_file.with_suffix(".json.antidote-bak"))
    kits_file.parent.mkdir(exist_ok=True)
    kits_file.write_text(json.dumps(kits + [KIT], indent=2))

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
