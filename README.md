<div align="center">

# 🔥 LOG ANALYZER 🔥

### *Your server is screaming. This tool speaks fluent scream.*

![python](https://img.shields.io/badge/python-3.x-blue?style=for-the-badge&logo=python&logoColor=white)
![memory](https://img.shields.io/badge/RAM%20usage-basically%20none-brightgreen?style=for-the-badge)
![500s](https://img.shields.io/badge/500%20errors-HUNTED-red?style=for-the-badge)
![vibes](https://img.shields.io/badge/vibes-immaculate-ff69b4?style=for-the-badge)

**Streams gigabytes of logs. One line at a time. Like a calm ninja eating spaghetti, one noodle at a time.** 🍝🥷

</div>

---

## 💀 THE PROBLEM

It's 3:47 AM. Production is on fire. Someone pastes a **14 GB** `access.log` into Slack and says *"can you take a look?"*

You open it in your editor. Your editor dies. Your laptop fan achieves liftoff. Your cat leaves the room.

## ⚡ THE SOLUTION

**Log Analyzer** reads your logs **line by line**, like a speed-reading monk. It never loads the whole file into memory, so a 50 MB log and a multi-GB log cost you roughly the same amount of RAM: *a tiny, polite amount.*

No pandas. No cluster. No "let me just spin up Elasticsearch real quick." Just Python and pure rage-fueled efficiency.

---

## 🧨 SUPERPOWERS

| Power | What it does |
|---|---|
| 🌊 **Streaming mode** | Processes logs line by line → low memory usage, even at GB scale |
| 🔢 **Request counter** | Counts every single request. Every. Single. One. |
| 📊 **Status code tracker** | Tallies your 200s, 404s, 500s and whatever else your server is feeling today |
| 👑 **Top 5 IPs** | Exposes the five most obsessed visitors (bots, fans, or enemies) |
| 💥 **Max consecutive 500s** | Finds your longest unbroken streak of server-side meltdown. A personal best nobody wants. |
| 📁 **CSV export** | Dumps the summary into `analysis_output.csv` so you can impress your manager with a spreadsheet |
| 🧾 **Apache / Nginx compatible** | Eats both log formats for breakfast |

---

## 🚀 LAUNCH SEQUENCE

### 1. Clone the beast
```bash
git clone https://github.com/chaouchmohamed/log-analyzer.git
cd log-analyzer
```

### 2. Arm the dependencies
```bash
pip install -r requirements.txt
```

### 3. FIRE
```bash
python analyzer.py logs/sample.log
```

Point it at your own log instead of the sample, and watch it chew:

```bash
python analyzer.py /var/log/nginx/access.log
```

When it's done, check **`analysis_output.csv`** for the full damage report. 📄💣

---

## 🧠 HOW IT WORKS (THE BIG BRAIN SECTION)

```
   📜 giant.log (14 GB of pain)
        │
        ▼
   ┌─────────────────┐
   │  read 1 line    │◄──────┐
   └────────┬────────┘       │
            ▼                │
   ┌─────────────────┐       │
   │ parse + update  │       │  repeat until
   │ counters        │       │  the file ends
   └────────┬────────┘       │
            │────────────────┘
            ▼
   ┌─────────────────┐
   │  📁 CSV report  │
   └─────────────────┘
```

Memory stays flat because nothing piles up except a few counters. No giant lists. No "load it all and pray." Just vibes and dictionaries. 🧙‍♂️

---

## 🔍 WHAT YOU GET

After a run, you'll know:

- 📈 **How many requests** hit your server
- 🎨 **Which status codes** showed up (and how often)
- 🕵️ **Which 5 IPs** are hogging the spotlight
- 🚨 **The longest streak of consecutive 500 errors**, aka *how long your server stayed face-down on the floor*

All saved to `analysis_output.csv`.

---

## 🗂️ REPO TOUR

```
log-analyzer/
├── 🐍 analyzer.py          # the engine. the machine. the legend.
├── 📁 logs/                # sample logs to play with
├── 🖼️ images/              # screenshots & shiny things
├── 📊 analysis_output.csv  # where the results land
├── 📦 requirements.txt     # dependencies
└── 📖 README.md            # you are here, hello 👋
```

---

## 🤔 FAQ

**Q: Will it handle my 20 GB log?**
A: It's built for GB-scale logs, since it streams instead of loading the whole file. Go wild.

**Q: Does it work with Nginx?**
A: Yes. And Apache. It's not picky.

**Q: Why so many emojis?**
A: Because staring at logs is already depressing enough.

**Q: Can it fix my 500 errors?**
A: No. It can only tell you *exactly how bad things got.* Healing is a you problem. 🩹

---

## 🛣️ FUTURE CHAOS (IDEAS)

- ⏱️ Time-window analysis for error spikes
- 🌍 GeoIP lookup for those top offenders
- 📉 Charts, because everyone loves charts
- 🤖 Slack alerts when the 500s go feral

PRs welcome. Bring snacks.

---

## 🤝 CONTRIBUTING

Found a bug? Open an issue. Got a cool idea? Open a PR. Got a 40 GB log that breaks it? **Please send it. We want to see.** 😈

---

<div align="center">

### Made with ☕, 🐍, and a deep distrust of `cat huge.log`

**If this saved you from a 3 AM disaster, drop a ⭐. It costs nothing and feeds the developer's ego.**

</div>
