# Voice for Voiceless: public indicator lists

Lists of spyware infrastructure that the free [Voice for Voiceless](https://github.com/qubix-wk)
spyware check downloads before each check. Released under CC0 (public domain), so anyone can
use them.

| File | What it holds |
|---|---|
| `sources.json` | Every extra list the app downloads (written daily by the watcher) |
| `lists/paragon-graphite-citizenlab.tsv` | Paragon Graphite, copied by hand from Citizen Lab's reports of 19 March 2025 and 12 June 2025 |
| `lists/citizenlab-reviewed.tsv` | Indicators from newer Citizen Lab reports, each approved by a person |
| `lists/withdrawals.tsv` | Indicators withdrawn from every list |

## How it stays up to date

Once a day, `.github/workflows/daily-watch.yml` runs `watcher/watch.py`:

1. **Citizen Lab** publishes indicators inside its reports, not as lists. The watcher reads
   each new report in Citizen Lab's research feed and drafts the "defanged" values
   (`example[.]com`) as candidates in a pull request, each with the sentence it came from and a
   warning when it looks doubtful. **A person reviews and merges it**; only then do the apps use
   them. A test on real reports (2026-10-29) showed that reading reports automatically would
   flag news sites and certificate labels and miss real servers, so the review isn't optional.
2. **Amnesty International**: every machine-readable list in AmnestyTech/investigations that
   MVT's index doesn't already include is added to `sources.json` automatically.

Lists from MVT's index, ECHAP, abuse.ch, Spamhaus and others are downloaded by the app directly
from their publishers.

## Reviewing a pull request

Keep a line only if the report says devices contact it: a spyware server, an infection link,
a spyware file. Delete certificate labels, ordinary websites where an ad appeared, examples,
and the researchers' own tools. Change `strong` to `lead` for anything that should only be
"worth a look". To withdraw something already published, add it to `lists/withdrawals.tsv`.

Indicators are facts published by The Citizen Lab and Amnesty International; credit goes to
them. This project is not affiliated with either.
