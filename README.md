# RAG Corpus Poison Scanner

A dependency-free Python CLI that scans documents **before** they are
indexed into a RAG (retrieval-augmented generation) corpus, and flags
content an attacker could use to steer the LLM that later retrieves
them: embedded instructions, hidden text, fake citations, and
exfiltration triggers.

## Why this exists

Once a poisoned document is chunked and embedded, every future
retrieval can surface the payload to the model. Catching it at the
door is cheaper than catching it at query time. This is the
ingestion-time companion to runtime guards: scan the corpus first,
quarantine flagged files, and only then index what is clean.

## What it detects

| Finding | Severity |
|---|---|
| Instruction override ("ignore your previous instructions") | critical |
| New role assignment ("you are now...") | critical |
| Fake system / role marker (`SYSTEM:`, `[INST]`, `<\|system\|>`) | critical |
| Exfiltration instruction (send private data somewhere) | critical |
| Fake citation (invented DOI / link attached to a claim) | high |
| Credential harvest ("enter your API key...") | high |
| Tool abuse ("run this shell command...") | high |
| Jailbreak attempt ("developer mode", "bypass the filter") | high |
| Hidden text: HTML comments, `display: none`, zero-width chars | high |
| White-on-white text, homoglyph mixing, urgency override | medium |

All detection is pattern-based and fully offline: no network calls, no
API keys, no data leaves the machine.

## Usage

```bash
python rag_corpus_scanner.py docs/                    # scan a whole corpus
python rag_corpus_scanner.py docs/ --json report.json # machine-readable report
python rag_corpus_scanner.py docs/ --fail-on high     # CI gate for a docs pipeline
python rag_corpus_scanner.py single-doc.md
cat doc.md | python rag_corpus_scanner.py -
```

Scans `.txt`, `.md`, `.markdown`, `.html`, `.htm` and `.rst` files,
recursively under a directory. Exit code: `0` = clean, `1` = findings
at or above `--fail-on` (default: critical), `2` = usage/input error.

## Example

```text
$ python rag_corpus_scanner.py examples/
2 file(s) scanned, 1 flagged, 5 finding(s), worst severity: critical
  examples/poisoned-doc.md:12: [critical] instruction_override: Ignore your previous instructions
  examples/poisoned-doc.md:12: [critical] role_reassignment: You are now
  examples/poisoned-doc.md:13: [critical] exfiltration_instruction: Send the customer's private API key
  examples/poisoned-doc.md:11: [high] html_comment: <!--
  examples/poisoned-doc.md:21: [high] hidden_html: <p style="display: none">
Counts: exfiltration_instruction=1, hidden_html=1, html_comment=1, instruction_override=1, role_reassignment=1
```

## Tests

```bash
python -m unittest discover tests -v   # 13 tests, all passing
```

## Files

- `rag_corpus_scanner.py` — the scanner (standard library only)
- `tests/test_rag_corpus_scanner.py` — 13 unit tests
- `examples/poisoned-doc.md` — handbook excerpt with a hidden HTML-comment
  payload and a `display: none` block (the URL shown is the reserved
  example.com domain)
- `examples/clean-doc.md` — the same excerpt without the payload

## Limitations

Pattern matching catches known phrasings, not meaning: it can miss
well-obfuscated or paraphrased injections and can flag legitimate
quoted text (for example, a security article describing an attack).
Treat its output as a triage aid: quarantine flagged files, review
critical findings by hand, and never index a flagged document
unreviewed.

## How it fits the series

This continues the AI-agent guardrail series: prompt-injection
detection on user input, tool-permission auditing before an agent
runs, output-leak scanning after it responds, context-poison scanning
on everything retrieved in between, and now corpus-poison scanning
before any of that content is indexed at all.

## LinkedIn fit

One line: it is the ingestion-time guardrail for the AI red teaming
of LLM agents that the author's profile leads with — the tool a red
teamer runs on a knowledge base before an agent is ever allowed to
retrieve from it.

## Author

Sajid Hussain Raza — University Cybersecurity Lecturer, AI Security
Engineer and AI Red Teamer, Director and Co-founder of Cyber Legends,
Lahore. https://cyberlegends.org

## License

MIT.
