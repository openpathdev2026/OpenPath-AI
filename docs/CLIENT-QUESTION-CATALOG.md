# OpenPath-AI — Client Question Catalog

This is the **contract**: the fixed set of questions OpenPath answers. It is
generated from `openpath/catalog.py` (the single source of truth in code).
Adding, removing, or rephrasing a question is a deliberate change made there.

For every question, OpenPath either backs the answer with cited raw evidence
(soundness) or discloses what it could not determine and why (disclosure). It
never invents activity.

| # | Question | Facet | Certified |
|---|----------|-------|-----------|
| Q01 | What did USER do during the last 24 hours? | `core` | ✅ |
| Q02 | When did USER log in during the last 24 hours? | `login` | ✅ |
| Q03 | Where did USER log in from? | `login` | ✅ |
| Q04 | What sessions did USER have during the last 24 hours? | `sessions` | ✅ |
| Q05 | Did USER become root during the last 24 hours? | `privilege` | ✅ |
| Q06 | What did USER do as root during the last 24 hours? | `root_activity` | ✅ |
| Q07 | What commands did USER run during the last 24 hours? | `commands` | ✅ |
| Q08 | What files did USER modify during the last 24 hours? | `files` | ✅ |
| Q09 | What accounts did USER create or modify during the last 24 hours? | `accounts` | ✅ |
| Q10 | What groups did USER create or modify during the last 24 hours? | `groups` | ✅ |
| Q11 | What packages did USER install or remove during the last 24 hours? | `packages` | ✅ |
| Q12 | What network activity did USER perform during the last 24 hours? | `network` | ✅ |
| Q13 | What did USER do before and after the incident? | `timeline` | ✅ |
| Q14 | What evidence supports what USER did during the last 24 hours? | `evidence` | ✅ |
| Q15 | What could OpenPath not determine about USER during the last 24 hours? | `gaps` | ✅ |

*Certified* = a conformance test asserts a correct, cited, gap-disclosing answer.

One facet may serve more than one question (e.g. `login` answers both Q02 "when"
and Q03 "where"). Q13 is the timeline pivoted around an event (`--around <ts>`).
