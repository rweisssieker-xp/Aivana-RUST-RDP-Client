# Development verification — September 14, 2026

Scope: US-English product migration, production delivery tooling, Stripe account integration, recorded application checks, ticket intake and authorized escalation, and logged-out recovery tooling. This is development evidence, not a sales or live-operation approval.

## Reproducible checks

Use the pinned Rust toolchain and the lockfile. Run `cargo test --offline --bins -- --test-threads=1` and `cargo build --offline --bins` from the repository root. Both binaries build; compiler warnings remain. The final complete Rust run passed: desktop **512 passed, zero failed, five ignored**; team server **46 passed, zero failed**. This totals **558 passed tests**. Ignored tests are not acceptance evidence.

Isolated PowerShell checks were rerun successfully:

| Script | Passed checks |
| --- | ---: |
| `scripts/distribution/Test-Production.ps1` | 27 |
| `scripts/distribution/Test-UpdateTask.ps1` | 17 |
| `scripts/distribution/Test-Restore.ps1` | 20 |
| `scripts/background/Test-Background.ps1` | 18 |
| `scripts/acceptance/Test-Acceptance.ps1` | 7 |

These 89 checks use temporary fixtures and mocked signature/scheduler boundaries. They do not sign packages, register real tasks, charge payments, deliver tickets, or restore user data.

The English literal audit (`python scripts/audit-english.py`) returned 56 candidates. Inspection identified retained multilingual catalogs and lookup keys, legacy status matching, and recommendation stopwords. Native release and ticket views were captured using isolated APPDATA/LOCALAPPDATA directories and inspected. This is representative visual verification, not an exhaustive review of every runtime state. User-authored data, operating-system messages, and historical engineering documents retain their original language.

An earlier complete Rust run had 509 passes, one HTTP/service fixture failure, and five ignored tests. The failing test passed on an isolated rerun (one pass, 516 filtered out) and in the final complete run. The transient failure is retained here rather than omitted from the evidence; its root cause was not established. No assertion was weakened to obtain the final pass.

Local logs: `C:\temp\relayne-completion-verified-tests.log`, `C:\temp\relayne-completion-verified-build.log`, `C:\temp\relayne-http-fixture-recheck.log`, and `C:\temp\relayne-restore-final.log`. Screenshots are under `C:\temp\relayne-completion-visual`. These machine-local artifacts are not distributed as live acceptance evidence.

After the final English registration-label adjustment, `release_view_renders_in_all_locales` passed again (one test). Documentation links resolve locally. The staged whitespace check passes outside the third-party inventory; original dependency license texts intentionally preserve upstream whitespace.

## External requirements

- Publisher certificate, trusted release endpoint, signing pipeline, and Windows trust/update acceptance.
- Stripe credentials, webhook endpoint, approved recurring Price and inclusive/exclusive tax treatment, Customer Portal configuration, and actual Stripe test-mode acceptance. Stripe is selected; EUR 9.99 net versus gross remains undecided.
- Product-specific legal/privacy approval, binding support terms, and resolution of 29 dependency declaration/license-text review entries in the 483-package inventory.
- Real RDP, Gateway, WinRM, Hyper-V, multi-monitor, provider, and logged-out task acceptance in supported customer environments.

The development application remains usable. Subscription evidence does not turn the development build into a commercially licensed release. Sales readiness remains false until the external requirements have evidence.
