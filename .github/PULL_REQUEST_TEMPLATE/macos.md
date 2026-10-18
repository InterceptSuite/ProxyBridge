<!--
Thank you for contributing to ProxyBridge! 🙌  Please read CONTRIBUTING.md first (it is short and explains why we ask for this).

Quick reminders:
  - This pull request must target the `dev` branch.
  - You must have commented on the linked issue BEFORE you started, and heard back from a maintainer.
  - Fill in each part below. An automatic check looks for the answers and will ask you for anything missing.
  - macOS template. Other platforms: add ?template=windows.md or ?template=linux.md to the address of this page.
-->

## Linked issue
Fixes #
<!-- type the issue number right after the #, for example: Fixes #123 -->

## What does this pull request do?
<!-- What changed and why, in a few sentences. -->

## macOS signing and testing
<!-- macOS changes are accepted only if YOU built, signed and ran the app. We can't sign or test it for you. See CONTRIBUTING.md. -->
- **macOS version and chip:** <!-- e.g. macOS 26.5, Apple M4 -->
- **Xcode version:** <!-- e.g. 26.6 -->
- **How you signed the app:** <!-- e.g. Developer ID with my own team and my own bundle IDs -->
- **Did the signed app run and behave correctly with your change?** <!-- what you saw, and the system extension approved? -->

## Tests
<!-- Write each answer after the question. The platform's automatic checks (CI) run on top of this, but we still need to know what YOU ran. -->
- **Did you run the tests locally? (which ones, on which system):** <!-- MacOS/tests/logic/run.sh and MacOS/tests/pbtest.py (the suites you ran) -->
- **Result or output (paste the last lines):** <!-- e.g. "22/22 passed" -->
- **Did anything fail? (what, and why):** <!-- "no", or what failed and why -->
- **New tests added (or "none"):** <!-- the files or test names -->
- **Tests removed or changed (or "none"):** <!-- and why -->

## Anything else? (optional)
<!-- New dependencies, screenshots or logs, anything a reviewer should know. -->

---
By opening this pull request I confirm that it targets `dev`, that I commented on the linked issue before starting, and that I ran the tests listed above.
