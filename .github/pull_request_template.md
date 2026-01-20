# Pull Request

## ⚠️ IMPORTANT - READ BEFORE SUBMITTING

### Required Pre-Submission Checklist

- [ ] I have read the [CONTRIBUTING.md](../CONTRIBUTING.md) file
- [ ] I have created a GitHub issue for this change and linked it below
- [ ] I have forked the **`dev`** branch (NOT `master`)
- [ ] I understand that the `master` branch is ONLY updated when a new release is created
- [ ] I understand that pull requests to `master` will be **REJECTED**

### ⛔ Critical Information

**DO NOT submit a pull request directly to the `master` branch.** The master branch is only updated when a new release is created. No direct commits or merges are accepted to master - neither from the InterceptSuite team nor from contributors.

**All changes MUST be submitted to the `dev` branch**, which contains the latest code and commits.

**You MUST create a GitHub issue first** before submitting a pull request. This allows the InterceptSuite team to:
- Verify if the bug is already fixed in the development branch
- Confirm if a new feature is accepted and approved
- Avoid duplicate work

Pull requests without an associated issue will be rejected.

---

## Pull Request Details

### Type of Change
<!-- Select one -->
- [ ] Bug Fix
- [ ] New Feature
- [ ] Code Improvement/Refactoring
- [ ] Documentation Update
- [ ] Other (please describe):

### Related GitHub Issue
**Issue Link:** <!-- REQUIRED: Paste the link to your GitHub issue here -->
<!-- Example: https://github.com/InterceptSuite/ProxyBridge/issues/123 -->

### Platform(s) Affected
<!-- Check all that apply -->
- [ ] Windows
- [ ] macOS
- [ ] Linux
- [ ] Cross-platform/All

---

## macOS Application Changes

### Does this pull request include changes to the macOS application?
- [ ] Yes
- [ ] No

**If YES, you MUST answer the following:**

### macOS Code Signing & Verification
<!-- macOS applications require a valid signature to run. You must verify your changes work. -->

- [ ] I have signed the macOS app with a valid Apple Developer account
- [ ] I have run the signed application on macOS to verify my changes work as expected
- [ ] I confirm the application launches and functions correctly with my changes

**⚠️ Important:** If you cannot sign the macOS app to verify your code changes work, please DO NOT submit this pull request. Instead, use the GitHub issue you created to let the InterceptSuite team fix the bug or add the feature. You will need to wait for the next release.

---

## Description of Changes

### What does this pull request do?
<!-- Provide a clear and detailed description of your changes -->


### How has this been tested?
<!-- Describe the tests you ran to verify your changes -->
- Test environment (OS, version, etc.):
- Test steps:
- Test results:


### Compilation & Dependencies
- [ ] I have reviewed the [CONTRIBUTING.md](../CONTRIBUTING.md) file for compilation instructions
- [ ] I have verified all required libraries and packages are documented
- [ ] My changes compile without errors
- [ ] My changes do not introduce new dependencies (or I have documented them below)

**New dependencies (if any):**
<!-- List any new libraries, packages, or system requirements -->


---

## Screenshots/Logs (if applicable)
<!-- Add screenshots, error logs, or other supporting materials -->


---

## Additional Context
<!-- Add any other context about the pull request here -->


---

## Final Checklist

- [ ] My code follows the project's coding style
- [ ] I have commented my code, particularly in hard-to-understand areas
- [ ] I have updated documentation as needed
- [ ] My changes do not generate new warnings or errors
- [ ] I have tested my changes on the target platform(s)
- [ ] I have verified this change is based on the latest `dev` branch
- [ ] I understand that pull requests without an associated GitHub issue will be rejected
