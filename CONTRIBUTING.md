# Contributing to OneLauncher/OneClient

Welcome!

Please read our [Code of Conduct] to keep our community approachable and respectable.

## New Contributor Guide

To familiarize yourself with the project, please read the [README]. Here are some resources to help you get started with open-source contributions:

- [Finding ways to contribute to open-source on GitHub]
- [Setting up Git]
- [GitHub flow]
- [Collaborating with pull requests]
- [The Rust Book]
- [The `cargo` CLI]

## Getting Started

### Issues

#### Creating a New Issue

If you come across an issue or have a feature request for OneLauncher/OneClient, please [search if a related issue has already been reported]. If no relevant issue exists, you can open a new issue using the appropriate [issue form].

#### Solving an Issue

To find an issue that interests you, you can browse through our [existing issues] and use the available `labels` to narrow down your search (See [Labels] for more information). As a general rule, if you find an issue you want to work on, you are welcome to open a PR with a fix.

### Making Changes

#### Making Changes Locally

This project is a pure Rust [`Cargo`] workspace (edition 2024). Make sure you have a
recent Rust toolchain (`rustc` **1.97+**) installed before proceeding - the easiest way
is via [rustup].

To make changes locally, follow these steps:

1. Clone the repository: `git clone https://github.com/Polyfrost/OneLauncher`
2. Navigate to the project directory: `cd OneLauncher`
3. Configure your system environment for OneLauncher/OneClient development:
   1. Install a Rust toolchain that supports edition 2024: `rustup toolchain install stable`
   2. Freya renders with [Skia]; on Linux you may also need system libraries such as a C
      compiler, `pkg-config`, and the usual GUI/graphics dev packages. See the
      [Freya setup guide] for platform-specific prerequisites.

### Running

The app crate is `oneclient_app`:

- `cargo run -p oneclient_app` - Runs the **OneClient** desktop application.
- `cargo build --release -p oneclient_app` - Builds an optimized release binary.

After you finish making your changes and committed them to your branch, run
`cargo fmt` and `cargo clippy` to fix style inconsistencies and catch lints.

### Testing the game protection

Games run in a sandbox and get a fake Minecraft token; the launcher swaps in
the real one only for requests it allows (`oneclient_broker`,
`oneclient_sandbox`). To check it:

- `cargo test -p oneclient_broker` - the token rules, the prompts, and a red
  team of attacks a hostile mod could make over the real pipes. The agent
  tests need Java 11+ (`java` on `PATH` or `ONECLIENT_TEST_JAVA`) and are
  skipped without it.
- What a sandboxed process can reach: `cargo test -p oneclient_sandbox --test escape`
  on Windows, `cargo test -p oneclient_sandbox --test escape_unix -- --nocapture --test-threads=1`
  on Linux and macOS (it prints which backend ran).
- A real game: `cargo run -p oneclient_core --example sandbox_launch -- 1.21.4`
  (add `fabric` for a modded one). It launches with an offline account,
  waits for the main menu, checks the running game from outside (on Linux),
  stops it like the stop button does, and exits with 1 if anything failed.
  The first run downloads Java and the game into `target/sandbox-launch`.
- In the app (`cargo run -p oneclient_app`), each instance has a **Security**
  tab: how well this system protects it, what the game did with the account,
  the rules for account changes, and shared folders.

On Linux the sandbox needs `bubblewrap`. Ubuntu 23.10 and later block it with
AppArmor by default, so games fall back to Landlock, which protects less, and
the Security tab says so.

### Packaging

Installers are built with [cargo-packager] (config in
`packages/oneclient_app/Cargo.toml` under `[package.metadata.packager]`):

- `cargo install cargo-packager --locked`
- `cargo build --release -p oneclient_app`
- `cargo packager --release -p oneclient_app --formats <nsis|app,dmg|deb,appimage>`

Releases are cut by dispatching the `OneClient Release Build` GitHub Actions
workflow. See the **Packaging / Releasing** section of the [README] for details
and per-OS prerequisites.

### Pull Request

Once you have finished making your changes, create a pull request (PR) to submit them.

- Fill out the template to help reviewers understand your changes and the purpose of your PR.
- If your change is user-facing, add a change file with `knope document-change`, or create `.changeset/<anything>.md` by hand:
  ```md
  ---
  default: patch
  ---

  # Fixed the thing players noticed
  ```
  Use `patch` for fixes, `minor` for features and `major` for breaking changes. The title becomes your line in the release notes. PRs without one fail the `Changeset Check` unless a maintainer labels them `no changeset`.
- If you are addressing an existing issue, don't forget to [link your PR to the issue].
- Enable the checkbox to [allow maintainer edits] so that the branch can be updated for merging.
- Once you submit your PR, a team member will review your proposal. They may ask questions or request additional information.
- You may be asked to make changes before the PR can be merged, either through [suggested changes] or pull request comments. You can apply suggested changes directly through the UI. For other changes, you can make them in your fork and commit them to your branch.
- As you update your PR and apply changes, [mark each conversation as resolved].
- If you run into any merge issues, refer to this [git tutorial] to help you resolve merge conflicts and other issues.

### Your PR is Merged!

Congratulations! 🎉🎉 Polyfrost thanks you for your contribution! ✨
Once your PR is merged, your changes will be included in the next release.

### Common Errors

#### macOS errors with Xcode command line tools

Build errors can occur when the Xcode command line tools are not installed or not in your `PATH`.

Run `xcode-select --install` in the terminal to install them. If they are already installed, ensure that macOS is updated to the latest version available.

### Credits

This CONTRIBUTING.md file was inspired by the [`github/docs` CONTRIBUTING.md] file, and we extend our gratitude to the original authors.

[cargo-packager]: https://github.com/crabnebula-dev/cargo-packager
[Skia]: https://skia.org/
[Freya setup guide]: https://book.freyaui.dev/setup.html
[`cargo`]: https://doc.rust-lang.org/cargo/getting-started/installation.html
[rustup]: https://rustup.rs/
[Labels]: https://github.com/Polyfrost/OneLauncher/labels
[The Rust Book]: https://doc.rust-lang.org/book/
[The `cargo` CLI]: https://doc.rust-lang.org/cargo/
[Collaborating with pull requests]: https://docs.github.com/en/github/collaborating-with-pull-requests
[GitHub flow]: https://docs.github.com/en/get-started/quickstart/github-flow
[Setting up Git]: https://docs.github.com/en/get-started/quickstart/set-up-git
[Finding ways to contribute to open-source on GitHub]: https://docs.github.com/en/get-started/exploring-projects-on-github/finding-ways-to-contribute-to-open-source-on-github
[Code of Conduct]: ./CODE_OF_CONDUCT.md
[README]: ./README.md
[search if a related issue has already been reported]: https://docs.github.com/en/github/searching-for-information-on-github/searching-on-github/searching-issues-and-pull-requests#search-by-the-title-body-or-comments
[issue form]: https://github.com/Polyfrost/OneLauncher/issues/new/choose
[existing issues]: https://github.com/Polyfrost/OneLauncher/issues
[`github/docs` CONTRIBUTING.md]: https://github.com/github/docs/blob/main/CONTRIBUTING.md
[link your PR to the issue]: https://docs.github.com/en/issues/tracking-your-work-with-issues/linking-a-pull-request-to-an-issue
[allow maintainer edits]: https://docs.github.com/en/github/collaborating-with-issues-and-pull-requests/allowing-changes-to-a-pull-request-branch-created-from-a-fork
[suggested changes]: https://docs.github.com/en/github/collaborating-with-issues-and-pull-requests/incorporating-feedback-in-your-pull-request
[mark each conversation as resolved]: https://docs.github.com/en/github/collaborating-with-issues-and-pull-requests/commenting-on-a-pull-request#resolving-conversations
[git tutorial]: https://lab.github.com/githubtraining/managing-merge-conflicts
