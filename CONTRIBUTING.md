# Contributing to Phylax

Thank you for your interest in improving Phylax! We welcome contributions from engineers, researchers, and security practitioners.

## Core Architectural Principles

All contributions to Phylax adhere to two core tenets:

1. **One-Job-Pattern (OJP):**
   - Each module and guard is isolated, purpose-built, and focused entirely on a single security responsibility.
   - Zero structural overlap or redundant abstraction.
   - Fail-fast perimeter architecture with sub-microsecond zero-heap latency.

2. **Test-Driven Development (TDD):**
   - No features or fixes are merged without corresponding unit and integration tests.
   - Real-world simulation and attack vector coverage are mandatory.

## Development Workflow

### Prerequisites
- Rust stable (1.75+)
- Cargo

### Building & Testing
Run the complete test matrix before opening a PR:

```bash
# 1. Format code according to rustfmt guidelines
cargo fmt --check

# 2. Run Clippy across all targets and features
cargo clippy --all-targets --all-features -- -D warnings

# 3. Execute all unit and integration tests
cargo test --all-targets --all-features

# 4. Verify examples compile
cargo check --example axum_edge_defense
cargo check --example standalone_bloom
```

### Pull Request Guidelines
- Branch from `main`.
- Keep PRs focused on a single change or fix.
- Ensure all CI checks pass.
- Maintain zero-telemetry sovereignty: never introduce external telemetry pings or analytics tracking.
