//! # `phylax` Standalone Leaked Credential Bloom Filter Example
//! Demonstrates sub-microsecond in-memory password breach validation and account velocity defense.
//!
//! Run with: `cargo run --example standalone_bloom`

use phylax::prelude::*;
use std::time::Instant;

fn main() {
    println!("🛡️ Phylax Leaked Credential & Account Velocity Demonstration");
    println!("------------------------------------------------------------");

    let guard = CredentialGuard::default();

    // 1. In-Memory Breached Password Validation (<25ns)
    let candidate_passwords = [
        "123456",
        "password",
        "admin123",
        "hunter2",
        "MySuper#Secret!Password_2026_Unique",
        "Phylax!SovereignEdge999",
    ];

    println!("\n🔍 Testing Password Quality against in-memory 8KB Bloom Filter:");
    for pwd in candidate_passwords {
        let start = Instant::now();
        let verdict = guard.check_password_quality(pwd);
        let elapsed = start.elapsed();

        if verdict.is_clean() {
            println!("  ✅ [ALLOWED] {:<38} (evaluated in {:?})", pwd, elapsed);
        } else {
            println!(
                "  ❌ [BLOCKED] {:<38} (evaluated in {:?}) -> {}",
                pwd,
                elapsed,
                verdict.public_message()
            );
        }
    }

    // 2. Distributed Brute-Force Account Velocity Lockout
    let target_account = "victim_operator@example.com";
    let now = 1_700_000_000_000;

    println!(
        "\n🎯 Simulating distributed brute-force attacks on '{}':",
        target_account
    );
    for i in 1..=6 {
        guard.record_failure(target_account, now + i * 1000);
        let verdict = guard.check_account_velocity(target_account, now + i * 1000 + 500);
        match verdict {
            phylax::CredentialVerdict::Clean => {
                println!("  Attempt {}: Recorded failure (Account status: Normal)", i);
            }
            phylax::CredentialVerdict::PoWRequirementElevated {
                required_difficulty,
            } => {
                println!(
                    "  Attempt {}: ⚠️ Elevated PoW demanded (difficulty: {} bits)",
                    i, required_difficulty
                );
            }
            phylax::CredentialVerdict::TargetAccountThrottled {
                cooloff_remaining_s,
                ..
            } => {
                println!(
                    "  Attempt {}: 🔒 ACCOUNT LOCKED IN COOLDOWN ({}s remaining)",
                    i, cooloff_remaining_s
                );
            }
            _ => {}
        }
    }

    println!("\n✨ Demo completed successfully!");
}
