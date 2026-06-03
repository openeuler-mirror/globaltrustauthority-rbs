/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2026. All rights reserved.
 * Global Trust Authority Resource Broker Service is licensed under the Mulan PSL v2.
 * You can use this software according to the terms and conditions of the Mulan PSL v2.
 * You may obtain a copy of Mulan PSL v2 at:
 *     http://license.coscl.org.cn/MulanPSL2
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
 * PURPOSE.
 * See the Mulan PSL v2 for more details.
 */

//! Account lockout tracker for bearer token authentication failures.
//!
//! Tracks consecutive authentication failures per user (`sub`) and locks
//! the account when the threshold is reached. Lockout state is stored
//! in memory using a concurrent map (`DashMap`).

use std::sync::Arc;
use std::time::{Duration, Instant};

use dashmap::DashMap;
use log::warn;

/// Maximum consecutive failed authentication attempts before lockout.
const MAX_FAILED_ATTEMPTS: u32 = 5;

/// Duration of account lockout after reaching the failure threshold.
const LOCK_DURATION: Duration = Duration::from_secs(5 * 60); // 5 minutes

/// TTL for failure counter entries. If no new failures occur within this
/// period, the counter is automatically removed (reset to zero).
const COUNTER_TTL: Duration = Duration::from_secs(30 * 60); // 30 minutes

/// Entry tracking failed authentication attempts for a single user.
struct LockoutEntry {
    /// Number of consecutive failed attempts.
    failed_count: u32,
    /// Timestamp of the most recent failure (used for TTL expiry and
    /// lockout duration calculation).
    last_failed_at: Instant,
}

/// Thread-safe tracker for authentication failure lockouts.
///
/// Uses `DashMap` for concurrent access across multiple Actix workers.
/// All workers share the same `Arc<LockoutTracker>` instance so that
/// failure counts are accurate regardless of which worker handles the request.
pub struct LockoutTracker {
    entries: DashMap<String, LockoutEntry>,
}

impl LockoutTracker {
    /// Create a new empty `LockoutTracker`.
    pub fn new() -> Self {
        Self {
            entries: DashMap::new(),
        }
    }

    /// Create a new `Arc<LockoutTracker>` for shared use across workers.
    pub fn new_shared() -> Arc<Self> {
        Arc::new(Self::new())
    }

    /// Check whether the given user (`sub`) is currently locked out.
    ///
    /// Returns `true` if the user has reached the maximum failure threshold
    /// and the lockout period has not yet expired. A locked-out user must
    /// wait for the lockout duration to pass, and then provide a successful
    /// authentication to reset the counter — the counter is **not** cleared
    /// when the lockout expires.
    pub fn is_locked(&self, sub: &str) -> bool {
        if let Some(entry) = self.entries.get(sub) {
            if entry.failed_count >= MAX_FAILED_ATTEMPTS {
                let elapsed = entry.last_failed_at.elapsed();
                return elapsed < LOCK_DURATION;
            }
        }
        false
    }

    /// Record a failed authentication attempt for the given user.
    ///
    /// Increments the failure counter. If the counter reaches the threshold,
    /// the account is considered locked (the next `is_locked()` call will
    /// return `true`).
    pub fn record_failure(&self, sub: &str) {
        self.entries
            .entry(sub.to_string())
            .and_modify(|entry| {
                entry.failed_count += 1;
                entry.last_failed_at = Instant::now();
            })
            .or_insert(LockoutEntry {
                failed_count: 1,
                last_failed_at: Instant::now(),
            });

        if let Some(entry) = self.entries.get(sub) {
            if entry.failed_count >= MAX_FAILED_ATTEMPTS {
                warn!(
                    "Account locked for user '{}' after {} consecutive authentication failures",
                    sub, entry.failed_count
                );
            }
        }
    }

    /// Record a successful authentication for the given user.
    ///
    /// A successful authentication resets the failure counter to zero,
    /// removing the entry entirely. This implements the "success clears
    /// the counter" policy.
    pub fn record_success(&self, sub: &str) {
        if self.entries.remove(sub).is_some() {
            log::info!(
                "Authentication success cleared lockout counter for user '{}'",
                sub
            );
        }
    }

    /// Returns the current failure count for a user, or 0 if no entry exists.
    ///
    /// Primarily useful in tests to verify that failure counting works correctly.
    pub fn get_failed_count(&self, sub: &str) -> u32 {
        self.entries
            .get(sub)
            .map(|e| e.failed_count)
            .unwrap_or(0)
    }

    /// Returns the number of active entries in the tracker.
    ///
    /// Primarily useful in tests to verify cleanup behaviour.
    pub fn active_count(&self) -> usize {
        self.entries.len()
    }

    /// Returns true if a tracker entry exists for the given sub.
    ///
    /// Primarily useful in tests to verify that non-existent subs do not
    /// get entries created.
    pub fn has_entry(&self, sub: &str) -> bool {
        self.entries.contains_key(sub)
    }

    /// Remove expired counter entries.
    ///
    /// Entries whose `last_failed_at` is older than `COUNTER_TTL` are
    /// removed, effectively resetting their failure count to zero. This
    /// should be called periodically (e.g., every 60 seconds) to reclaim
    /// memory and allow stale counters to decay.
    pub fn cleanup_expired(&self) {
        let now = Instant::now();
        self.entries.retain(|sub, entry| {
            let age = now.duration_since(entry.last_failed_at);
            if age > COUNTER_TTL {
                log::debug!(
                    "Expired lockout counter removed for user '{}' (age: {}s, failures: {})",
                    sub,
                    age.as_secs(),
                    entry.failed_count
                );
                false // remove
            } else {
                true // keep
            }
        });
    }
}

impl std::fmt::Debug for LockoutTracker {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LockoutTracker")
            .field("active_entries", &self.entries.len())
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_new_tracker_is_empty() {
        let tracker = LockoutTracker::new();
        assert!(!tracker.is_locked("any_user"));
        assert_eq!(tracker.entries.len(), 0);
    }

    #[test]
    fn test_single_failure_does_not_lock() {
        let tracker = LockoutTracker::new();
        tracker.record_failure("user1");
        assert!(!tracker.is_locked("user1"));
        let entry = tracker.entries.get("user1").unwrap();
        assert_eq!(entry.failed_count, 1);
    }

    #[test]
    fn test_five_failures_triggers_lockout() {
        let tracker = LockoutTracker::new();
        for _ in 0..5 {
            tracker.record_failure("user1");
        }
        assert!(tracker.is_locked("user1"));
    }

    #[test]
    fn test_success_clears_counter() {
        let tracker = LockoutTracker::new();
        for _ in 0..4 {
            tracker.record_failure("user1");
        }
        assert!(!tracker.is_locked("user1"));

        tracker.record_success("user1");
        assert!(!tracker.is_locked("user1"));
        assert!(tracker.entries.get("user1").is_none());
    }

    #[test]
    fn test_success_after_lockout_clears_counter() {
        let tracker = LockoutTracker::new();
        for _ in 0..5 {
            tracker.record_failure("user1");
        }
        assert!(tracker.is_locked("user1"));

        tracker.record_success("user1");
        assert!(!tracker.is_locked("user1"));
        assert!(tracker.entries.get("user1").is_none());
    }

    #[test]
    fn test_interleaved_success_resets_counter() {
        let tracker = LockoutTracker::new();
        // 3 failures
        for _ in 0..3 {
            tracker.record_failure("user1");
        }
        // 1 success resets
        tracker.record_success("user1");
        // 2 more failures (total consecutive = 2, not 5)
        for _ in 0..2 {
            tracker.record_failure("user1");
        }
        assert!(!tracker.is_locked("user1"));
    }

    #[test]
    fn test_different_users_tracked_separately() {
        let tracker = LockoutTracker::new();
        for _ in 0..5 {
            tracker.record_failure("user_a");
        }
        tracker.record_failure("user_b");

        assert!(tracker.is_locked("user_a"));
        assert!(!tracker.is_locked("user_b"));
    }

    #[test]
    fn test_nonexistent_user_not_locked() {
        let tracker = LockoutTracker::new();
        assert!(!tracker.is_locked("ghost_user"));
    }

    #[test]
    fn test_cleanup_removes_expired_entries() {
        let tracker = LockoutTracker::new();

        // Simulate an entry with a very old timestamp.
        // We can't set Instant directly, so we test cleanup logic
        // by manually inserting an entry with a past Instant.
        tracker.entries.insert(
            "stale_user".to_string(),
            LockoutEntry {
                failed_count: 3,
                last_failed_at: Instant::now() - COUNTER_TTL - Duration::from_secs(60),
            },
        );

        // Fresh entry should survive cleanup.
        tracker.record_failure("fresh_user");

        tracker.cleanup_expired();
        assert!(tracker.entries.get("stale_user").is_none());
        assert!(tracker.entries.get("fresh_user").is_some());
    }

    #[test]
    fn test_cleanup_keeps_recent_entries() {
        let tracker = LockoutTracker::new();
        tracker.record_failure("recent_user");

        tracker.cleanup_expired();
        assert!(tracker.entries.get("recent_user").is_some());
    }

    #[test]
    fn test_counter_preserved_after_lockout_expires_simulated() {
        let tracker = LockoutTracker::new();

        // Manually insert an entry that is locked but lockout has expired
        // (counter >= 5, but elapsed > LOCK_DURATION).
        tracker.entries.insert(
            "user_expired_lock".to_string(),
            LockoutEntry {
                failed_count: 5,
                last_failed_at: Instant::now() - LOCK_DURATION - Duration::from_secs(60),
            },
        );

        // Lockout has expired, so is_locked returns false.
        assert!(!tracker.is_locked("user_expired_lock"));

        // But the counter is still 5, so one more failure re-triggers lockout.
        tracker.record_failure("user_expired_lock");
        let entry = tracker.entries.get("user_expired_lock").unwrap();
        assert_eq!(entry.failed_count, 6);
        assert!(tracker.is_locked("user_expired_lock"));
    }

    #[test]
    fn test_shared_arc() {
        let tracker = LockoutTracker::new_shared();
        tracker.record_failure("user1");
        assert!(!tracker.is_locked("user1"));
        assert_eq!(tracker.entries.len(), 1);
    }

    #[test]
    fn test_counter_continues_growing_after_threshold() {
        let tracker = LockoutTracker::new();
        for _ in 0..5 {
            tracker.record_failure("user1");
        }
        assert!(tracker.is_locked("user1"));

        // Additional failures beyond the threshold should increment the counter.
        for _ in 0..3 {
            tracker.record_failure("user1");
        }
        let entry = tracker.entries.get("user1").unwrap();
        assert_eq!(entry.failed_count, 8);
        // Still locked — the lockout duration is measured from the last failure.
        assert!(tracker.is_locked("user1"));
    }

    /// Concurrent stress test: many tasks simultaneously call
    /// record_failure, is_locked, and cleanup_expired on a shared tracker.
    /// DashMap guarantees safe concurrent access; this test verifies that
    /// no data races, panics, or corruption occur under heavy load.
    #[tokio::test]
    async fn test_concurrent_access_safety() {
        let tracker = Arc::new(LockoutTracker::new());

        // Spawn 20 tasks that each record 3 failures for distinct users.
        let mut handles = Vec::new();
        for i in 0..20 {
            let lt = Arc::clone(&tracker);
            handles.push(tokio::spawn(async move {
                let sub = format!("concurrent_user_{}", i);
                for _ in 0..3 {
                    lt.record_failure(&sub);
                }
                lt.is_locked(&sub);
            }));
        }

        // Also spawn tasks that check is_locked for non-existent users
        // and run cleanup_expired concurrently.
        for _ in 0..5 {
            let lt = Arc::clone(&tracker);
            handles.push(tokio::spawn(async move {
                lt.is_locked("ghost");
                lt.cleanup_expired();
            }));
        }

        // All tasks should complete without panic or error.
        for h in handles {
            h.await.expect("concurrent task should not panic");
        }

        // After all failures, each user should have exactly 3 failures
        // (not locked, since threshold is 5).
        for i in 0..20 {
            let sub = format!("concurrent_user_{}", i);
            assert!(!tracker.is_locked(&sub));
            let entry = tracker.entries.get(&sub).unwrap();
            assert_eq!(entry.failed_count, 3);
        }
    }
}