//! Behavioral specification for breakpoint management.

/// Verifies breakpoint builders and metadata.
mod breakpoint;

/// Verifies concrete breakpoint controller behavior.
mod controller;

/// Verifies breakpoint manager lifecycle and recovery.
mod manager;

/// Provides deterministic VMI and controller fixtures.
mod mock;
