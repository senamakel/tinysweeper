# Review timing

`src/review_timing.rs` collects per-review phase spans and emits one structured
timing event when the final handle for a run is dropped. Its fields and
operator-facing log filters are documented in the [server guide](../server/README.md#review-timing-logs).
