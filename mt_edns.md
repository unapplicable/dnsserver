---
RFC: 6891
Mutation Test: EDNS(0) Option Handling and Buffer Size

Summary:
- Mutation tests target RFC 6891 edge and negative cases:
  - Unknown option codes (must be ignored, not rejected)
  - Overlong/truncated option rdata (malformed options)
  - Duplicate option codes in one OPT RR
  - Buffer size negotiation exploits (oversized/undersized/zero)
  - Non-root name/malformed OPT RR
  - Legacy/padding/critical EDNS(0) options
- Each test validates correct fallback and RFC-compliant behavior—no DoS, crash, or protocol violation.

References:
- RFC 6891 sec. 7 (Option Handling)
- BIND/Unbound EDNS testing practices

Test Results + Rationale (2026-01-28):

- Unknown option codes test: FAILED (parsed options < injected options)
  - Root cause: in rropt.cpp, when any option claims a length longer than available, parsing stops and discards all subsequent options.
  - RFC 6891: Unknown codes MUST be safely parsed/retained but ignored at protocol/application level. Malformed/truncated options should be ignored/skipped, but valid subsequent options must still be parsed.
  - Current implementation stops parsing after first malformed/overlength option, violating expected fallback.
  - Plan: Refactor unpack logic to skip only the invalid option, continue parsing remaining options.

- Reserved/padding/legacy/critical codes test: PASSED (all codes parsed and ignored safely)

- Mixed valid/malformed/reserved/unknown test: PASSED (at least valid options parsed; malformed not causing crash)

Edge Case Pitfalls:
- If malformed/truncated option present before valid ones, current logic discards remainder.
  - Must ensure isolated malformed option does not block valid options after.

Action:
- Patch rropt.cpp unpack loop to skip malformed options, continue parsing as RFC and other implementations (BIND, Unbound) do.

(End of update)
