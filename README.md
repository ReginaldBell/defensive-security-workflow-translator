# Explainability & Validation

## Phase 4: Deterministic Explainability

- All incident summaries are generated using deterministic templates for explainability.
- The summary and recommended_actions fields are guaranteed to be consistent and reproducible for the same input.
- Evidence fields are always present and retain their original structure.

## Validation

- Pytest coverage includes a minimal test that:
  - Runs detection on a fixed input
  - Asserts summary is a string and matches the template prefix
  - Asserts recommended_actions is a list of 4 strings
  - Asserts all required evidence keys exist

**Phase 4 is complete.**
