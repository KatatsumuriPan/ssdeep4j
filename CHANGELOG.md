# Changelog

All notable changes to this project will be documented in this file.

## [1.2.0] - 2026-02-01

### Added
- Added `FuzzyHash` class to represent a parsed fuzzy hash, enabling more efficient comparisons when reusing hash objects.
- Added `FuzzyHasher.hashToFuzzyHash` methods to compute hashes directly into `FuzzyHash` objects.
- Added `FuzzyState.digestToFuzzyHash` method.
- Added `FuzzyComparator.compare` overloads to support `FuzzyHash` objects.

### Changed
- Updated `FuzzyComparator` to support `FuzzyHash` comparisons.

## [1.1.0] - 2025-12-20

### Changed
- Java8 and higher is now supported.
- Optimized performance by separating Java 8 and higher implementations (Multi-Release JAR).
- Improved overall performance.

### Fixed
- Fixed JavaDoc issues.
- Added `Automatic-Module-Name` to `pom.xml`.

## [1.0.0] - 2025-12-14

First release.
