# Change Log
All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com) and this project adheres to [Semantic Versioning](https://semver.org).

## 5.0.0 - 2021-09-06

### Added

- Nothing

### Changed

- createJwtToken($customPayload, $profile = 'default', $overrideClaims = []) now setting sub (subject) reserved claim

### Deprecated

- Nothing

### Removed

- nothing

### Fixed

- Nothing

## 4.0.0 - 2021-09-06

### Added

- profiles in config
- leeway to account for clock skew when verifying JWT
- loadJwtProfile($profile) in service

### Changed

- createJwtToken($customPayload, $profile = 'default', $overrideClaims = []) create jwt based on profile, ability to add/override claims on creation
- verifyJwtToken($token, $profile = 'default') verify based on profile
- createRefreshToken($profile = 'default') refresh token based on profile
- processRefreshToken($modelType, $modelId, $token = null, $profile = 'default') process refresh token based on profile

### Deprecated

- Nothing

### Removed

- All class attributes in JwtHelperService class

### Fixed

- Nothing

## 3.0.0 - 2021-02-16

### Added

- Nothing

### Changed

- processRefreshToken function - change return array by removing keys to simplify output

### Deprecated

- Nothing

### Removed

- nothing

### Fixed

- Nothing

## 2.0.0 - 2021-02-16

### Added

- Nothing

### Changed

- verifyJwtToken function - change argument order, now accepts null token
- processRefreshToken function - change argument order, now accepts null token

### Deprecated

- Nothing

### Removed

- nothing

### Fixed

- Nothing