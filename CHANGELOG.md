# Change Log
All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com) and this project adheres to [Semantic Versioning](https://semver.org).

## 9.0.1 - 2025-03-03

### Added

- nothing

### Changed

- README

### Deprecated

- nothing

### Removed

- nothing

### Fixed

- nothing

## 9.0.0 - 2025-02-28

### Added

- deleteRefreshToken() in ModelRefreshToken

### Changed

- processRefreshToken() add grantType parameter to know if login or refresh_token

### Deprecated

- Nothing

### Removed

- nothing

### Fixed

- processRefreshToken() could not login if refresh token was expired

## 8.1.1 - 2023-06-19

### Added

- Nothing

### Changed

- Nothing

### Deprecated

- Nothing

### Removed

- nothing

### Fixed

- verifyJwtToken() check if token is null before decoded using JWT::decode()

## 8.1.0 - 2023-05-02

### Added

- upgraded firebase/php-jwt dependency to ^6.0

### Changed

- Nothing

### Deprecated

- Nothing

### Removed

- nothing

### Fixed

- nothing

## 8.0.2 - 2022-09-09

### Added

- Nothing

### Changed

- SimpleJwtGuard authenticateByToken()

### Deprecated

- Nothing

### Removed

- nothing

### Fixed

## 8.0.1 - 2022-09-08

### Added

- Nothing

### Changed

- SimpleJwtGuard authenticateByToken()

### Deprecated

- Nothing

### Removed

- nothing

### Fixed

- authenticateByToken() case where user provider can return null for valid token

## 8.0.0 - 2022-08-09

### Added

- Guard method authenticateByToken() to authenticate using token

### Changed

- SimpleJwtGuard

- JwtHelperService verifyJwtToken($token, $profile = 'default')

### Deprecated

- Nothing

### Removed

- nothing

### Fixed

- Nothing

## 7.0.0 - 2022-08-03

### Added

- noting

### Changed

- SimpleJwtGuard allow to push custom claims when generating jwt token in guard

### Deprecated

- Nothing

### Removed

- nothing

### Fixed

- Nothing

## 6.0.0 - 2022

### Added

- device_id column to bind refresh token to a device

### Changed

- ModelRefreshToken to use device_id column
- processRefreshToken() add deviceId as parameter

### Deprecated

- Nothing

### Removed

- nothing

### Fixed

- Nothing

## 5.0.0 - 2022-07-20

### Added

- Contracts\JwtServiceInterface
- Services\Auth\SimpleJwtGuard, implements Illuminate\Contracts\Auth\Guard

### Changed

- createJwtToken($customPayload, $profile = 'default', $overrideClaims = []) now setting sub (subject) reserved claim
- JwtHelperService now implements Contracts\JwtServiceInterface

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