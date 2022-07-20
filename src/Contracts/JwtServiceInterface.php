<?php

namespace aliirfaan\LaravelSimpleJwt\Contracts;

interface JwtServiceInterface
{
    /**
     * createJwtToken
     *
     * Create a jwt with given payload
     * 
     * @param  array $customPayload jwt custom payload
     * @param  string $profile jwt profile defined in config
     * @param  array $overrideClaims array of claims to override or include
     * @return string jwt token
     */
    public function createJwtToken($customPayload, $profile = 'default', $overrideClaims = []);

    /**
     * verifyJwtToken
     * 
     * Verifies jwt token validity, expiry, signature
     *
     * @param  string $token jwt token
     * @param  string $profile jwt profile defined in config
     * @return array
     */
    public function verifyJwtToken($token, $profile = 'default');

    /**
     * createRefreshToken
     *
     * @param  string $profile jwt profile defined in config
     * @return string refresh token
     */
    public function createRefreshToken($profile = 'default');

    /**
     * verifyRefreshToken
     *
     * verifies refersh token validity by comparison, expiry date, blacklisted
     *
     * @param  ModelRefreshToken $modelObject
     * @param  string/null $token refresh token. If token is null,we only check if blacklisted and expiry
     * 
     * @return array
     */
    public function verifyRefreshToken($modelObject, $token = null);
}