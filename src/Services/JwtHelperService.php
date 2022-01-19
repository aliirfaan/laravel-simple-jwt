<?php

namespace aliirfaan\LaravelSimpleJwt\Services;

use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Str;
use \Firebase\JWT\JWT;
use aliirfaan\LaravelSimpleJwt\Models\ModelRefreshToken;
use aliirfaan\LaravelSimpleJwt\Exceptions\NotFoundException;

/**
 * JwtHelperService
 * 
 * Helper class to generate and validate JWT token
 */
class JwtHelperService
{        
    /**
     * loadJwtProfile
     *
     * @param  string $profile jwt profile defined in config
     * @return array
     * @throws NotFoundException If profile is not found
     */
    public function loadJwtProfile($profile)
    {
        $configKey = 'simple-jwt.profiles.' . $profile;
        $jwtProfile = [];
        if (config()->has($configKey)) {
            $jwtProfile = config($configKey);
        } else {
            throw new NotFoundException('Profile not found');
        }

        return $jwtProfile;
    }
    
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
    public function createJwtToken($customPayload, $profile = 'default', $overrideClaims = [])
    {
        $jwtProfile = $this->loadJwtProfile($profile);

        $issuedAtClaim = time();
        $jwtSuject = array_key_exists('sub', $customPayload) ? $customPayload['sub'] : null;
        
        $tokenPayload = array(
            'iss' => $jwtProfile['jwt_issuer'],
            'aud' => $jwtProfile['jwt_audience'],
            'iat' => $issuedAtClaim,
            'sub' => $jwtSuject,
            'data' => $customPayload,
        );

        // check if our tokens have an expiry
        if (intval($jwtProfile['jwt_does_expire']) == 1) {
            $expiredClaim = $issuedAtClaim + $jwtProfile['jwt_ttl_seconds'];
            $tokenPayload['exp'] = $expiredClaim;
        }

        // replace claims if provided
        $tokenPayload = array_replace($tokenPayload, $overrideClaims);

        $token = JWT::encode($tokenPayload, $jwtProfile['jwt_secret']);

        return $token;
    }
    
    /**
     * verifyJwtToken
     * 
     * Verifies jwt token validity, expiry, signature
     *
     * @param  string $token jwt token
     * @param  string $profile jwt profile defined in config
     * @return array
     */
    public function verifyJwtToken($token, $profile = 'default')
    {
        $data = array(
            'result' => null,
            'errors' => null,
            'message' => null,
        );

        try {
            $jwtProfile = $this->loadJwtProfile($profile);

            // leeway
            JWT::$leeway = $jwtProfile['jwt_leeway_seconds'];
            
            $decoded = JWT::decode($token, $jwtProfile['jwt_secret'], array($jwtProfile['jwt_algo']));
            $data['result'] = $decoded->data;
        } catch (\Firebase\JWT\BeforeValidException $e) {
            $data['errors'] = true;
            $data['message'] = $e->getMessage();
        } catch (\Firebase\JWT\ExpiredException $e) {
            $data['errors'] = true;
            $data['message'] = $e->getMessage();
        } catch (\Firebase\JWT\SignatureInvalidException $e) {
            $data['errors'] = true;
            $data['message'] = $e->getMessage();
        } catch (\Exception $e) {
            $data['errors'] = true;
            $data['message'] = $e->getMessage();
        }

        return $data;
    }
    
    /**
     * createRefreshToken
     *
     * @param  string $profile jwt profile defined in config
     * @return string refresh token
     */
    public function createRefreshToken($profile = 'default')
    {
        $jwtProfile = $this->loadJwtProfile($profile);

        $refreshTokenUuid = (string) Str::uuid();
        $hashedRefreshToken = Hash::make($refreshTokenUuid);
        $refreshTtlDays = '+' .$jwtProfile['jwt_refresh_ttl_days'] . ' days';
        $refreshTokenExpiryDate = Date('Y-m-d H:i:s', strtotime($refreshTtlDays));

        $refreshToken = [
            'token' => $refreshTokenUuid,
            'hashed_token' => $hashedRefreshToken,
            'expires_at' => $refreshTokenExpiryDate,
        ];

        return $refreshToken;
    }
    
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
    public function verifyRefreshToken($modelObject, $token = null)
    {
        $data = array(
            'success' => false,
            'errors' => null,
            'message' => null,
        );

        // check if refresh token matches
        if (!is_null($token) && Hash::check($token, $modelObject->refresh_token) == false) {
            $data['errors'] = true;
            $data['message'] = 'Refresh token does not match';
        }

        // check if blacklisted
        if (is_null($data['errors'])) {
            if (intval($modelObject->blacklisted) == 1) {
                $data['errors'] = true;
                $data['message'] = 'Refresh token blacklisted';
            }
        }

        // check if not expired
        if (is_null($data['errors'])) {
            $dateNow = date('Y-m-d H:i:s');
            if ($modelObject->expires_at < $dateNow) {
                $data['errors'] = true;
                $data['message'] = 'Refresh token expired';
            }
        }

        if (is_null($data['errors'])) {
            $data['success'] = true;
        }

        return $data;
    }
    
    
    /**
     * processRefreshToken
     * 
     * Verifies refresh token in the database and updates token if required
     *
     * @param  string $modelType model name
     * @param  int $modelId model id in database
     * @param  string|null $token refresh token
     * @param  string $profile jwt profile defined in config
     * @return array
     */
    public function processRefreshToken($modelType, $modelId, $token = null, $profile = 'default')
    {
        $data = array(
            'success' => false,
            'result' => null,
            'errors' => null,
            'message' => null,
        );

        try {
            $jwtProfile = $this->loadJwtProfile($profile);

            $modelRefreshToken =  new ModelRefreshToken();
            $refreshTokenObj = $modelRefreshToken->getRefreshToken($modelType, $modelId);
            $refreshTokenData = null;

            if (!is_null($refreshTokenObj)) {
                // a refresh token exists, check its validity
                $isValidRefreshToken = $this->verifyRefreshToken($refreshTokenObj, $token);
                if ($isValidRefreshToken['success'] == true) {
                    if (intval($jwtProfile['jwt_refresh_should_extend']) == 1) {
                        $refreshTokenData = [
                            'model_id' => $refreshTokenObj->model_id, 
                            'model_type' => $refreshTokenObj->model_type
                        ];
                    }
                } else {
                    $data['errors'] = $isValidRefreshToken['errors'];
                    $data['message'] = $isValidRefreshToken['message'];
                }
            } else {
                // no refresh token found, add a new refresh token
                $refreshTokenData = [
                    'model_id' => $modelId, 
                    'model_type' => $modelType
                ];
            }

            // check if we should create or update refresh token
            if (!is_null($refreshTokenData)) {
                $newToken = $this->createRefreshToken();
                $refreshTokenData['refresh_token'] = $newToken['hashed_token'];
                $refreshTokenData['expires_at']= $newToken['expires_at'];
                
                $modelRefreshToken->createOrUpdateRefreshToken($refreshTokenData);
                $data['result'] = $newToken['token'];
            }
        } catch (\Exception $e) {
            report($e);
            $data['errors'] = true;
            $data['message'] = 'An exception occured';
        }

        if (is_null($data['errors'])) {
            $data['success'] = true;
        }

        return $data;
    }
}
