<?php

namespace aliirfaan\LaravelSimpleJwt\Services;

use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Str;
use \Firebase\JWT\JWT;
use aliirfaan\LaravelSimpleJwt\Models\ModelRefreshToken;

/**
 * JwtHelperService
 * 
 * Helper class to generate and validate JWT token
 */
class JwtHelperService
{    
    /**
     * jwtSecret
     *
     * @var String secret key to encode jwt
     */
    private $jwtSecret;
        
    /**
     * jwtIssuer
     *
     * @var String jwt issuing authority
     */
    private $jwtIssuer;
        
    /**
     * jwtAudience
     *
     * @var String jwt audience
     */
    private $jwtAudience;    

    /**
     * jwtAlgo
     *
     * @var String Supported algorith to hash jwt
     */
    private $jwtAlgo;

        
    /**
     * jwtTtlSeconds
     *
     * @var int Number of seconds after which jwt expires
     */
    private $jwtTtlSeconds;

        
    /**
     * jwtRefreshTtlDays
     *
     * @var int Number of days to extend refresh token expiry
     */
    private $jwtRefreshTtlDays;

        
    /**
     * jwtDoesExpire
     *
     * @var bool whether jwt expires
     */
    private $jwtDoesExpire;

        
    /**
     * jwtRefreshShouldExtend
     *
     * @var bool whether we shoudl extend refresh token
     */
    private $jwtRefreshShouldExtend;

    public function __construct()
    {
        $this->jwtSecret = config('simple-jwt.jwt_secret');
        $this->jwtAlgo = config('simple-jwt.jwt_algo');
        $this->jwtIssuer = config('simple-jwt.jwt_issuer');
        $this->jwtAudience = config('simple-jwt.jwt_audience');
        $this->jwtDoesExpire = config('simple-jwt.jwt_does_expire');
        $this->jwtTtlSeconds = config('simple-jwt.jwt_ttl_seconds');
        $this->jwtRefreshShouldExtend = config('simple-jwt.jwt_refresh_should_extend');
        $this->jwtRefreshTtlDays = config('simple-jwt.jwt_refresh_ttl_days');
    }
    
    /**
     * createJwtToken
     *
     * Create a jwt with given payload
     * @TODO: nbf
     * 
     * @param  array $payload jwt payload
     * @return string jwt token
     */
    public function createJwtToken($payload)
    {
        $issuedAtClaim = time();
        //$notBeforeClaim = $issuedAtClaim + 1;

        $tokenPayload = array(
            'iss' => $this->jwtIssuer,
            'aud' => $this->jwtAudience,
            'iat' => $issuedAtClaim,
            //'nbf' => $notBeforeClaim,
            'data' => $payload,
        );

        // check if our tokens have an expiry
        if (intval($this->jwtDoesExpire) == 1) {
            $expiredClaim = $issuedAtClaim + $this->jwtTtlSeconds;
            $tokenPayload['exp'] = $expiredClaim;
        }
        $token = JWT::encode($tokenPayload, $this->jwtSecret);

        return $token;
    }
    
    /**
     * verifyJwtToken
     * 
     * Verifies jwt token validity, expiry, signature
     *
     * @param  string $token jwt token
     * @return array
     */
    public function verifyJwtToken($token)
    {
        $data = array(
            'result' => null,
            'errors' => null,
            'message' => null,
        );

        try {
            $decoded = JWT::decode($token, $this->jwtSecret, array($this->jwtAlgo));
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
     * @return string refresh token
     */
    public function createRefreshToken()
    {
        $refreshTokenUuid = (string) Str::uuid();
        $hashedRefreshToken = Hash::make($refreshTokenUuid);
        $refreshTtlDays = '+' . $this->jwtRefreshTtlDays . ' days';
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
     * @return array
     */
    public function processRefreshToken($modelType, $modelId, $token = null)
    {
        $data = array(
            'success' => false,
            'result' => null,
            'errors' => null,
            'message' => null,
        );

        try {
            $modelRefreshToken =  new ModelRefreshToken();
            $refreshTokenObj = $modelRefreshToken->getRefreshToken($modelType, $modelId);
            $refreshTokenData = null;

            if (!is_null($refreshTokenObj)) {
                // a refresh token exists, check its validity
                $isValidRefreshToken = $this->verifyRefreshToken($refreshTokenObj, $token);
                if ($isValidRefreshToken['success'] == true) {
                    if (intval($this->jwtRefreshShouldExtend) == 1) {
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
