<?php

namespace aliirfaan\LaravelSimpleJwt\Services\Auth;

use Illuminate\Auth\GuardHelpers;
use Illuminate\Contracts\Auth\Guard;
use Illuminate\Support\Traits\Macroable;
use Illuminate\Contracts\Auth\UserProvider;
use Illuminate\Http\Request;
use aliirfaan\LaravelSimpleJwt\Services\JwtHelperService; 

class SimpleJwtGuard implements Guard
{
    use GuardHelpers, Macroable;

    /**
     * The name of the Guard. Typically "session".
     *
     * Corresponds to guard name in authentication configuration.
     *
     * @var string
     */
    protected $name;

    /**
     * The user we last attempted to retrieve.
     *
     * @var \Illuminate\Contracts\Auth\Authenticatable
     */
    protected $lastAttempted;

    /**
     * The JWT instance.
     */
    protected $jwtService;

    /**
     * The request instance.
     *
     * @var \Illuminate\Http\Request
     */
    protected $request;

    /**
     * Create a new authentication guard.
     *
     * @param  string  $name
     * @param  \Illuminate\Contracts\Auth\UserProvider  $provider
     * @param  \Illuminate\Contracts\Session\Session  $session
     * @param  \Symfony\Component\HttpFoundation\Request|null  $request
     * @return void
     */
    public function __construct(JwtHelperService $jwtService, $name, UserProvider $provider, Request $request = null)
    {
        $this->name = $name;
        $this->jwtService = $jwtService;
        $this->request = $request;
        $this->provider = $provider;
    }

    /**
     * Get the currently authenticated user.
     *
     * @return \Illuminate\Contracts\Auth\Authenticatable|null
     */
    public function user()
    {
        if (!is_null($this->user)) {
            return $this->user;
        }

        $token = $request->bearerToken();
        $verifyToken = $this->jwtService->verifyJwtToken($token);
        if ($verifyToken['errors'] == null) {
            $tokenClaims = (array) $verifyToken['result'];
            $this->user = $this->provider->retrieveById($tokenClaims['sub']);

            return $this->user;
        }

        return null;
    }

    /**
     * Validate a user's credentials.
     *
     * @param  array  $credentials
     * @return bool
     */
    public function validate(array $credentials = [])
    {
        $this->lastAttempted = $user = $this->provider->retrieveByCredentials($credentials);

        return $this->hasValidCredentials($user, $credentials);
    }
}