<?php

namespace aliirfaan\LaravelSimpleJwt\Http\Middleware;

use Closure;
use aliirfaan\LaravelSimpleJwt\Services\JwtHelperService;

class SimpleJwtVerify
{
    protected $jwtServiceInstance;

    public function __construct(JwtHelperService $jwtHelperService)
    {
        $this->jwtHelperService = $jwtHelperService;
    }

    /**
     * Handle an incoming request.
     *
     * @param  \Illuminate\Http\Request  $request
     * @param  \Closure  $next
     * @return mixed
     */
    public function handle($request, Closure $next)
    {
        try {

            $token = $request->bearerToken();
            
            $verifyToken = $this->jwtHelperService->verifyJwtToken($token);
            if ($verifyToken['errors'] == true) {
                // handle jwt error

                echo json_encode($verifyToken);
                exit();
            }

            // passed token validate, continue with request
            $tokenClaims = (array) $verifyToken['result'];
            $request->attributes->add(['token_claims' => $tokenClaims]);

        } catch (\Exception $e) {
            //
        }

        return $next($request);
    }
}
