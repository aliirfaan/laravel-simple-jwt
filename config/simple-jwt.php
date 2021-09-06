<?php

return [

    /*
    |--------------------------------------------------------------------------
    | JWT configuration
    |--------------------------------------------------------------------------
    |
    | Here you may configure your settings for JWT. You are free to adjust these settings as needed.
    | These settings should be made available for each profile you create.
    |
    | jwt_secret | String
    | Secret key to use to encode JWT. You can generate one using an online service or package.
    |
    | jwt_algo | String
    | Name of supported hashing algorithm
    |
    | jwt_issuer | String
    | Name of authority issuing JWT, normally your application name
    |
    | jwt_audience | String
    | Name of resource server that will accept the claim, normally application url
    |
    | jwt_does_expire | Bool (true or false)
    | Whether the jwt expires
    |
    | jwt_ttl_seconds | Numeric
    | Number of seconds after which the JWT expires if jwt_does_expire is set to true
    |
    | jwt_leeway_seconds | Numeric
    | When checking nbf, iat or expiration times, we want to provide some extra leeway time to account for clock skew
    |
    | jwt_refresh_should_extend | Bool (true or false)
    | Whether we should automatically extend the JWT refresh token
    |
    | jwt_refresh_ttl_days | Numeric
    | Number of days to extend refresh token expiry
    */
    
    'profiles' => [
        // default jwt settings, you can add other profiles with the same format below
        'default' => [
            'jwt_secret' => env('DEFAULT_JWT_SECRET'),
            'jwt_algo' => env('DEFAULT_JWT_ALGO', 'HS256'),
            'jwt_issuer' => env('DEFAULT_JWT_ISSUER', config('app.name')),
            'jwt_audience' => env('DEFAULT_JWT_AUDIENCE', config('app.url')),
            'jwt_does_expire' => env('DEFAULT_JWT_DOES_EXPIRE', true),
            'jwt_ttl_seconds' => env('DEFAULT_JWT_TTL_SECONDS', 900),
            'jwt_leeway_seconds' => env('DEFAULT_JWT_LEEWAY_SECONDS', 0),
            'jwt_refresh_should_extend' => env('DEFAULT_JWT_REFRESH_SHOULD_EXTEND', true),
            'jwt_refresh_ttl_days' => env('DEFAULT_JWT_REFRESH_TTL_DAYS', 90),
        ]
    ]
];
