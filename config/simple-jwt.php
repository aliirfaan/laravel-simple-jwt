<?php

return [

    /*
    |--------------------------------------------------------------------------
    | JWT configuration
    |--------------------------------------------------------------------------
    |
    | Here you may configure your settings for JWT. You are free to adjust these settings as needed.
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
    | jwt_refresh_should_extend | Bool (true or false)
    | Whether we should automatically extend the JWT refresh token
    |
    | jwt_refresh_ttl_days | Numeric
    | Number of days to extend refresh token expiry
    */

    'jwt_secret' => env('JWT_SECRET'),
    'jwt_algo' => env('JWT_ALGO', 'HS256'),
    'jwt_issuer' => env('JWT_ISSUER', config('app.name')),
    'jwt_audience' => env('JWT_AUDIENCE', config('app.url')),
    'jwt_does_expire' => env('JWT_DOES_EXPIRE', true),
    'jwt_ttl_seconds' => env('JWT_TTL_SECONDS', 900),
    'jwt_refresh_should_extend' => env('JWT_REFRESH_SHOULD_EXTEND', true),
    'jwt_refresh_ttl_days' => env('JWT_REFRESH_TTL_DAYS', 90),
];
