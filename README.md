# Laravel Simple JWT

This package allows you to generate Json Web Tokens. You can then verify the JWT code and grant access based on its validity. You can also use the optional refresh token flow for long lived sessions.

## JWT flow

* User logs in and gets a JWT with custom claims
* For each request consumer sends JWT
* App verifies JWT and allow of disallow user based on validity

## Refresh token flow

* User logs in and gets a JWT with custom claims and also gets a refresh token with an expiry date
* For each request consumer sends JWT, refresh token is extended and gets a later expiry date
* If JWT expires, consumer sends refresh token
* App checks if refresh token is expired
* If refresh token is not expired, issue a JWT and extend refresh token

## Features

* Generate JWT
* Verify JWT
* Configuration for JWT expiry
* Refresh token flow after JWT expires
* Extend refresh token everytime the application is used so that user is not logged out 
* Blacklist user so that token is not refreshed

## Requirements

* [Composer](https://getcomposer.org/)
* [Laravel](http://laravel.com/)
* [firebase/php-jwt](https://github.com/firebase/php-jwt)


## Installation

You can install this package on an existing Laravel project with using composer:

```bash
 $ composer require aliirfaan/laravel-simple-jwt
```

Register the ServiceProvider by editing **config/app.php** file and adding to providers array:

```php
  aliirfaan\LaravelSimpleJwt\SimpleJwtServiceProvider::class,
```

Note: use the following for Laravel <5.1 versions:

```php
 'aliirfaan\LaravelSimpleJwt\SimpleJwtServiceProvider',
```

Publish files with:

```bash
 $ php artisan vendor:publish --provider="aliirfaan\LaravelSimpleJwt\SimpleJwtServiceProvider"
```

or by using only `php artisan vendor:publish` and select the `aliirfaan\LaravelSimpleJwt\SimpleJwtServiceProvider` from the outputted list.

Apply the migrations:

```bash
 $ php artisan migrate
 ```

## Configuration

This package publishes an `simple-jwt.php` file inside your applications's `config` folder which contains the settings for this package. Most of the variables are bound to environment variables, but you are free to directly edit this file, or add the configuration keys to the `.env` file.

jwt_secret | String
Secret key to use to encode JWT. You can generate one using an online service or package.

```php
'jwt_secret' => env('JWT_SECRET')
```

jwt_algo | String
Name of supported hashing algorithm

```php
'jwt_algo' => env('JWT_ALGO', 'HS256')
```

jwt_issuer | String
Name of authority issuing JWT, normally your application name

```php
'jwt_issuer' => env('JWT_ISSUER', config('app.name'))
```

jwt_audience | String
Name of resource server that will accept the claim, normally application url

```php
'jwt_audience' => env('JWT_AUDIENCE', config('app.url'))
```

jwt_does_expire | Bool (true or false)
Whether the jwt expires

```php
'jwt_does_expire' => env('JWT_DOES_EXPIRE', true)
```

jwt_ttl_seconds | Numeric
Number of seconds after which the JWT expires if jwt_does_expire is set to true

```php
'jwt_ttl_seconds' => env('JWT_TTL_SECONDS', 900)
```

jwt_refresh_should_extend | Bool (true or false)
Whether we should automatically extend the JWT refresh token

```php
'jwt_refresh_should_extend' => env('JWT_REFRESH_SHOULD_EXTEND', true)
```

jwt_refresh_ttl_days | Numeric
Number of days to extend refresh token expiry

```php
'jwt_refresh_ttl_days' => env('JWT_REFRESH_TTL_DAYS', 90)
```

## Usage

```php
<?php

namespace App\Http\Controllers;

use Illuminate\Http\Request;
use aliirfaan\LaravelSimpleJwt\Services\JwtHelperService; // jwt helper service

class JwtTestController extends Controller
{
     /**
     * Include our service using dependency injection
     */
    public function index(Request $request, JwtHelperService $jwtHelperService)
    {
        // jwt flow

        // payload
        $tokenPayload = array(
            'customer_id' => 1234,
        );

        // jwt token
        $jwt = $jwtHelperService->createJwtToken($tokenPayload);
        //dd($jwt);

        // verify jwt, you will normally do this in a middleware
        $token = 'eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJMYXJhdmVsX2Jsb2ciLCJhdWQiOiJodHRwOlwvXC9sb2NhbGhvc3RcL2Jsb2ciLCJpYXQiOjE2MTIxODAyMTEsImRhdGEiOnsiY3VzdG9tZXJfaWQiOjEyMzR9LCJleHAiOjE2MTIxODExMTF9.uqFln2iQVRvaYvKDTGEG29SrT1flj9JEvFBg2zO3whM';
        $verifyJwt = $jwtHelperService->verifyJwtToken($token);
        if ($verifyJwt['errors'] == true) {

        } else {
            //get your token claims
            $tokenClaims = (array) $verifyJwt['result'];
            //dd($tokenClaims);
        }

        // refresh token flow. Using refresh flow is optional and depends on your use case
        
        $modelType = 'customer'; // your model type name you want, should be unique so that you can sent refresh tokens to multiple types of model 
        $modelId = 253; // your model id
        $refreshToken = '798798-543543-5435432543'; // the refresh token sent by consumer/client, will be null for new logins

        $refreshTokenResult = processRefreshToken($refreshToken, $modelType, $modelId);
        dd($refreshTokenResult);
    }
}
```
### Middleware usage

You can verify the jwt in a route middleware like below. Do not forget to register you middleware.

```php
<?php

namespace App\Http\Middleware;

use Closure;
use aliirfaan\LaravelSimpleJwt\Services\JwtHelperService;

class SimpleJwtVerifyExample
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

            // get token from header bearer token
            $token = $request->bearerToken();
            
            $verifyToken = $this->jwtHelperService->verifyJwtToken($token);
            if ($verifyToken['errors'] == true) {

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
```

## License

The MIT License (MIT)

Copyright (c) 2020

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.