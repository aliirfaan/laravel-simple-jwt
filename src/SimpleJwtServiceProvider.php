<?php

namespace aliirfaan\LaravelSimpleJwt;

use aliirfaan\LaravelSimpleJwt\Services\JwtHelperService;

class SimpleJwtServiceProvider extends \Illuminate\Support\ServiceProvider
{
    /**
     * Register services.
     *
     * @return void
     */
    public function register()
    {
        $this->app->bind('aliirfaan\LaravelSimpleJwt\Services\JwtHelperService', function ($app) {
            return new JwtHelperService();
        });
    }

    /**
     * Bootstrap the application services.
     *
     * @return void
     */
    public function boot()
    {
        $this->loadMigrationsFrom(__DIR__.'/../database/migrations');
        
        $this->publishes([
            __DIR__.'/../config/simple-jwt.php' => config_path('simple-jwt.php'),
        ]);
    }
}
