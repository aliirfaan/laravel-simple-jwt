<?php

namespace aliirfaan\LaravelSimpleJwt;

use Illuminate\Support\Facades\Auth;
use aliirfaan\LaravelSimpleJwt\Services\Auth\SimpleJwtGuard;
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

        Auth::extend('simple-jwt-guard', function ($app, $name, array $config) {
            return new SimpleJwtGuard($name, Auth::createUserProvider($config['provider']), $config['jwt_class'], $config['profile'], $this->app['events'], $this->app['request']);
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
