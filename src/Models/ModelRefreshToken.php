<?php

namespace aliirfaan\LaravelSimpleJwt\Models;

use Illuminate\Database\Eloquent\Model;

/**
 * OTP model
 */
class ModelRefreshToken extends Model
{
    protected $fillable = ['model_id', 'model_type', 'refresh_token', 'expires_at', 'blacklisted'];

    public function getRefreshToken($modelType, $modelId)
    {
        return ModelRefreshToken::where(function ($query) use ($modelId) {
            $query->where('model_id', '=', $modelId);
        })->where(function ($query) use ($modelType) {
            $query->where('model_type', '=', $modelType);
        })
        ->orderBy('expires_at', 'desc')
        ->first();
    }

    public function createOrUpdateRefreshToken($refreshTokenData)
    {
        return ModelRefreshToken::updateOrCreate(
            [
                'model_id' => $refreshTokenData['model_id'], 
                'model_type' => $refreshTokenData['model_type']
            ],
            [
                'refresh_token' => $refreshTokenData['refresh_token'],
                'expires_at' => $refreshTokenData['expires_at'],
            ]
        );
    }
}
