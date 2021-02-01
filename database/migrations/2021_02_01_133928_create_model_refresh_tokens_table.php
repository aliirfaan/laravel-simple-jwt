<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

class CreateModelRefreshTokensTable extends Migration
{
    /**
     * Run the migrations.
     *
     * @return void
     */
    public function up()
    {
        Schema::create('model_refresh_tokens', function (Blueprint $table) {
            $table->id();
            $table->string('model_id')->index('model_id_index');
            $table->string('model_type')->index('model_type_index');
            $table->string('refresh_token');
            $table->timestamp('expires_at')->nullable()->index('expires_at_index');
            $table->tinyInteger('blacklisted')->default(0);
            $table->timestamps();
        });
    }

    /**
     * Reverse the migrations.
     *
     * @return void
     */
    public function down()
    {
        Schema::dropIfExists('model_refresh_tokens');
    }
}
