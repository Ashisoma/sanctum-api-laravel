<?php

use App\Http\Controllers\AuthController;
use App\Http\Controllers\ProductController;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Route;

/*
|--------------------------------------------------------------------------
| API Routes
|--------------------------------------------------------------------------
|
| Here is where you can register API routes for your application. These
| routes are loaded by the RouteServiceProvider within a group which
| is assigned the "api" middleware group. Enjoy building your API!
|
*/

// Protected ROutes
Route::group(['middleware'=>['auth:sanctum']], function () {
    Route::post('/products', [ProductController::class, 'store']);
    Route::delete('/products/{id}', [ProductController::class, 'destroy']);
    Route::put('/products/{id}', [ProductController::class, 'update']);
    Route::post('/logout', [AuthController::class, 'logout']);
});


// Public routes
Route::post('/login', [AuthController::class, 'login']);

Route::post('/register', [AuthController::class, 'register']);

Route::get('/products/{id}', [ProductController::class, 'show'],);

Route::get('/products/search/{name}', [ProductController::class, 'search']);

Route::get('/products', [ProductController::class, 'index']);


Route::get('/',function(){
    return "Products";
});