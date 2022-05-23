<?php

namespace App\Http\Controllers;

use App\Models\User;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Hash;
use PhpParser\Parser\Tokens;

class AuthController extends Controller
{
    public function register(Request $request){
        $fields = $request->validate([
            'name' => 'required|string',
            'email' => 'required|string|unique:users,email',
            'password' => 'required|string|confirmed'
        ]);

        $user = User::create([
            'name' => $fields['name'],
            'email' => $fields['email'],
            'password' => bcrypt($fields['password'])
        ]);

        $token = $user->createToken('myapptoken')->plainTextToken;

        $response = [
            'user' => $user,
            'token' => $token
        ];

        return response($response, 201);
    }

    public function login(Request $request){
        $fields = $request->validate([
            // 'name' => 'required|string',
            'email' => 'required|string',
            'password' => 'required|string'
        ]);

        // check if the user is exits
        $user = User::where('email', $fields['email'])->first();

        if (!$user || !Hash::check($fields['password'], $user->password)) {
            # code...
            return response([
                'message' =>'Bad Credentials',
            ], 401);
        }

        $token = $user->createToken('myapptoken')->plainTextToken;

        $response = [
            'user' => $user,
            'token' => $token
        ];

        return response($response, 201);
    }

    public function logout(Request $request){
        // $us = auth()->token();
        // Auth::guard()-logout();
        // $del->delete();
        // $this->guard()->logout();

        // $request->session()->invalidate();

        // $request->session()->regenerateToken();

        try {
            $request->user()->currentAccessToken()->delete();
            return [
                'message' => 'Logged out ',
                // 'user'=> $us,
            ];
        } catch (\Throwable $th) {
            return [
                'message' => 'Logged out ',
                'errorlog' => $th->getMessage(),
                // 'user'=> $us,
            ];
        }
    }

}
