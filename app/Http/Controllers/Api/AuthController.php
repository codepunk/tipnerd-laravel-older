<?php

namespace App\Http\Controllers\Api;

use App\Http\Controllers\Controller;
use App\Models\User;
use Illuminate\Auth\Events\Registered;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Hash;
use Illuminate\Validation\Rules;

class AuthController extends Controller
{
    public function register(Request $request): JsonResponse
    {
        $request->validate([
            'username' => ['required', 'string', 'max:255', 'unique:'.User::class],
            'name' => ['required', 'string', 'max:255'],
            'email' => ['required', 'string', 'lowercase', 'email', 'max:255', 'unique:'.User::class],
            'password' => ['required', 'confirmed', Rules\Password::defaults()]
        ]);

        $user = User::create([
            'username' => $request->username,
            'name' => $request->name,
            'email' => $request->email,
            'password' => Hash::make($request->password),
        ]);

        event(new Registered($user));

        $created_user= User::where('email', '=', $request->email)->first();

        return response()->json([
            'user'=>$created_user,
            'status'=>'registered',
            'verified'=>false], 200);
    }

    public function login(Request $request): JsonResponse
    {
        $username_or_email = request('username_or_email');
        $field = filter_var($username_or_email, FILTER_VALIDATE_EMAIL) ? 'email' : 'username';

        if (! Auth::attempt(
            [$field => $username_or_email, 'password' => request('password')],
            request('remember'))
        ) {
            return response()->json(
                [
                    "user" => Null,
                    "message" => "Invalid login details",
                    "status" => "failed",
                ],
                200
            );
        }
        $user = User::where($field, $username_or_email)->firstOrFail();

        $logged_in_user=[
            'id' => $user->id,
            'email' => $user->email,
            'email_verified_at'=>  $user->email_verified_at,
            'status'=>'loggedIn'
        ];

        if ($user->email_verified_at != Null) {
            $token = $user->createToken("auth_token")->plainTextToken;
            $logged_in_user['user_token'] = $token;
            $logged_in_user['token_type'] = 'Bearer';
            $logged_in_user['verified'] = true;
        } else {
            $logged_in_user['verified'] = false;
        }

        return response()->json(
            $logged_in_user,
            200
        );
    }
}
