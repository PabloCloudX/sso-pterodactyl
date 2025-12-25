<?php

namespace WemX\Sso\Http\Controllers;

use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\Auth;
use Pterodactyl\Models\User;
use Illuminate\Http\Request;
use Illuminate\Support\Str;

class SsoController 
{

    /**
     * Attempt to login the user
     *
     * @return Redirect
     */
    public function handle($token)
    {
        if(!$this->hasToken($token)) {
            return redirect()->back()->withError('Token does not exists or has expired');
        }

        try {
            Auth::loginUsingId($this->getToken($token));
            $this->invalidateToken($token);

            return redirect()->intended('/');
        } catch(\Exception $error) {
            return redirect()->back()->withError('Something went wrong, please try again.');
        }
    }

    /**
     * Handle incoming webhook
     *
     * @return $token
     */
    public function webhook(Request $request)
{
    // 🔐 WAJIB header khusus
    $header = $request->header('pauthgacor');
    if (!$header || $header !== 'pauthgacor') {
        return response([
            'success' => false,
            'message' => 'Unauthorized SSO access'
        ], 403);
    }

    // 📧 ambil email
    $email = $request->query('email');
    if (!$email) {
        return response([
            'success' => false,
            'message' => 'Email is required'
        ], 400);
    }

    // 👤 cari user
    $user = User::where('email', $email)->first();
    if (!$user) {
        return response([
            'success' => false,
            'message' => 'User not found'
        ], 404);
    }

    // 🚫 block admin
    /*if ($user->root_admin) {
        return response([
            'success' => false,
            'message' => 'Admin accounts are not allowed'
        ], 403);
    }

    // 🚫 block 2FA
    if ($user->two_factor_enabled ?? $user->2fa ?? false) {
        return response([
            'success' => false,
            'message' => '2FA enabled account not supported'
        ], 403);
    }*/

    // 🔑 generate token BARU
    $token = $this->generateToken($user->id);

    // 🔁 redirect login
    return response([
        'success' => true,
        'redirect' => route('sso-wemx.login', $token),
    ], 200);
}

    /**
     * Generate a random access token and store the user_id inside
     * Tokens are only valid for 60 seconds
     *
     * @return mixed
     */
    protected function generateToken($user_id)
    {
        $token = Str::random(config('sso-wemx.token.length', 48));
        Cache::add($token, $user_id, config('sso-wemx.token.lifetime', 60));
        return $token;
    }

    /**
     * Returns the value of the token
     *
     * @return mixed
     */
    protected function getToken($token)
    {
        return Cache::get($token);
    }

    /**
     * Returns true or false based on if the token exists
     *
     * @return bool
     */
    protected function hasToken($token): bool
    {
        return Cache::has($token);
    }

    /**
     * Invalidates the token so it can no longer be used
     *
     * @return void
     */
    protected static function invalidateToken($token)
    {
        Cache::forget($token);
    }
}
