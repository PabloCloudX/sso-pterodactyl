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
            //$this->invalidateToken($token);

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
    if (!config('sso-wemx.secret')) {
        abort(403, 'SSO secret not configured');
    }

    if ($request->input('sso_secret') !== config('sso-wemx.secret')) {
        abort(403, 'Invalid SSO secret');
    }

    $email = $request->input('email');
    if (!$email) {
        abort(422, 'Email is required');
    }

    $user = User::where('email', $email)->first();
    if (!$user) {
        abort(404, 'User not found');
    }

    if ($user->use_totp) {
        abort(403, '2FA account not supported');
    }

    // 🔑 GENERATE TOKEN
    $token = $this->generateToken($user->id);

    // 🚀 LANGSUNG REDIRECT & LOGIN
    return redirect()->route('sso-wemx.login', $token);
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
