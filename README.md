# laravel-jwt

laravel jwt 认证例子


Laravel 5.6 可以不用注册  JWT provider，可以自发现，
5.5 以下的版本需要注册，并且自编写中间件来过滤，验证过的 $user 注入到控制器

```
public function __construct(User $user)
{
    $this->user = $user;
}
```


5.6 可以在控制器构造函数中直接

``` php
public function __construct()
{
    $this->user = JWTAuth::parseToken()->authenticate();
}
```


5.5 的中间件

``` php
<?php
namespace App\Http\Middleware;
use Closure;
use JWTAuth;
use Tymon\JWTAuth\Exceptions\JWTException;
use Symfony\Component\HttpKernel\Exception\UnauthorizedHttpException;
class VerifyJWTToken
{
    /**
     * Handle an incoming request.
     *
     * @param  \Illuminate\Http\Request  $request
     * @param  \Closure  $next
     * @return mixed
     */
    public function handle($request, Closure $next)
    {
        try{
            $user = JWTAuth::toUser($request->input('token'));
        }catch (JWTException $e) {
            if($e instanceof \Tymon\JWTAuth\Exceptions\TokenExpiredException) {
                return response()->json(['token_expired'], $e->getStatusCode());
            }else if ($e instanceof \Tymon\JWTAuth\Exceptions\TokenInvalidException) {
                return response()->json(['token_invalid'], $e->getStatusCode());
            }else{
                return response()->json(['error'=>'Token is required']);
            }
        }
       return $next($request);
    }
}
``` 

laravel 的登录控制器方法在类库中，不好更改和阅读，
自己写登录控制器代码看起来更明了


```
composer create-project laravel/laravel laravel-jwt
```

```
composer require tymon/jwt-auth:dev-develop --prefer-source
```
Laravel 5.4 以下版本使用
```
composer require tymon/jwt-auth
```

Laravel 5.5 以下版本需要注册， 5.5 以上的版本可以自动发现。

config/app.php  添加注册

``` php
'providers' => [
......
Tymon\JWTAuth\Providers\JWTAuthServiceProvider::class,
],
'aliases' => [
......
'JWTAuth' => Tymon\JWTAuth\Facades\JWTAuth::class,
'JWTFactory' => Tymon\JWTAuth\Facades\JWTFactory::class,
],
```


5.5 以上使用

```
php artisan vendor:publish --provider="Tymon\JWTAuth\Providers\LaravelServiceProvider"
```


5.5 以下添加 jwt 配置

```
php artisan vendor:publish --provider="Tymon\JWTAuth\Providers\JWTAuthServiceProvider"
```

之后生成 config/jwt.php 文件。


5.5 以上使用
```
php artisan jwt:secret
```

5.5 以下使用

```
php artisan jwt:generate
```

注册中间件  app/Http/Kernel.php

``` php
protected $routeMiddleware = [
    ....
    'auth.jwt' => \Tymon\JWTAuth\Http\Middleware\Authenticate::class,
];
```

修改路由 routes/api.php

``` php
Route::post('login', 'ApiController@login');
Route::post('register', 'ApiController@register');

Route::group(['middleware' => 'auth.jwt'], function () {
    Route::get('logout', 'ApiController@logout');

    Route::get('user', 'ApiController@getAuthUser');

    Route::get('products', 'ProductController@index');
    Route::get('products/{id}', 'ProductController@show');
    Route::post('products', 'ProductController@store');
    Route::put('products/{id}', 'ProductController@update');
    Route::delete('products/{id}', 'ProductController@destroy');
});
```


修改 app/User.php

``` php
<?php

namespace App;

use Illuminate\Notifications\Notifiable;
use Illuminate\Foundation\Auth\User as Authenticatable;
use Tymon\JWTAuth\Contracts\JWTSubject;

class User extends Authenticatable implements JWTSubject
{
    use Notifiable;

    /**
     * The attributes that are mass assignable.
     *
     * @var array
     */
    protected $fillable = [
        'name', 'email', 'password',
    ];

    /**
     * The attributes that should be hidden for arrays.
     *
     * @var array
     */
    protected $hidden = [
        'password', 'remember_token',
    ];

    /**
     * Get the identifier that will be stored in the subject claim of the JWT.
     *
     * @return mixed
     */
    public function getJWTIdentifier()
    {
        return $this->getKey();
    }

    /**
     * Return a key value array, containing any custom claims to be added to the JWT.
     *
     * @return array
     */
    public function getJWTCustomClaims()
    {
        return [];
    }

}

```

创建一个 ApiController.php

``` 
php artisan make:controller ApiController
```

``` php
<?php

namespace App\Http\Controllers;

use App\Http\Requests\RegisterAuthRequest;
use App\User;
use Illuminate\Http\Request;
use JWTAuth;
use Tymon\JWTAuth\Exceptions\JWTException;

class ApiController extends Controller
{
    public $loginAfterSignUp = true;

    public function register(RegisterAuthRequest $request)
    {
        $user = new User();
        $user->name = $request->name;
        $user->email = $request->email;
        $user->password = bcrypt($request->password);
        $user->save();

        if ($this->loginAfterSignUp) {
            return $this->login($request);
        }

        return response()->json([
            'success' => true,
            'data' => $user
        ], 200);
    }

    public function login(Request $request)
    {
        $input = $request->only('email', 'password');
        $jwt_token = null;

        if (!$jwt_token = JWTAuth::attempt($input)) {
            return response()->json([
                'success' => false,
                'message' => 'Invalid Email or Password',
            ], 401);
        }

        return response()->json([
            'success' => true,
            'token' => $jwt_token,
        ]);
    }

    public function logout(Request $request)
    {
        $this->validate($request, [
            'token' => 'required'
        ]);

        try {
            JWTAuth::invalidate($request->token);

            return response()->json([
                'success' => true,
                'message' => 'User logged out successfully'
            ]);
        } catch (JWTException $exception) {
            return response()->json([
                'success' => false,
                'message' => 'Sorry, the user cannot be logged out'
            ], 500);
        }
    }

    public function getAuthUser(Request $request)
    {
        这里不需验证 token，也不需要参数传递，检查 heade 中的 token 就行了
        //$this->validate($request, [
        //    'token' => 'required'
        //]);


        $user = JWTAuth::authenticate($request->token);

        return response()->json(['user' => $user]);
    }
}
```

创建一个测试 product 模型和控制器

```
php artisan make:model Product -mc
```


