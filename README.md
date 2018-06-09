# laravel-jwt

laravel jwt ��֤����


Laravel 5.6 ���Բ���ע��  JWT provider�������Է��֣�
5.5 ���µİ汾��Ҫע�ᣬ�����Ա�д�м�������ˣ���֤���� $user ע�뵽������

```
public function __construct(User $user)
{
    $this->user = $user;
}
```


5.6 �����ڿ��������캯����ֱ��

``` php
public function __construct()
{
    $this->user = JWTAuth::parseToken()->authenticate();
}
```


5.5 ���м��

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

laravel �ĵ�¼����������������У����ø��ĺ��Ķ���
�Լ�д��¼���������뿴����������


```
composer create-project laravel/laravel laravel-jwt
```

```
composer require tymon/jwt-auth:dev-develop --prefer-source
```
Laravel 5.4 ���°汾ʹ��
```
composer require tymon/jwt-auth
```

Laravel 5.5 ���°汾��Ҫע�ᣬ 5.5 ���ϵİ汾�����Զ����֡�

config/app.php  ���ע��

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


5.5 ����ʹ��

```
php artisan vendor:publish --provider="Tymon\JWTAuth\Providers\LaravelServiceProvider"
```


5.5 ������� jwt ����

```
php artisan vendor:publish --provider="Tymon\JWTAuth\Providers\JWTAuthServiceProvider"
```

֮������ config/jwt.php �ļ���


5.5 ����ʹ��
```
php artisan jwt:secret
```

5.5 ����ʹ��

```
php artisan jwt:generate
```

ע���м��  app/Http/Kernel.php

``` php
protected $routeMiddleware = [
    ....
    'auth.jwt' => \Tymon\JWTAuth\Http\Middleware\Authenticate::class,
];
```

�޸�·�� routes/api.php

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


�޸� app/User.php

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

����һ�� ApiController.php

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
        ���ﲻ����֤ token��Ҳ����Ҫ�������ݣ���� heade �е� token ������
        //$this->validate($request, [
        //    'token' => 'required'
        //]);


        $user = JWTAuth::authenticate($request->token);

        return response()->json(['user' => $user]);
    }
}
```

����һ������ product ģ�ͺͿ�����

```
php artisan make:model Product -mc
```


