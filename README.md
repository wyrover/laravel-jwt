# laravel-jwt

laravel jwt 认证例子

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