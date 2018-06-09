# laravel-jwt

laravel jwt ��֤����

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