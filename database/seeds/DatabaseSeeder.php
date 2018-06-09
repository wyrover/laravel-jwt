<?php

use Illuminate\Database\Seeder;

class DatabaseSeeder extends Seeder
{
    /**
     * Seed the application's database.
     *
     * @return void
     */
    public function run()
    {
        //$this->call(UsersTableSeeder::class);
        $now = date("Y-m-d H:i:s");
 
        DB::table('users')->truncate();
        DB::table('users')->insert([
                'name' => 'wyrover',
                'email' => 'wyrover@gmail.com',
                'password' => app('hash')->make('wyrover'),                
                'created_at' => $now, 
                'updated_at' => $now
                ]);
    }
}
