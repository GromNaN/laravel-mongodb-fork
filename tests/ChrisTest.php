<?php

declare(strict_types=1);

namespace MongoDB\Laravel\Tests;

use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;
use MongoDB\Laravel\Tests\Models\Passenger;
use MongoDB\Laravel\Tests\Models\SpaceShip;

class ChrisTest extends TestCase
{
    public function test()
    {
        $schema = Schema::connection('sqlite');
        $schema->dropIfExists('space_ships');
        $schema->create('space_ships', function (Blueprint $table) {
            $table->id();
            $table->string('name');
            $table->timestamps();
        });

        Passenger::truncate();
        SpaceShip::truncate();

        $spaceship = new SpaceShip();
        $spaceship->id = 1234;
        $spaceship->name = 'Nostromo';
        $spaceship->save();

        $passengerEllen = new Passenger();
        $passengerEllen->name = 'Ellen Ripley';

        $passengerDwayne = new Passenger();
        $passengerDwayne->name = 'Dwayne Hicks';

        $spaceship->passengers()->save($passengerEllen);
        $spaceship->passengers()->save($passengerDwayne);

        $this->assertEquals($spaceship->id, $passengerEllen->space_ship_id);
        $this->assertEquals($spaceship->id, $passengerDwayne->space_ship_id);
    }
}
