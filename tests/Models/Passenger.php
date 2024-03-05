<?php

declare(strict_types=1);

namespace MongoDB\Laravel\Tests\Models;

use MongoDB\Laravel\Eloquent\Model;
use MongoDB\Laravel\Relations\BelongsTo;

class Passenger extends Model
{
    protected $connection = 'mongodb';

    public function spaceship(): BelongsTo
    {
        return $this->BelongsTo(SpaceShip::class);
    }
}
