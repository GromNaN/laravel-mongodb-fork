<?php

declare(strict_types=1);

namespace MongoDB\Laravel\Tests\Models;

use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\HasMany;
use MongoDB\Laravel\Eloquent\HybridRelations;

class SpaceShip extends Model
{
    use HybridRelations;

    protected $connection = 'sqlite';

    public $primaryKey = 'id';

    public function passengers(): HasMany
    {
        return $this->hasMany(Passenger::class);
    }
}
