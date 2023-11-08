<?php

declare(strict_types=1);

namespace MongoDB\Laravel\Tests\Models;

use Illuminate\Database\Eloquent\Relations\BelongsTo;
use Illuminate\Database\Eloquent\Relations\MorphOne;
use MongoDB\Laravel\Eloquent\Model as Eloquent;

/**
 * @property string $title
 * @property string $author
 * @property array $chapters
 */
class Book extends Eloquent
{
    protected $connection       = 'mongodb';
    protected $collection       = 'books';
    protected static $unguarded = true;
    protected $primaryKey       = 'title';

    public function author(): BelongsTo
    {
        return $this->belongsTo(User::class, 'author_id');
    }

    public function sqlAuthor(): BelongsTo
    {
        return $this->belongsTo(SqlUser::class, 'author_id');
    }

    public function photo(): MorphOne
    {
        return $this->morphOne(SqlPhoto::class, 'has_image');
    }
}
