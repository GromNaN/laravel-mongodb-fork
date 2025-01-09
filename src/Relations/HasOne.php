<?php

declare(strict_types=1);

namespace MongoDB\Laravel\Relations;

use Illuminate\Database\Eloquent\Builder;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\HasOne as EloquentHasOne;
use Illuminate\Support\Arr;

use function is_null;

class HasOne extends EloquentHasOne
{
    /**
     * Get the key for comparing against the parent key in "has" query.
     *
     * @return string
     */
    public function getForeignKeyName()
    {
        return $this->foreignKey;
    }

    /**
     * Get the key for comparing against the parent key in "has" query.
     *
     * @return string
     */
    public function getHasCompareKey()
    {
        return $this->getForeignKeyName();
    }

    /** @inheritdoc */
    public function getRelationExistenceQuery(Builder $query, Builder $parentQuery, $columns = ['*'])
    {
        $foreignKey = $this->getForeignKeyName();

        return $query->select($foreignKey)->where($foreignKey, 'exists', true);
    }

    public function ofMany($column = 'id', $aggregate = 'MAX', $relation = null)
    {
        return parent::ofMany($column, $aggregate, $relation);
        $this->ofMany = true;

        $order = match($aggregate) {
            'MAX' => -1,
            'MIN' => 1,
            default => throw new \LogicException('Invalid aggregate fonction for ofMany relation. Available aggregates: MIN, MAX'),
        };
    }

    protected function newOneOfManySubQuery($groupBy, $columns = null, $aggregate = null)
    {
        $subQuery = $this->query->getModel()
            ->newQuery()
            ->withoutGlobalScopes($this->removedScopes());

        foreach (Arr::wrap($groupBy) as $group) {
            $subQuery->groupBy($this->qualifyRelatedColumn($group));
        }

        if (! is_null($columns)) {
            foreach ($columns as $key => $column) {
                $aggregatedColumn = $subQuery->qualifyColumn($column);

                if ($key === 0) {
                    $aggregatedColumn = ['$' . strtolower($aggregate) => '$' . $aggregatedColumn];
                } else {
                    $aggregatedColumn = ['$min' => '$' . $aggregatedColumn];
                }

                $subQuery->project([$column . '_aggregate' => $aggregatedColumn]);
            }
        }

        $this->addOneOfManySubQueryConstraints($subQuery, column: null, aggregate: $aggregate);

        return $subQuery;

        parent::newOneOfManySubQuery($groupBy, $columns, $aggregate);
    }

    /**
     * Get the name of the "where in" method for eager loading.
     *
     * @param string $key
     *
     * @return string
     */
    protected function whereInMethod(Model $model, $key)
    {
        return 'whereIn';
    }
}
