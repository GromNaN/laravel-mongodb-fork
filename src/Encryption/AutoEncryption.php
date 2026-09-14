<?php

declare(strict_types=1);

namespace MongoDB\Laravel\Encryption;

use InvalidArgumentException;
use LogicException;
use MongoDB\BSON\Binary;
use MongoDB\Database;
use MongoDB\Driver\ClientEncryption;
use MongoDB\Driver\Exception\RuntimeException;
use MongoDB\Driver\Manager;
use MongoDB\Driver\Query as DriverQuery;
use MongoDB\Laravel\Connection;

use function array_key_exists;
use function array_key_first;
use function array_values;
use function base64_decode;
use function in_array;
use function is_array;
use function is_string;
use function phpversion;
use function sprintf;
use function str_contains;
use function strlen;
use function version_compare;

use WeakReference;

/**
 * Queryable Encryption support: configuration validation, encryptedFieldsMap
 * normalization, data key management, and the write-time safety guard. Owned
 * by a Connection, which exposes the public surface.
 *
 * @internal
 */
final class AutoEncryption
{
    /**
     * Collections confirmed to be created as encrypted collections. The full
     * set is loaded lazily in a single listCollections call so every mapped
     * collection is checked in one round trip, then cached.
     *
     * @var array<string, true>|null
     */
    private ?array $encryptedCollectionNames = null;

    private ?Manager $plainManager = null;

    /**
     * The owning Connection. Held weakly to avoid a reference cycle (the
     * Connection holds this AutoEncryption instance).
     *
     * @var WeakReference<Connection>
     */
    private readonly WeakReference $connection;

    private readonly string $dsn;

    private readonly array $config;

    public function __construct(Connection $connection, string $dsn, array $config)
    {
        $this->connection = WeakReference::create($connection);
        $this->dsn = $dsn;
        $this->config = $config;
    }

    /**
     * The owning Connection. It stays alive while this instance does, because
     * the Connection is the only strong reference to it.
     */
    private function connection(): Connection
    {
        return $this->connection->get() ?? throw new LogicException('The owning Connection is no longer available.');
    }

    /**
     * Prepare the driver options for a MongoDB client: validate the automatic
     * encryption configuration and normalize the encryptedFieldsMap early. A
     * broken autoEncryption block fails fast at connection time.
     *
     * @param  array<string, mixed> $driverOptions
     *
     * @return array<string, mixed>
     */
    public function prepareDriverOptions(array $driverOptions): array
    {
        $autoEncryption = $driverOptions['autoEncryption'] ?? null;

        if (! is_array($autoEncryption)) {
            return $driverOptions;
        }

        $autoEncryption = $this->validateAutoEncryptionConfig($autoEncryption);

        // libmongocrypt (>= 1.18.0) resolves a field declared by "keyAltName"
        // to its real keyId from the key vault at runtime, so the package only
        // has to give every field a name (explicit, or the default) and the
        // driver performs the lookup. No key vault query happens at connection
        // time.
        if (is_array($autoEncryption['encryptedFieldsMap'] ?? null)) {
            $autoEncryption['encryptedFieldsMap'] = $this->normalizeEncryptedFieldsMap($autoEncryption['encryptedFieldsMap']);
            $this->ensureAltKeyNameSupport($autoEncryption['encryptedFieldsMap']);
        }

        $driverOptions['autoEncryption'] = $autoEncryption;

        return $driverOptions;
    }

    /**
     * Determine whether automatic encryption (Queryable Encryption or CSFLE)
     * is requested on this connection.
     *
     * @param  array<string, mixed> $config
     */
    public function isEncryptionEnabled(array $config): bool
    {
        return ! empty($config['keyVaultNamespace']);
    }

    /**
     * Determine whether automatic encryption is active on this connection.
     *
     * When a collection name is given, only collections mapped in the
     * encryptedFieldsMap are encrypted; the others keep their usual behavior.
     */
    public function isAutoEncryptionEnabled(?string $collection = null): bool
    {
        $config = $this->connection()->getConfig('driver_options.autoEncryption');

        if (! is_array($config) || ! $this->isEncryptionEnabled($config)) {
            return false;
        }

        if ($collection === null) {
            return true;
        }

        return isset($config['encryptedFieldsMap'][$collection]);
    }

    /**
     * Ensure a mapped collection exists as an encrypted collection before any
     * write. When automatic encryption is configured for a collection that is
     * not created with server-side encryptedFields, writes store the mapped
     * fields in plaintext without any error. This guard fails fast instead,
     * pointing to the encrypted collection creation step. See DRIVERS-3647.
     *
     * Unmapped and non-encrypted collections are ignored. The names of all
     * encrypted collections are fetched once in a single query, then cached,
     * so every mapped collection is validated in one round trip.
     */
    public function ensureEncryptedCollectionReady(string $collection): void
    {
        if (! $this->isAutoEncryptionEnabled($collection)) {
            return;
        }

        if (isset($this->encryptedCollectionNames()[$collection])) {
            return;
        }

        throw new LogicException(
            sprintf('Collection "%s" is mapped for automatic encryption but is not created as an encrypted collection. Run "php artisan mongodb:encrypted:create %s" or "Schema::createEncrypted(\'%s\')" before writing, otherwise the fields are stored in plaintext. See DRIVERS-3647.', $collection, $collection, $collection),
        );
    }

    /**
     * The names of every collection in this database created as an encrypted
     * collection. Loaded lazily from a single listCollections call and cached.
     *
     * @return array<string, true>
     */
    private function encryptedCollectionNames(): array
    {
        if ($this->encryptedCollectionNames !== null) {
            return $this->encryptedCollectionNames;
        }

        $names = [];

        // Read the encrypted collection metadata through a plain manager, as
        // the spec does, instead of the auto-encrypting connection client.
        $database = new Database($this->plainManager(), $this->connection()->getDatabaseName());

        foreach ($database->listCollections(['filter' => ['options.encryptedFields' => ['$exists' => true]]]) as $info) {
            if ($info->getEncryptedFields() !== null) {
                $names[$info->getName()] = true;
            }
        }

        return $this->encryptedCollectionNames = $names;
    }

    /**
     * Validate the shape of the driver_options.autoEncryption configuration and
     * return a normalized copy. This only checks the static configuration; it
     * never contacts the server.
     *
     * @param  array<string, mixed> $autoEncryption
     *
     * @return array<string, mixed>
     */
    public function validateAutoEncryptionConfig(array $autoEncryption): array
    {
        if (empty($autoEncryption['keyVaultNamespace']) || ! is_string($autoEncryption['keyVaultNamespace'])) {
            throw new InvalidArgumentException('The "autoEncryption.keyVaultNamespace" driver option is required to use Queryable Encryption. Configure "database.connections.<name>.driver_options.autoEncryption.keyVaultNamespace".');
        }

        if (empty($autoEncryption['kmsProviders']) || ! is_array($autoEncryption['kmsProviders'])) {
            throw new InvalidArgumentException('The "autoEncryption.kmsProviders" driver option must be a non-empty array to use Queryable Encryption.');
        }

        // Validate the local master key, if the local provider is declared.
        $localProvider = $autoEncryption['kmsProviders']['local'] ?? null;
        if (is_array($localProvider)) {
            $key = $localProvider['key'] ?? null;
            if (! is_string($key)) {
                throw new InvalidArgumentException('The "autoEncryption.kmsProviders.local.key" value is required and must be a base64-encoded 96-byte master key.');
            }

            $decoded = base64_decode($key, true) ?: base64_decode($key);
            if ($decoded === false) {
                throw new InvalidArgumentException('The "autoEncryption.kmsProviders.local.key" value is not valid base64.');
            }

            if (strlen($decoded) !== 96) {
                throw new InvalidArgumentException('The "autoEncryption.kmsProviders.local.key" master key must decode to exactly 96 bytes.');
            }
        }

        // Normalize the crypt_shared settings. The shared library is required
        // for automatic encryption; default it to true unless explicitly
        // disabled and reject an explicitly null library path.
        $extraOptions = is_array($autoEncryption['extraOptions'] ?? null) ? $autoEncryption['extraOptions'] : [];
        $extraOptions += ['cryptSharedLibRequired' => true];

        $hasSearchPath = ! empty($extraOptions['cryptSharedLibPath'])
        || ! empty($extraOptions['cryptSharedSearchPath'])
        || ! empty($extraOptions['cryptSharedSearchPaths']);
        if ($extraOptions['cryptSharedLibRequired'] && ! $hasSearchPath && array_key_exists('cryptSharedLibPath', $extraOptions) && $extraOptions['cryptSharedLibPath'] === null) {
            throw new InvalidArgumentException('The "autoEncryption.extraOptions.cryptSharedLibPath" value cannot be null. Provide the path to the Automatic Encryption Shared Library or a search path.');
        }

        $autoEncryption['extraOptions'] = $extraOptions;

        // A collection mapped for automatic encryption must reference an
        // existing data encryption key. Point to the keys-first bootstrap.
        foreach (($autoEncryption['encryptedFieldsMap'] ?? []) as $collection => $encryptedFields) {
            if (! is_array($encryptedFields)) {
                continue;
            }

            foreach (($encryptedFields['fields'] ?? []) as $field) {
                if (is_array($field) && array_key_exists('keyId', $field) && $field['keyId'] === null) {
                    throw new InvalidArgumentException(sprintf('The encrypted field map for collection "%s" references a field with a null "keyId". Set a "keyAltName" or remove the "keyId" so it is resolved or generated automatically when the collection is created.', $collection));
                }
            }
        }

        return $autoEncryption;
    }

    /**
     * Normalize the encryptedFieldsMap to the driver's list form. Two field
     * syntaxes are accepted: a list of objects with an explicit "path", and an
     * object keyed by path with a flat "queryType". Each field receives its
     * alternate key name (declared, or the default) when it does not carry a
     * keyId.
     *
     * @param  array<string, mixed> $encryptedFieldsMap
     *
     * @return array<string, mixed>
     */
    public function normalizeEncryptedFieldsMap(array $encryptedFieldsMap): array
    {
        foreach ($encryptedFieldsMap as $collection => $encryptedFields) {
            $fields = $encryptedFields['fields'] ?? null;

            if (! is_array($fields)) {
                throw new LogicException(sprintf('The encrypted fields map entry for collection "%s" must define a "fields" array.', $collection));
            }

            $encryptedFieldsMap[$collection]['fields'] = $this->normalizeEncryptedFields($fields, (string) $collection);
        }

        return $encryptedFieldsMap;
    }

    /**
     * Normalize the "fields" of a single collection into the driver's list
     * form, accepting both the list and keyed-by-path syntaxes. A bare string
     * value is the bsonType of a randomized, non-queryable field.
     *
     * @param  array<mixed> $fields
     * @param  string       $collection
     *
     * @return array<int, array<string, mixed>>
     */
    private function normalizeEncryptedFields(array $fields, string $collection): array
    {
        $normalized = [];

        foreach ($fields as $key => $config) {
            // Prefer an explicit path; otherwise the array key is the path.
            $path = is_array($config) && isset($config['path']) && is_string($config['path'])
                ? $config['path']
                : (is_string($key) ? $key : null);
            if ($path === null) {
                throw new LogicException(sprintf('Missing "path" for an encrypted field in collection "%s".', $collection));
            }

            // A bare string value is the bsonType of a randomized field.
            if (is_string($config)) {
                $config = ['bsonType' => $config];
            }

            if (! is_array($config)) {
                throw new LogicException(sprintf('Invalid encrypted field for path "%s" in collection "%s": expected a string bsonType or an array.', $path, $collection));
            }

            $bsonType = $config['bsonType'] ?? null;
            if (! is_string($bsonType) || $bsonType === '') {
                throw new LogicException(sprintf('Missing or invalid "bsonType" for encrypted field "%s" in collection "%s".', $path, $collection));
            }

            if (isset($config['keyId']) && isset($config['keyAltName'])) {
                throw new LogicException(sprintf('Encrypted field "%s" in collection "%s" cannot declare both "keyId" and "keyAltName".', $path, $collection));
            }

            $field = ['path' => $path, 'bsonType' => $bsonType];

            if (isset($config['keyId'])) {
                $field['keyId'] = $config['keyId'];
            }

            if (isset($config['queries']) && is_array($config['queries'])) {
                $field['queries'] = $config['queries'];
            } elseif (isset($config['queryType'])) {
                $queryType = $config['queryType'];
                if (! in_array($queryType, ['equality', 'range'], true)) {
                    throw new LogicException(sprintf('Invalid "queryType" "%s" for encrypted field "%s" in collection "%s": supported values are "equality" and "range".', $queryType, $path, $collection));
                }

                $query = ['queryType' => $queryType];
                foreach (['min', 'max', 'sparsity', 'precision'] as $option) {
                    if (array_key_exists($option, $config)) {
                        $query[$option] = $config[$option];
                    }
                }

                $field['queries'] = [$query];
            }

            if (isset($config['keyAltName']) && is_string($config['keyAltName']) && $config['keyAltName'] !== '') {
                $field['keyAltName'] = $config['keyAltName'];
            } elseif (! array_key_exists('keyId', $field)) {
                $field['keyAltName'] = $this->keyAltNameFor($field, $collection);
            }

            $normalized[] = $field;
        }

        return $normalized;
    }

    /**
     * Compute the alternate key name to use for a field: the declared
     * keyAltName, or "<database>.<collection>/<path>" by default.
     *
     * The database and collection are joined as a MongoDB namespace and the
     * path is separated by a slash. A slash cannot appear in a database or
     * collection name, so the name is unambiguous. See DRIVERS-3637.
     *
     * @param  array<string, mixed> $field
     */
    private function keyAltNameFor(array $field, string $collection): string
    {
        if (isset($field['keyAltName']) && is_string($field['keyAltName']) && $field['keyAltName'] !== '') {
            return $field['keyAltName'];
        }

        return $this->connection()->getDatabaseName() . '.' . $collection . '/' . $field['path'];
    }

    /**
     * Get the client-side encryption support used to generate and manage data
     * encryption keys.
     *
     * This requires automatic encryption to be configured on the connection.
     *
     * @throws InvalidArgumentException when automatic encryption is not enabled.
     */
    public function getClientEncryption(): ClientEncryption
    {
        $autoEncryption = $this->connection()->getConfig('driver_options.autoEncryption');

        if (! is_array($autoEncryption) || ! $this->isEncryptionEnabled($autoEncryption)) {
            throw new InvalidArgumentException('Queryable Encryption is not enabled on this connection. Configure "driver_options.autoEncryption" with a "keyVaultNamespace" and "kmsProviders" first.');
        }

        $config = $this->validateAutoEncryptionConfig($autoEncryption);

        // The key vault client must be free of auto encryption (CSFLE rule),
        // so it cannot be the auto-encryption-enabled connection client.
        return $this->connection()->getClient()->createClientEncryption([
            'keyVaultClient' => $config['keyVaultClient'] ?? $this->plainManager(),
            'keyVaultNamespace' => $config['keyVaultNamespace'],
            'kmsProviders' => $config['kmsProviders'],
        ]);
    }

    /**
     * Get the automatic encryption options configured on this connection.
     *
     * @return array<string, mixed>
     */
    public function getEncryptionOptions(): array
    {
        $autoEncryption = $this->connection()->getConfig('driver_options.autoEncryption');

        return is_array($autoEncryption) ? $autoEncryption : [];
    }

    /**
     * Resolve every field lacking a keyId, generating the data key when it does
     * not exist yet. This makes encrypted collection creation idempotent:
     * re-creating a dropped collection reuses the same keys.
     *
     * @param  array<string, array{fields: list<array<string, mixed>>}> $encryptedFieldsMap
     *
     * @return array<string, array{
     *     fields: list<array{
     *         path: string,
     *         bsonType: string,
     *         keyId: Binary,
     *         queries?: list<array<string, mixed>>,
     *     }>,
     * }>
     */
    public function resolveOrCreateEncryptionKeys(array $encryptedFieldsMap): array
    {
        $config = $this->getEncryptionOptions();
        $clientEncryption = $this->getClientEncryption();
        $kmsProvider = array_key_first($config['kmsProviders']) ?: 'local';

        foreach ($encryptedFieldsMap as $collection => $encryptedFields) {
            $fields = $encryptedFields['fields'] ?? [];

            foreach ($fields as &$field) {
                if (! is_array($field) || isset($field['keyId'])) {
                    continue;
                }

                $keyAltName = $this->keyAltNameFor($field, $collection);
                $existing = $this->findDataKeyByAltName($keyAltName);

                $keyId = $existing instanceof Binary
                    ? $existing
                    : $clientEncryption->createDataKey($kmsProvider, ['keyAltNames' => [$keyAltName]]);

                // The driver accepts only one of keyId or keyAltName on a
                // field; the alternate name has served its purpose.
                $field = ['keyId' => $keyId] + $field;
                unset($field['keyAltName']);
            }

            unset($field);

            $encryptedFields['fields'] = array_values($fields);
            $encryptedFieldsMap[$collection] = $encryptedFields;
        }

        return $encryptedFieldsMap;
    }

    /**
     * Look up the keyId of a data key by its alternate name in the key vault.
     * Uses a direct query rather than ClientEncryption::getKeyByAltName so it
     * works regardless of driver/server support for that helper.
     *
     * @param  string       $keyAltName
     * @param  Manager|null $manager
     */
    private function findDataKeyByAltName(string $keyAltName, ?Manager $manager = null): ?Binary
    {
        $namespace = $this->connection()->getConfig('driver_options.autoEncryption.keyVaultNamespace');

        if (! is_string($namespace) || ! str_contains($namespace, '.')) {
            return null;
        }

        $query = new DriverQuery(['keyAltNames' => $keyAltName]);
        $cursor = ($manager ?? $this->plainManager())->executeQuery($namespace, $query);

        foreach ($cursor as $document) {
            $id = $document->_id ?? null;
            if ($id instanceof Binary) {
                return $id;
            }
        }

        return null;
    }

    /**
     * Get a cached plain (non-auto-encrypted) manager to the same server,
     * used only to reach the key vault.
     */
    private function plainManager(): Manager
    {
        if ($this->plainManager === null) {
            $options = $this->config['options'] ?? [];

            // Apply the top-level credentials, mirroring Connection::createConnection().
            if (! isset($options['username']) && ! empty($this->config['username'])) {
                $options['username'] = $this->config['username'];
            }

            if (! isset($options['password']) && ! empty($this->config['password'])) {
                $options['password'] = $this->config['password'];
            }

            $driverOptions = [
                'driver' => ['name' => 'laravel-mongodb', 'version' => Connection::getVersion()],
            ];

            $this->plainManager = new Manager($this->dsn, $options, $driverOptions);
        }

        return $this->plainManager;
    }

    /**
     * Verify the installed ext-mongodb can resolve encrypted fields by
     * keyAltName (libmongocrypt >= 1.18, i.e. ext-mongodb 2.4.0+). Only
     * checked when an alternate key name is actually used, so keyId-based and
     * non-encrypted configs stay compatible with older extensions.
     *
     * @param  array<string, mixed> $encryptedFieldsMap
     */
    private function ensureAltKeyNameSupport(array $encryptedFieldsMap): void
    {
        foreach ($encryptedFieldsMap as $encryptedFields) {
            foreach (($encryptedFields['fields'] ?? []) as $field) {
                if (! is_array($field) || isset($field['keyId'])) {
                    continue;
                }

                $version = phpversion('mongodb');

                if (is_string($version) && version_compare($version, '2.4.0', '<')) {
                    throw new RuntimeException(sprintf('Referencing encrypted fields by keyAltName requires ext-mongodb 2.4.0 or later (libmongocrypt >= 1.18). Installed version is %s.', $version));
                }

                return;
            }
        }
    }
}
