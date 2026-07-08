using Microsoft.Data.Sqlite;
using SafeVault.Data;
using Xunit;

namespace SafeVault.Tests;

/// <summary>
/// Verifies the fix for the SQL-injection vulnerability found in the
/// debugging activity: UsersLookupRepository must treat all search input
/// as data, never as executable SQL, no matter what the caller sends.
/// </summary>
public class SqlInjectionTests : IAsyncLifetime
{
    private SqliteConnection _keepAliveConnection = null!;
    private const string ConnectionString = "DataSource=file:sqlitjection?mode=memory&cache=shared";

    public async Task InitializeAsync()
    {
        // SQLite in-memory DBs are dropped once the last connection closes,
        // so we keep one connection open for the lifetime of the test.
        _keepAliveConnection = new SqliteConnection(ConnectionString);
        await _keepAliveConnection.OpenAsync();

        await using var setup = _keepAliveConnection.CreateCommand();
        setup.CommandText = @"
            CREATE TABLE AspNetUsers (Id TEXT PRIMARY KEY, UserName TEXT, Email TEXT);
            INSERT INTO AspNetUsers VALUES ('1', 'alice', 'alice@example.com');
            INSERT INTO AspNetUsers VALUES ('2', 'bob', 'bob@example.com');
            INSERT INTO AspNetUsers VALUES ('3', 'carol', 'carol@example.com');
        ";
        await setup.ExecuteNonQueryAsync();
    }

    public Task DisposeAsync()
    {
        _keepAliveConnection.Dispose();
        return Task.CompletedTask;
    }

    [Fact]
    public async Task NormalSearch_ReturnsMatchingUser()
    {
        var repo = new UsersLookupRepository(ConnectionString);

        var results = await repo.SearchByUserNameAsync("alice");

        Assert.Single(results);
        Assert.Equal("alice", results[0].UserName);
    }

    [Theory]
    [InlineData("' OR '1'='1")]
    [InlineData("x' UNION SELECT Id, UserName, Email FROM AspNetUsers --")]
    [InlineData("'; DROP TABLE AspNetUsers; --")]
    [InlineData("nonexistent' OR 1=1 --")]
    public async Task InjectionAttempts_DoNotAlterQueryBehavior(string maliciousInput)
    {
        var repo = new UsersLookupRepository(ConnectionString);

        // A parameterized query treats the whole string as a literal search
        // value, so none of these payloads should return the full table
        // (3 rows) or throw — they should just fail to match anything.
        var results = await repo.SearchByUserNameAsync(maliciousInput);

        Assert.True(results.Count < 3, $"Injection payload leaked {results.Count} rows: '{maliciousInput}'");
    }

    [Fact]
    public async Task DropTablePayload_DoesNotActuallyDropTable()
    {
        var repo = new UsersLookupRepository(ConnectionString);

        await repo.SearchByUserNameAsync("'; DROP TABLE AspNetUsers; --");

        // If the injection had worked, this normal query would now fail
        // because the table would no longer exist.
        var stillThere = await repo.SearchByUserNameAsync("bob");
        Assert.Single(stillThere);
    }
}
