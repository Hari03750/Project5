using Microsoft.Data.Sqlite;

namespace SafeVault.Data;

/// <summary>
/// Demonstrates a raw ADO.NET query path (e.g. for an admin search screen)
/// and the concrete fix applied for the SQL-injection vulnerability found
/// during the debugging activity.
///
/// VULNERABLE VERSION (do not use — kept here only as a documented example
/// of what Copilot flagged and what was replaced):
///
///     var sql = "SELECT Id, UserName, Email FROM AspNetUsers " +
///               "WHERE UserName = '" + searchTerm + "'";
///     // An attacker could pass:  ' OR '1'='1
///     // which turns the query into a full-table dump.
///
/// FIXED VERSION (below): the search term is always passed as a bound
/// parameter, never concatenated into the SQL text. The database driver
/// treats it strictly as data, so it cannot change the query's structure.
/// </summary>
public class UsersLookupRepository
{
    private readonly string _connectionString;

    public UsersLookupRepository(string connectionString)
    {
        _connectionString = connectionString;
    }

    public async Task<List<(string Id, string UserName, string Email)>> SearchByUserNameAsync(string searchTerm)
    {
        var results = new List<(string, string, string)>();

        // Defense in depth: validate shape/length even though parameterization
        // already neutralizes injection. Rejecting obviously malformed input
        // early also protects against denial-of-service via huge inputs.
        if (string.IsNullOrWhiteSpace(searchTerm) || searchTerm.Length > 256)
        {
            return results;
        }

        await using var connection = new SqliteConnection(_connectionString);
        await connection.OpenAsync();

        await using var command = connection.CreateCommand();
        command.CommandText =
            "SELECT Id, UserName, Email FROM AspNetUsers WHERE UserName LIKE @search LIMIT 25;";

        // Parameter binding — the fix. The value is never concatenated into CommandText.
        command.Parameters.AddWithValue("@search", $"%{searchTerm}%");

        await using var reader = await command.ExecuteReaderAsync();
        while (await reader.ReadAsync())
        {
            results.Add((
                reader.GetString(0),
                reader.IsDBNull(1) ? string.Empty : reader.GetString(1),
                reader.IsDBNull(2) ? string.Empty : reader.GetString(2)));
        }

        return results;
    }
}
