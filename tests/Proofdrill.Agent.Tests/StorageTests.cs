using Proofdrill.Agent.Storage;

namespace Proofdrill.Agent.Tests;

public class ArtefactLocatorTests
{
    private static StoredObject Object(string key, string when, long size = 1024) =>
        new(key, size, DateTimeOffset.Parse(when, System.Globalization.CultureInfo.InvariantCulture));

    [Fact]
    public void The_newest_artefact_is_chosen_by_the_storage_clock_and_never_by_the_name()
    {
        // The names sort the wrong way round on purpose. A backup script that
        // changes its date format one day would otherwise silently start drilling
        // an artefact from months ago, and the report would be green.
        var objects = new[]
        {
            Object("backups/2026-08-11.dump", "2026-01-01T00:00:00Z"),
            Object("backups/01-01-2026.dump", "2026-08-11T00:00:00Z"),
        };

        Assert.Equal("backups/01-01-2026.dump", ArtefactLocator.Newest(objects, "*.dump")!.Key);
    }

    [Fact]
    public void The_pattern_matches_the_file_name_and_not_the_whole_key()
    {
        var objects = new[] { Object("nightly/production/db-2026-08-11.dump", "2026-08-11T00:00:00Z") };

        Assert.NotNull(ArtefactLocator.Newest(objects, "db-*.dump"));
    }

    [Fact]
    public void Objects_that_do_not_match_are_not_candidates()
    {
        var objects = new[]
        {
            Object("backups/README.txt", "2026-08-11T10:00:00Z"),
            Object("backups/db-2026-08-10.dump", "2026-08-10T00:00:00Z"),
        };

        // The newest object in the bucket is the readme. The newest ARTEFACT is not.
        Assert.Equal("backups/db-2026-08-10.dump", ArtefactLocator.Newest(objects, "*.dump")!.Key);
    }

    [Fact]
    public void Nothing_matching_is_null_rather_than_the_nearest_thing()
    {
        Assert.Null(ArtefactLocator.Newest([Object("backups/notes.txt", "2026-08-11T00:00:00Z")], "*.dump"));
    }

    [Theory]
    [InlineData("db-*.dump", "db-2026-08-11.dump", true)]
    [InlineData("db-*.dump", "db-.dump", true)]
    [InlineData("db-*.dump", "other.dump", false)]
    [InlineData("db-?.dump", "db-1.dump", true)]
    [InlineData("db-?.dump", "db-12.dump", false)]
    [InlineData("*.dump", "archive.dump.gz", false)]
    // A dot is a literal in a glob and a wildcard in a regular expression. If the
    // translation forgets to escape it, `*.dump` also matches `archiveXdump`.
    [InlineData("*.dump", "archiveXdump", false)]
    public void The_glob_is_a_glob_and_not_a_regular_expression(string pattern, string name, bool matches)
    {
        Assert.Equal(matches, ArtefactLocator.Matcher(pattern).IsMatch(name));
    }
}

public class SigV4Tests
{
    // The canonical path is where a signer usually goes wrong, and the failure is
    // a 403 that reads exactly like bad credentials — which sends people to
    // rotate a key that was never the problem.
    [Fact]
    public void Slashes_separate_segments_and_are_not_encoded()
    {
        Assert.Equal("/nightly/production/db.dump",
            SigV4.CanonicalPath(new Uri("https://storage.example.com/nightly/production/db.dump")));
    }

    [Fact]
    public void A_space_in_a_key_is_percent_encoded_and_never_a_plus()
    {
        Assert.Equal("/backups/db%20latest.dump",
            SigV4.CanonicalPath(new Uri("https://storage.example.com/backups/db latest.dump")));
    }

    [Fact]
    public void The_characters_S3_keys_actually_contain_survive_correctly()
    {
        // Unreserved characters must NOT be encoded, and everything else must be.
        Assert.Equal("/a-b_c.d~e/f%2Bg%3Ah",
            SigV4.CanonicalPath(new Uri("https://storage.example.com/a-b_c.d~e/f+g:h")));
    }

    [Fact]
    public void An_empty_path_is_a_single_slash()
    {
        Assert.Equal("/", SigV4.CanonicalPath(new Uri("https://storage.example.com")));
    }

    [Fact]
    public void Query_parameters_are_sorted_by_name_and_encoded()
    {
        Assert.Equal("continuation-token=a%2Fb&list-type=2&prefix=nightly%2F",
            SigV4.CanonicalQuery(new Uri(
                "https://s.example.com/b?list-type=2&prefix=nightly%2F&continuation-token=a%2Fb")));
    }

    [Fact]
    public void A_parameter_without_a_value_still_has_its_equals_sign()
    {
        Assert.Equal("acl=", SigV4.CanonicalQuery(new Uri("https://s.example.com/b?acl")));
    }

    [Fact]
    public void No_query_is_an_empty_string_and_not_a_question_mark()
    {
        Assert.Equal("", SigV4.CanonicalQuery(new Uri("https://s.example.com/b")));
    }
}
