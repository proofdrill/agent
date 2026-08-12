namespace Proofdrill.Agent.Tests;

/// <summary>
/// The splitter every comparison in this agent stands on.
/// <para>
/// Its whole reason for existing is the first two tests: a function body and a
/// string literal both carry semicolons, and a pattern that stops at the first
/// one truncates BOTH sides of a comparison at the same wrong place. That does
/// not produce a false alarm — it produces a false <em>pass</em>, on a report
/// that says the database came back intact.
/// </para>
/// </summary>
public class DdlTests
{
    [Fact]
    public void A_semicolon_inside_a_function_body_does_not_end_the_statement()
    {
        var statements = Ddl.Split("""
            CREATE FUNCTION public.touch() RETURNS trigger
                LANGUAGE plpgsql
                AS $$
            BEGIN
              NEW.updated_at := now();
              RETURN NEW;
            END;
            $$;
            CREATE TRIGGER t BEFORE UPDATE ON public.rows FOR EACH ROW EXECUTE FUNCTION public.touch();
            """);

        Assert.Equal(2, statements.Count);
        Assert.Contains("RETURN NEW;", statements[0], StringComparison.Ordinal);
        Assert.StartsWith("CREATE TRIGGER", statements[1], StringComparison.Ordinal);
    }

    // The defect this replaced, in the smallest form it can take. Truncated at
    // the first semicolon these two are the same string, and a drill would report
    // that the function survived the restore unchanged.
    [Fact]
    public void Two_functions_that_differ_only_after_the_first_semicolon_are_not_equal()
    {
        var one = Ddl.Split("CREATE FUNCTION f() RETURNS int AS $$ BEGIN x; RETURN 1; END; $$;").Single();
        var other = Ddl.Split("CREATE FUNCTION f() RETURNS int AS $$ BEGIN x; RETURN 2; END; $$;").Single();

        Assert.NotEqual(one, other);
    }

    [Fact]
    public void A_semicolon_inside_a_string_literal_does_not_end_the_statement()
    {
        var statements = Ddl.Split(
            "CREATE POLICY p ON t USING ((tag = 'a;b'::text)); CREATE POLICY q ON t USING (true);");

        Assert.Equal(2, statements.Count);
        Assert.Contains("'a;b'", statements[0], StringComparison.Ordinal);
    }

    [Fact]
    public void A_doubled_quote_is_content_and_not_the_end_of_the_literal()
    {
        var statement = Ddl.Split("CREATE POLICY p ON t USING ((note = 'it''s; fine'::text));").Single();

        Assert.Contains("'it''s; fine'", statement, StringComparison.Ordinal);
    }

    [Fact]
    public void A_semicolon_inside_a_quoted_identifier_does_not_end_the_statement()
    {
        var statements = Ddl.Split("""GRANT SELECT ON TABLE public."odd;name" TO app_role;""");

        Assert.Single(statements);
        Assert.Contains("\"odd;name\"", statements[0], StringComparison.Ordinal);
    }

    [Fact]
    public void Comments_are_dropped_and_leave_a_space_behind_them()
    {
        var statements = Ddl.Split("""
            -- the table
            CREATE TABLE t ( -- a column
              id bigint /* and a note */ NOT NULL
            );
            """);

        Assert.Equal("CREATE TABLE t ( id bigint NOT NULL )", statements.Single());
    }

    [Fact]
    public void Block_comments_nest_the_way_PostgreSQL_nests_them()
    {
        Assert.Equal("SELECT 1", Ddl.Split("SELECT /* outer /* inner */ still a comment */ 1;").Single());
    }

    // Whitespace outside quoted text is not information; inside it, it is data.
    // A normaliser that could not tell 'a  b' from 'a b' would be reporting a
    // database it had not read.
    [Fact]
    public void Whitespace_is_collapsed_outside_quotes_and_kept_inside_them()
    {
        var statement = Ddl.Split("""
            CREATE POLICY   p ON t
                USING ((note = 'two  spaces'::text));
            """).Single();

        Assert.Equal("CREATE POLICY p ON t USING ((note = 'two  spaces'::text))", statement);
    }

    // `$1` is a parameter reference. Read as a dollar quote it would swallow
    // everything up to the next `$`, and the statement after it with it.
    [Fact]
    public void A_positional_parameter_is_not_a_dollar_quote()
    {
        var statements = Ddl.Split("""
            CREATE POLICY p ON t USING ((id = $1));
            CREATE POLICY q ON t USING (true);
            """);

        Assert.Equal(2, statements.Count);
    }

    [Fact]
    public void A_tagged_dollar_quote_ends_only_at_its_own_tag()
    {
        var statement = Ddl.Split("CREATE FUNCTION f() RETURNS text AS $body$ SELECT $$x$$; $body$;").Single();

        Assert.Contains("$$x$$;", statement, StringComparison.Ordinal);
    }

    // What pg_dump has actually written since 17.6, and the token is different in
    // every dump. Attached to the statement beside it, it would make that
    // statement differ from its own artefact on every drill ever run.
    [Fact]
    public void A_psql_meta_command_is_not_part_of_the_statement_beside_it()
    {
        var statements = Ddl.Split("""
            \restrict F0EfCvFwNje3LSdv3LCCRhQ8h9eQktMqwFCH5fn2Uhqd8feWKouZtfaYwLJO5Ao
            SET client_encoding = 'UTF8';
            CREATE TABLE t (id bigint);
            \unrestrict F0EfCvFwNje3LSdv3LCCRhQ8h9eQktMqwFCH5fn2Uhqd8feWKouZtfaYwLJO5Ao
            """);

        Assert.Equal(["SET client_encoding = 'UTF8'", "CREATE TABLE t (id bigint)"], statements);
    }

    // Only at the start of a line, because that is the only place psql reads one
    // — and a backslash is an ordinary character everywhere else.
    [Fact]
    public void A_backslash_inside_a_statement_is_left_alone()
    {
        var statement = Ddl.Split(@"CREATE POLICY p ON t USING ((path = 'C:\dir'::text));").Single();

        Assert.Contains(@"'C:\dir'", statement, StringComparison.Ordinal);
    }

    [Fact]
    public void An_empty_statement_is_not_a_statement()
    {
        Assert.Empty(Ddl.Split(";;\n  \n;"));
    }

    [Fact]
    public void What_follows_the_last_semicolon_is_still_a_statement()
    {
        // A script that ends without one is malformed, and dropping its last
        // statement silently would hide an object rather than report it.
        Assert.Equal(["SELECT 1", "SELECT 2"], Ddl.Split("SELECT 1; SELECT 2"));
    }
}
