namespace Proofdrill.Agent.Tests;

/// <summary>
/// What this agent takes out of a <c>pg_dumpall --globals-only</c> artefact, and
/// — with more force — what it refuses to take.
/// <para>
/// The fixture is not invented. It is the output of <c>pg_dumpall --globals-only</c>
/// from PostgreSQL 17, verbatim, including the <c>\restrict</c> line with its
/// random token, the password verifiers, the <c>GRANTED BY</c> clauses and a
/// tablespace. A parser tested against a tidied-up version of its input is tested
/// against the wrong document.
/// </para>
/// </summary>
public class GlobalsDdlTests
{
    private static readonly string[] Reserved = ["proofdrill", "proofdrill_assert"];

    private const string Artefact = """
        --
        -- PostgreSQL database cluster dump
        --

        \restrict 8Tf1wbfM4bKG918oGyLcCC0DGprly8ONnOxQ7V60ZHPFKsyzCiepjETPJPJNBaW

        SET default_transaction_read_only = off;

        SET client_encoding = 'UTF8';
        SET standard_conforming_strings = on;

        --
        -- Roles
        --

        CREATE ROLE "Reporting Role";
        ALTER ROLE "Reporting Role" WITH NOSUPERUSER INHERIT NOCREATEROLE NOCREATEDB NOLOGIN NOREPLICATION NOBYPASSRLS;
        CREATE ROLE admin_role;
        ALTER ROLE admin_role WITH SUPERUSER INHERIT CREATEROLE CREATEDB LOGIN NOREPLICATION NOBYPASSRLS PASSWORD 'SCRAM-SHA-256$4096:3V3ou7tT1XzrJfjCT/lVbg==$cTA2DKLnqid22ta4aIO4CW3LmWowdFwntfAngSnfPxg=:O+dcPLhaa6qqBwlFfUfR0h1/rhYKkrDx3Q/iaKkRKlM=' VALID UNTIL '2027-01-01 00:00:00+00';
        CREATE ROLE app_role;
        ALTER ROLE app_role WITH NOSUPERUSER INHERIT NOCREATEROLE NOCREATEDB NOLOGIN NOREPLICATION NOBYPASSRLS;
        CREATE ROLE backup_role;
        ALTER ROLE backup_role WITH NOSUPERUSER INHERIT NOCREATEROLE NOCREATEDB LOGIN NOREPLICATION BYPASSRLS PASSWORD 'SCRAM-SHA-256$4096:xhvfAnPiSaKN0+1mmrQGpQ==$KMc7ySSszJkmZGdJ0OlAbDcV5OahQhHntd4zTEf5J1g=:BM9txhSRJI77N33pLG0is7VRqJNIjUGGYjJ9tyDQsig=';
        CREATE ROLE source;
        ALTER ROLE source WITH SUPERUSER INHERIT CREATEROLE CREATEDB LOGIN REPLICATION BYPASSRLS;

        --
        -- User Configurations
        --

        --
        -- User Config "app_role"
        --

        ALTER ROLE app_role SET search_path TO 'public', 'app';

        --
        -- Role memberships
        --

        GRANT app_role TO backup_role WITH INHERIT TRUE GRANTED BY source;
        GRANT pg_read_all_data TO app_role WITH INHERIT TRUE GRANTED BY source;
        GRANT pg_read_server_files TO backup_role WITH INHERIT TRUE GRANTED BY source;

        --
        -- Tablespaces
        --

        CREATE TABLESPACE extra OWNER admin_role LOCATION '/tmp/ts';

        \unrestrict 8Tf1wbfM4bKG918oGyLcCC0DGprly8ONnOxQ7V60ZHPFKsyzCiepjETPJPJNBaW

        --
        -- PostgreSQL database cluster dump complete
        --
        """;

    [Fact]
    public void Every_role_the_artefact_declares_is_read_with_its_attributes()
    {
        var globals = GlobalsDdl.Read(Artefact, Reserved);

        Assert.Equal(
            ["Reporting Role", "admin_role", "app_role", "backup_role", "source"],
            globals.Roles.Select(role => role.Name));

        var backup = globals.Roles.Single(role => role.Name == "backup_role");
        Assert.True(backup.Attributes.BypassRls);
        Assert.True(backup.Attributes.Login);
        Assert.False(backup.Attributes.Superuser);

        var app = globals.Roles.Single(role => role.Name == "app_role");
        Assert.False(app.Attributes.BypassRls);
        Assert.False(app.Attributes.Login);
        Assert.True(app.Attributes.Inherit);
    }

    // The whole product question, reduced to one line: which role in this
    // customer's cluster is exempt from every policy they wrote.
    [Fact]
    public void The_attributes_a_role_actually_holds_are_what_a_sentence_names()
    {
        var globals = GlobalsDdl.Read(Artefact, Reserved);

        Assert.Equal("LOGIN, BYPASSRLS", globals.Roles.Single(r => r.Name == "backup_role").Attributes.Held());
        Assert.Equal("no attributes", globals.Roles.Single(r => r.Name == "app_role").Attributes.Held());
    }

    /// <summary>
    /// The one that would be a real defect. A SCRAM verifier is base64, base64
    /// contains capitals, and a parser that looked for the word SUPERUSER anywhere
    /// in the line would eventually read an attribute out of somebody's password
    /// hash — on one cluster in a thousand, silently, in the direction that says a
    /// role is more privileged than it is.
    /// </summary>
    [Fact]
    public void An_attribute_is_never_read_out_of_a_string_literal()
    {
        var globals = GlobalsDdl.Read(
            """
            CREATE ROLE quiet;
            ALTER ROLE quiet WITH NOSUPERUSER INHERIT NOCREATEROLE NOCREATEDB NOLOGIN NOREPLICATION NOBYPASSRLS PASSWORD 'SCRAM-SHA-256$4096:SUPERUSER BYPASSRLS CREATEROLE==$x:y';
            """, Reserved);

        var role = Assert.Single(globals.Roles);
        Assert.Equal("no attributes", role.Attributes.Held());
    }

    [Fact]
    public void A_password_verifier_is_never_applied_and_never_re_emitted()
    {
        var statements = GlobalsDdl.Statements(GlobalsDdl.Read(Artefact, Reserved));

        Assert.DoesNotContain(statements, statement =>
            statement.Contains("PASSWORD", StringComparison.OrdinalIgnoreCase));
        Assert.DoesNotContain(statements, statement =>
            statement.Contains("SCRAM", StringComparison.OrdinalIgnoreCase));
        Assert.DoesNotContain(statements, statement =>
            statement.Contains("VALID UNTIL", StringComparison.OrdinalIgnoreCase));
    }

    // Engineering rule 4. A LOCATION is a directory on somebody else's machine,
    // outside the working directory this agent promised to stay inside.
    [Fact]
    public void A_tablespace_is_refused_and_said_out_loud()
    {
        var globals = GlobalsDdl.Read(Artefact, Reserved);

        Assert.DoesNotContain(GlobalsDdl.Statements(globals), statement =>
            statement.Contains("TABLESPACE", StringComparison.OrdinalIgnoreCase));
        Assert.Contains(globals.Refused, sentence => sentence.Contains("tablespace", StringComparison.Ordinal));
    }

    [Fact]
    public void A_per_role_server_parameter_is_refused_and_said_out_loud()
    {
        var globals = GlobalsDdl.Read(Artefact, Reserved);

        Assert.DoesNotContain(GlobalsDdl.Statements(globals), statement =>
            statement.Contains("search_path", StringComparison.Ordinal));
        Assert.Contains(globals.Refused, sentence => sentence.Contains("per-role setting", StringComparison.Ordinal));
    }

    /// <summary>
    /// <c>ASSERTIONS.md</c> §3 promises a customer statement cannot read a file or
    /// run a program on the machine the agent is installed on. An assertion names
    /// a role in its <c>as</c>, and a pack can arrive from the control plane — so
    /// that promise must not depend on what a customer's globals file grants.
    /// </summary>
    [Fact]
    public void Membership_of_a_machine_access_role_is_refused_and_the_readable_one_is_kept()
    {
        var globals = GlobalsDdl.Read(Artefact, Reserved);
        var statements = GlobalsDdl.Statements(globals);

        Assert.DoesNotContain(statements, statement =>
            statement.Contains("pg_read_server_files", StringComparison.Ordinal));
        Assert.Contains(globals.Refused, sentence =>
            sentence.Contains("machine-access", StringComparison.Ordinal));

        // pg_read_all_data reads every table and is NOT exempt from row level
        // security, so a role that has it in production has it here: the fidelity
        // is worth having and it takes nothing away.
        Assert.Contains(statements, statement =>
            statement.Contains("GRANT \"pg_read_all_data\" TO \"app_role\"", StringComparison.Ordinal));
    }

    [Fact]
    public void A_membership_keeps_its_options_and_loses_its_grantor()
    {
        var statements = GlobalsDdl.Statements(GlobalsDdl.Read(Artefact, Reserved));

        Assert.Contains(
            "GRANT \"app_role\" TO \"backup_role\" WITH INHERIT TRUE",
            statements);
        Assert.DoesNotContain(statements, statement =>
            statement.Contains("GRANTED BY", StringComparison.Ordinal));
    }

    [Fact]
    public void A_role_name_with_a_space_in_it_survives_being_read_and_written()
    {
        var statements = GlobalsDdl.Statements(GlobalsDdl.Read(Artefact, Reserved));

        Assert.Contains(statements, statement =>
            statement.StartsWith("CREATE ROLE \"Reporting Role\" WITH ", StringComparison.Ordinal));
    }

    /// <summary>
    /// Every attribute is written out, including the five that are usually absent.
    /// A CREATE ROLE that leaves an attribute to PostgreSQL's default applies a
    /// default and reports a declaration, and the comparison after it would be
    /// asserting that our default matches our default.
    /// </summary>
    [Fact]
    public void A_role_is_created_with_all_seven_attributes_and_no_default_is_relied_on()
    {
        var statements = GlobalsDdl.Statements(GlobalsDdl.Read(Artefact, Reserved));
        var created = statements.Single(statement =>
            statement.StartsWith("CREATE ROLE \"backup_role\"", StringComparison.Ordinal));

        Assert.Equal(
            "CREATE ROLE \"backup_role\" WITH NOSUPERUSER INHERIT NOCREATEROLE NOCREATEDB LOGIN NOREPLICATION BYPASSRLS",
            created);
    }

    [Fact]
    public void The_clusters_own_roles_are_not_rewritten_by_a_file_out_of_a_bucket()
    {
        var globals = GlobalsDdl.Read(
            """
            CREATE ROLE proofdrill;
            ALTER ROLE proofdrill WITH NOSUPERUSER NOINHERIT NOCREATEROLE NOCREATEDB NOLOGIN NOREPLICATION NOBYPASSRLS;
            CREATE ROLE pg_signal_backend;
            CREATE ROLE ordinary;
            """, Reserved);

        Assert.Equal("ordinary", Assert.Single(globals.Roles).Name);
        Assert.Contains(globals.Refused, sentence =>
            sentence.Contains("proofdrill", StringComparison.Ordinal)
            && sentence.Contains("pg_signal_backend", StringComparison.Ordinal));
    }

    /// <summary>
    /// A file that is not a globals artefact produces no roles and says how many
    /// statements it did not understand — which is what a customer sees when the
    /// globals pattern is pointed at the wrong object in the bucket.
    /// </summary>
    [Fact]
    public void A_file_that_is_not_a_globals_artefact_yields_nothing_and_reports_it()
    {
        var globals = GlobalsDdl.Read(
            """
            CREATE TABLE public.orders (id bigint PRIMARY KEY);
            COPY public.orders (id) FROM stdin;
            """, Reserved);

        Assert.Empty(globals.Roles);
        Assert.True(globals.IsEmpty);
        Assert.Contains(globals.Refused, sentence =>
            sentence.Contains("does not apply", StringComparison.Ordinal));
    }

    [Fact]
    public void A_shape_this_agent_has_not_seen_is_reported_rather_than_half_read()
    {
        var globals = GlobalsDdl.Read("GRANT reader, writer TO app_role;", Reserved);

        Assert.Empty(globals.Memberships);
        Assert.Contains(globals.Refused, sentence =>
            sentence.Contains("does not apply", StringComparison.Ordinal));
    }

    [Fact]
    public void Two_readings_of_a_role_name_every_attribute_they_disagree_about()
    {
        var declared = new RoleAttributes(false, true, false, false, false, false, false);
        var actual = declared with { BypassRls = true, Superuser = true };

        Assert.Equal(
            [
                "SUPERUSER was not declared and is held",
                "BYPASSRLS was not declared and is held",
            ],
            declared.Differences(actual));

        Assert.Empty(declared.Differences(declared));
    }
}
