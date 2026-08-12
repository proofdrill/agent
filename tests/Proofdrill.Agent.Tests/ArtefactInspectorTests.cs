namespace Proofdrill.Agent.Tests;

/// <summary>
/// Reading an artefact's table of contents and its DDL. Both parsers are
/// heuristics over text, which is exactly why they are pinned here: the cost of
/// getting one wrong is a role that is not created, and a role that is not
/// created is a policy that does not restore.
/// </summary>
public class ArtefactInspectorTests
{
    // The shape pg_restore --list actually writes.
    private const string TableOfContents = """
        ;
        ; Archive created at 2026-08-11 10:00:00 UTC
        ;     dbname: production
        ;     Dumped from database version: 17.10
        ;
        216; 1259 16389 TABLE public tenant_rows app_owner
        217; 1259 16400 TABLE public invoices app_owner
        3395; 0 16389 TABLE DATA public tenant_rows app_owner
        3400; 0 0 ACL public TABLE tenant_rows -
        """;

    [Fact]
    public void Reads_the_tables_an_artefact_declares()
    {
        Assert.Equal(["public.invoices", "public.tenant_rows"], ArtefactInspector.ParseTables(TableOfContents));
    }

    // TABLE and TABLE DATA are different entries whose first word is the same. A
    // positional read of the description gets this wrong and reports one table
    // twice while missing that its rows are a separate entry.
    [Fact]
    public void TABLE_DATA_is_not_mistaken_for_a_table()
    {
        Assert.DoesNotContain("public.DATA", ArtefactInspector.ParseTables(TableOfContents));
        Assert.Equal(2, ArtefactInspector.ParseTables(TableOfContents).Count);
    }

    [Fact]
    public void Comment_lines_and_blank_lines_are_ignored()
    {
        Assert.Empty(ArtefactInspector.ParseTables("""
            ;
            ; Dumped from database version: 17.10

            """));
    }

    [Fact]
    public void The_owner_is_the_last_field_of_an_entry()
    {
        Assert.Contains("app_owner", ArtefactInspector.ParseReferencedRoles(TableOfContents, ""));
    }

    [Fact]
    public void A_bare_hyphen_is_pg_restores_way_of_saying_no_owner()
    {
        Assert.DoesNotContain("-", ArtefactInspector.ParseReferencedRoles(TableOfContents, ""));
    }

    // Copied from a real `pg_restore --list`, trailing space included, because
    // the trailing space IS the finding: pg_restore prints the owner as an empty
    // field for an object that has none. Read as "the last thing on the line",
    // the extension's own name becomes a role, and the report tells the customer
    // their artefact references a role called pgcrypto.
    [Fact]
    public void An_extension_is_not_a_role()
    {
        var roles = ArtefactInspector.ParseReferencedRoles(
            "2; 3079 16386 EXTENSION - pgcrypto \n3447; 0 0 COMMENT - EXTENSION pgcrypto \n", "");

        Assert.Empty(roles);
    }

    [Fact]
    public void Grantees_are_read_from_the_ddl_because_the_contents_do_not_record_them()
    {
        var roles = ArtefactInspector.ParseReferencedRoles(
            "", "GRANT SELECT ON TABLE public.t TO reader, writer;");

        Assert.Contains("reader", roles);
        Assert.Contains("writer", roles);
    }

    [Fact]
    public void A_revoked_role_is_a_role_that_has_to_exist_too()
    {
        Assert.Contains("app_role", ArtefactInspector.ParseReferencedRoles(
            "", "REVOKE ALL ON TABLE public.t FROM app_role;"));
    }

    [Fact]
    public void An_owner_named_in_the_ddl_is_read()
    {
        Assert.Contains("schema_owner", ArtefactInspector.ParseReferencedRoles(
            "", "ALTER TABLE public.t OWNER TO schema_owner;"));
    }

    // The gap that produced a real defect: a policy naming a role which does not
    // exist does not restore, and what is left is a table with row level security
    // enabled and no policy on it.
    [Fact]
    public void A_policys_own_TO_clause_names_roles_that_must_exist()
    {
        var roles = ArtefactInspector.ParseReferencedRoles(
            "", "CREATE POLICY p ON public.t FOR SELECT TO app_role USING (true);");

        Assert.Contains("app_role", roles);
    }

    [Fact]
    public void A_quoted_role_name_with_a_space_is_an_ordinary_role_name()
    {
        var roles = ArtefactInspector.ParseReferencedRoles(
            "", "CREATE POLICY p ON public.t FOR SELECT TO \"Reporting Role\" USING (true);");

        Assert.Contains("Reporting Role", roles);
    }

    [Fact]
    public void PUBLIC_is_everybody_and_not_a_role_that_has_to_be_created()
    {
        Assert.DoesNotContain("PUBLIC", ArtefactInspector.ParseReferencedRoles(
            "", "GRANT SELECT ON TABLE public.t TO PUBLIC;"));
    }

    // A trailing WITH clause is not part of the role's name. Read as one, it
    // becomes `app_role WITH GRANT OPTION`, the identifier filter throws it away
    // for containing spaces, and the role is never created — so the grant that
    // needs it does not restore.
    [Fact]
    public void A_trailing_WITH_GRANT_OPTION_is_not_part_of_the_role_name()
    {
        var roles = ArtefactInspector.ParseReferencedRoles(
            "", "GRANT SELECT ON TABLE public.t TO app_role WITH GRANT OPTION;");

        Assert.Equal(["app_role"], roles);
    }

    // A wrong role name in a report is worse than a missing one: it sends
    // somebody looking for a role that never existed.
    [Fact]
    public void An_unquoted_fragment_with_whitespace_is_a_parse_that_went_wrong_and_is_dropped()
    {
        Assert.Empty(ArtefactInspector.ParseReferencedRoles("", "GRANT SELECT ON TABLE public.t TO a b c;"));
    }

    [Fact]
    public void Every_role_is_reported_once_however_many_times_it_appears()
    {
        var roles = ArtefactInspector.ParseReferencedRoles(TableOfContents, """
            ALTER TABLE public.tenant_rows OWNER TO app_owner;
            GRANT SELECT ON TABLE public.tenant_rows TO app_owner;
            """);

        Assert.Single(roles, role => role == "app_owner");
    }
}
