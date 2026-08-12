namespace Proofdrill.Agent.Tests;

/// <summary>
/// The comparison that level 3 rests on. These tests exist because the container
/// suite could not make it fail: manufacturing a restore that legitimately loses
/// a guarantee is either contrived or closed by the agent itself, so the
/// negative direction was asserted nowhere. It is asserted here.
/// <para>
/// Half of them are about the canonicalisation NOT working — a normaliser that
/// makes two different databases look the same is worse than no comparison at
/// all, because it reports the guarantee as intact.
/// </para>
/// </summary>
public class SecurityDdlTests
{
    private const string Rls = "ALTER TABLE public.tenant_rows ENABLE ROW LEVEL SECURITY;";
    private const string Forced = "ALTER TABLE public.tenant_rows FORCE ROW LEVEL SECURITY;";

    [Fact]
    public void Extracts_the_statements_that_carry_guarantees_and_nothing_else()
    {
        var set = SecurityDdl.Extract($"""
            CREATE TABLE public.tenant_rows (id bigint NOT NULL);
            ALTER TABLE public.tenant_rows OWNER TO app_owner;
            {Rls}
            {Forced}
            CREATE POLICY tenant_isolation ON public.tenant_rows USING ((tenant_id IS NOT NULL));
            GRANT SELECT ON TABLE public.tenant_rows TO app_role;
            CREATE INDEX ix_rows ON public.tenant_rows USING btree (id);
            """);

        Assert.Equal(2, set.RowLevelSecurity.Count);
        Assert.Single(set.Policies);
        Assert.Single(set.Grants);
    }

    [Fact]
    public void A_statement_split_across_lines_equals_the_same_statement_on_one()
    {
        var wrapped = SecurityDdl.Extract("""
            CREATE POLICY tenant_isolation ON public.tenant_rows
                USING ((tenant_id IS NOT NULL));
            """);

        var single = SecurityDdl.Extract(
            "CREATE POLICY tenant_isolation ON public.tenant_rows USING ((tenant_id IS NOT NULL));");

        Assert.Equal(single.Policies, wrapped.Policies);
    }

    // The OID finding. A policy's roles are stored as an array of OIDs and
    // printed in OID order, which is the order the TARGET cluster happened to
    // create them in — so the same policy comes back with its roles reversed.
    [Fact]
    public void The_order_of_roles_in_a_TO_clause_is_not_a_difference()
    {
        var declared = SecurityDdl.Extract(
            "CREATE POLICY p ON public.t FOR SELECT TO app_role, \"Reporting Role\" USING (true);");
        var restored = SecurityDdl.Extract(
            "CREATE POLICY p ON public.t FOR SELECT TO \"Reporting Role\", app_role USING (true);");

        Assert.Empty(Ddl.Difference(declared.Policies, restored.Policies).Lost);
        Assert.Empty(Ddl.Difference(declared.Policies, restored.Policies).Gained);
    }

    // And the other half of that fix: sorting a set must not blind the comparison
    // to a set whose CONTENTS changed.
    [Fact]
    public void A_different_role_in_a_TO_clause_is_still_a_difference()
    {
        var declared = SecurityDdl.Extract("CREATE POLICY p ON public.t FOR SELECT TO app_role USING (true);");
        var restored = SecurityDdl.Extract("CREATE POLICY p ON public.t FOR SELECT TO other_role USING (true);");

        var (lost, gained) = Ddl.Difference(declared.Policies, restored.Policies);

        Assert.Single(lost);
        Assert.Single(gained);
        Assert.Contains("app_role", lost[0], StringComparison.Ordinal);
    }

    [Fact]
    public void An_extra_role_in_a_TO_clause_is_still_a_difference()
    {
        var declared = SecurityDdl.Extract("CREATE POLICY p ON public.t FOR SELECT TO app_role USING (true);");
        var restored = SecurityDdl.Extract(
            "CREATE POLICY p ON public.t FOR SELECT TO app_role, extra_role USING (true);");

        Assert.NotEmpty(Ddl.Difference(declared.Policies, restored.Policies).Lost);
    }

    [Fact]
    public void The_order_of_privileges_in_a_grant_is_not_a_difference()
    {
        var declared = SecurityDdl.Extract("GRANT SELECT, INSERT ON TABLE public.t TO app_role;");
        var restored = SecurityDdl.Extract("GRANT INSERT, SELECT ON TABLE public.t TO app_role;");

        Assert.Empty(Ddl.Difference(declared.Grants, restored.Grants).Lost);
    }

    [Fact]
    public void A_privilege_that_was_not_granted_before_is_a_difference()
    {
        var declared = SecurityDdl.Extract("GRANT SELECT ON TABLE public.t TO app_role;");
        var restored = SecurityDdl.Extract("GRANT SELECT, DELETE ON TABLE public.t TO app_role;");

        Assert.NotEmpty(Ddl.Difference(declared.Grants, restored.Grants).Gained);
    }

    // The canonicaliser must not reach inside an expression. `TO` is an ordinary
    // English word and it turns up in data.
    [Fact]
    public void A_TO_inside_a_policy_expression_is_left_alone()
    {
        var declared = SecurityDdl.Extract(
            "CREATE POLICY p ON public.t USING ((status = 'ASSIGNED TO billing'::text));");
        var restored = SecurityDdl.Extract(
            "CREATE POLICY p ON public.t USING ((status = 'ASSIGNED TO billing'::text));");

        Assert.Empty(Ddl.Difference(declared.Policies, restored.Policies).Lost);
        Assert.Contains("ASSIGNED TO billing", declared.Policies.Single(), StringComparison.Ordinal);
    }

    // The product's headline failure, in the smallest form it can take: the
    // switch is still on and the second one is gone. Enabled leaves the owner
    // exempt; forced does not. Losing FORCE alone loses the guarantee.
    [Fact]
    public void Losing_FORCE_while_keeping_ENABLE_is_detected()
    {
        var declared = SecurityDdl.Extract($"{Rls}\n{Forced}");
        var restored = SecurityDdl.Extract(Rls);

        var (lost, gained) = Ddl.Difference(declared.RowLevelSecurity, restored.RowLevelSecurity);

        Assert.Single(lost);
        Assert.Contains("FORCE", lost[0], StringComparison.Ordinal);
        Assert.Empty(gained);
    }

    [Fact]
    public void A_policy_that_appeared_is_reported_as_well_as_one_that_was_lost()
    {
        var declared = SecurityDdl.Extract("CREATE POLICY kept ON public.t USING (true);");
        var restored = SecurityDdl.Extract("""
            CREATE POLICY kept ON public.t USING (true);
            CREATE POLICY appeared ON public.t USING (true);
            """);

        var (lost, gained) = Ddl.Difference(declared.Policies, restored.Policies);

        Assert.Empty(lost);
        Assert.Single(gained);
        Assert.Contains("appeared", gained[0], StringComparison.Ordinal);
    }

    [Fact]
    public void Identical_sets_compare_equal_in_both_directions()
    {
        var ddl = $"{Rls}\n{Forced}\nCREATE POLICY p ON public.t USING (true);";
        var (lost, gained) = Ddl.Difference(
            SecurityDdl.Extract(ddl).Policies, SecurityDdl.Extract(ddl).Policies);

        Assert.Empty(lost);
        Assert.Empty(gained);
    }

    // The defect the statement splitter closed, on the product's central check.
    // A policy expression can carry a semicolon inside a literal; read up to the
    // first one, these two truncate to the same text, compare EQUAL, and the
    // report says the guarantee survived the restore.
    [Fact]
    public void Two_policies_that_differ_after_a_semicolon_in_a_literal_are_not_equal()
    {
        var declared = SecurityDdl.Extract("CREATE POLICY p ON t USING ((tag = 'a;keep'::text));");
        var restored = SecurityDdl.Extract("CREATE POLICY p ON t USING ((tag = 'a;lost'::text));");

        Assert.Single(Ddl.Difference(declared.Policies, restored.Policies).Lost);
    }

    [Fact]
    public void A_revoke_is_a_guarantee_too()
    {
        var set = SecurityDdl.Extract("REVOKE ALL ON TABLE public.audit_events FROM app_role;");

        Assert.Single(set.Grants);
        Assert.Contains("REVOKE", set.Grants.Single(), StringComparison.Ordinal);
    }
}
