namespace Proofdrill.Agent.Tests;

/// <summary>
/// Level 2 — is it still that database? The container suite drills a real
/// artefact and watches these pass; what it cannot manufacture is a restore that
/// legitimately loses a constraint, so the negative direction is asserted here,
/// exactly as it is for level 3 in <see cref="SecurityDdlTests"/>.
/// </summary>
public class SchemaDdlTests
{
    private const string Dump = """
        SET client_encoding = 'UTF8';
        CREATE EXTENSION IF NOT EXISTS pgcrypto WITH SCHEMA public;
        CREATE TABLE public.orders (
            id bigint NOT NULL,
            customer_id bigint NOT NULL,
            total numeric(12,2) NOT NULL,
            CONSTRAINT orders_total_positive CHECK ((total > (0)::numeric))
        );
        CREATE SEQUENCE public.orders_id_seq AS bigint START WITH 1 INCREMENT BY 1 NO MINVALUE NO MAXVALUE CACHE 1;
        ALTER SEQUENCE public.orders_id_seq OWNED BY public.orders.id;
        CREATE FUNCTION public.touch() RETURNS trigger LANGUAGE plpgsql AS $$
        BEGIN
          NEW.updated_at := now();
          RETURN NEW;
        END;
        $$;
        ALTER TABLE ONLY public.orders ADD CONSTRAINT orders_pkey PRIMARY KEY (id);
        ALTER TABLE ONLY public.orders
            ADD CONSTRAINT orders_customer_fkey FOREIGN KEY (customer_id) REFERENCES public.customers(id);
        CREATE TRIGGER orders_touch BEFORE UPDATE ON public.orders
            FOR EACH ROW EXECUTE FUNCTION public.touch();
        CREATE INDEX orders_customer_ix ON public.orders USING btree (customer_id);
        ALTER TABLE public.orders OWNER TO app_owner;
        """;

    [Fact]
    public void Each_family_is_read_out_of_the_same_dump()
    {
        var set = SchemaDdl.Extract(Dump);

        Assert.Single(set.Extensions);
        Assert.Single(set.Tables);
        Assert.Equal(2, set.Sequences.Count);
        Assert.Single(set.Functions);
        Assert.Single(set.Triggers);
        Assert.Equal("UTF8", set.Encoding);
    }

    // A foreign key is a constraint, and it is counted separately because it is
    // the one whose silent absence has a name: a data-only restore leaves the
    // rows in place and the references unenforced.
    [Fact]
    public void A_foreign_key_is_not_counted_among_the_other_constraints()
    {
        var set = SchemaDdl.Extract(Dump);

        Assert.Single(set.ForeignKeys);
        Assert.Contains("orders_customer_fkey", set.ForeignKeys.Single(), StringComparison.Ordinal);
        Assert.Single(set.Constraints);
        Assert.Contains("orders_pkey", set.Constraints.Single(), StringComparison.Ordinal);
    }

    [Fact]
    public void Identical_dumps_differ_in_nothing()
    {
        var declared = SchemaDdl.Extract(Dump);
        var restored = SchemaDdl.Extract(Dump);

        var (lost, gained) = Ddl.Difference(declared.Tables, restored.Tables);

        Assert.Empty(lost);
        Assert.Empty(gained);
    }

    // The column type is inside the CREATE TABLE, which is why the whole
    // statement is compared and not a list of column names: a restore that
    // brought every table back with every column narrowed would otherwise pass.
    [Fact]
    public void A_column_that_changed_type_is_a_difference()
    {
        var declared = SchemaDdl.Extract("CREATE TABLE t (id bigint NOT NULL);");
        var restored = SchemaDdl.Extract("CREATE TABLE t (id integer NOT NULL);");

        Assert.Single(Ddl.Difference(declared.Tables, restored.Tables).Lost);
    }

    [Fact]
    public void A_lost_NOT_NULL_is_a_difference()
    {
        var declared = SchemaDdl.Extract("CREATE TABLE t (id bigint NOT NULL);");
        var restored = SchemaDdl.Extract("CREATE TABLE t (id bigint);");

        Assert.Single(Ddl.Difference(declared.Tables, restored.Tables).Lost);
    }

    [Fact]
    public void A_foreign_key_that_did_not_come_back_is_reported_by_name()
    {
        var declared = SchemaDdl.Extract(Dump);
        var restored = SchemaDdl.Extract(Dump.Replace(
            "ADD CONSTRAINT orders_customer_fkey FOREIGN KEY (customer_id) REFERENCES public.customers(id);",
            "",
            StringComparison.Ordinal));

        var (lost, gained) = Ddl.Difference(declared.ForeignKeys, restored.ForeignKeys);

        Assert.Contains("orders_customer_fkey", Assert.Single(lost), StringComparison.Ordinal);
        Assert.Empty(gained);
    }

    // Two functions whose bodies differ after the first semicolon. Before there
    // was a statement splitter both sides truncated to the same string and this
    // comparison passed, which is the worst outcome available to it.
    [Fact]
    public void A_function_body_that_changed_below_its_first_line_is_a_difference()
    {
        var declared = SchemaDdl.Extract(
            "CREATE FUNCTION f() RETURNS int LANGUAGE plpgsql AS $$ BEGIN PERFORM 1; RETURN 1; END; $$;");
        var restored = SchemaDdl.Extract(
            "CREATE FUNCTION f() RETURNS int LANGUAGE plpgsql AS $$ BEGIN PERFORM 1; RETURN 0; END; $$;");

        Assert.Single(Ddl.Difference(declared.Functions, restored.Functions).Lost);
    }

    [Fact]
    public void A_trigger_the_artefact_never_declared_is_a_difference_too()
    {
        var declared = SchemaDdl.Extract("CREATE TABLE t (id bigint);");
        var restored = SchemaDdl.Extract("""
            CREATE TABLE t (id bigint);
            CREATE TRIGGER appeared BEFORE INSERT ON t FOR EACH ROW EXECUTE FUNCTION f();
            """);

        Assert.Single(Ddl.Difference(declared.Triggers, restored.Triggers).Gained);
    }

    // pg_dump writes a serial column's default as a separate ALTER TABLE, after
    // the sequence it refers to. It is part of the table's definition all the
    // same: a table that came back without it is a table whose inserts now fail.
    [Fact]
    public void A_column_default_written_apart_from_its_table_is_still_the_table()
    {
        var declared = SchemaDdl.Extract("""
            CREATE TABLE public.t (id bigint NOT NULL);
            ALTER TABLE ONLY public.t ALTER COLUMN id SET DEFAULT nextval('public.t_id_seq'::regclass);
            """);
        var restored = SchemaDdl.Extract("CREATE TABLE public.t (id bigint NOT NULL);");

        Assert.Equal(2, declared.Tables.Count);
        Assert.Contains("nextval", Assert.Single(Ddl.Difference(declared.Tables, restored.Tables).Lost),
            StringComparison.Ordinal);
    }

    [Fact]
    public void An_artefact_that_records_no_encoding_says_so_rather_than_guessing()
    {
        Assert.Null(SchemaDdl.Extract("CREATE TABLE t (id bigint);").Encoding);
    }

    [Fact]
    public void An_index_and_an_owner_belong_to_no_family_here()
    {
        // Both are in the dump and neither is a level 2 family. What is not
        // compared is not silently folded into something that is.
        var set = SchemaDdl.Extract("""
            CREATE INDEX ix ON public.t USING btree (id);
            ALTER TABLE public.t OWNER TO app_owner;
            """);

        Assert.Empty(set.Tables);
        Assert.Empty(set.Constraints);
        Assert.Empty(set.Sequences);
    }
}
