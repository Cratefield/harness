//! Every venture's wrangler `migrations_dir` must carry every migration
//! its modules ship (issue #173 fallout).
//!
//! `fz migrations collect` writes those files, but it runs through
//! `cratefield_cli::main_for(venture::harness)` — a binary each venture
//! provides. `ventures/cratefield-waitlist` is a `cdylib` with no such
//! binary, so collect could never be run for it, and its directory sat at
//! one of the waitlist module's four migrations while #127, #133 and #173
//! each added one. Nothing noticed: `runtime-cloudflare` has no migration
//! handling at all, D1 applies whatever files are checked in, and CI only
//! ever applied `examples/venture`'s.
//!
//! The consequence is silent and total. `store::confirm_entry` writes to
//! `waitlist_position_lock` before assigning a position, so a deploy
//! without that migration fails every confirmation — the link in every
//! pending signup's inbox.
//!
//! This test is the check that was missing: it reproduces what collect
//! would write and compares it against what is checked in. A sibling test
//! reads each venture's manifest the way the doctor's
//! undeclared-migration check does (issue #870), so a venture cannot add
//! a module dependency whose SQL silently never ships either.

mod common;

use common::repo_root;
use cratefield_cli::doctor::{shipped_sql_files, venture_dependency_dirs};
use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

/// One composed module: the name it is mounted under, and the crate
/// directory whose `migrations/sqlite` it ships (`None` for an in-crate
/// module with no migrations of its own).
type ComposedModule = (&'static str, Option<&'static str>);

/// A venture and the modules it composes, in the order its builder does —
/// which is the order collect numbers them in.
const VENTURES: &[(&str, &[ComposedModule])] = &[
    (
        "ventures/cratefield-waitlist",
        &[("waitlist", Some("module-waitlist"))],
    ),
    (
        "examples/venture",
        &[
            // An in-crate module with no migrations of its own.
            ("sample", None),
            ("email-signup", Some("module-email-signup")),
            ("waitlist", Some("module-waitlist")),
            ("notifications", Some("module-notifications")),
            // In the builder's order the CRM comes after `orgs` and the
            // venture's own `admin` module, neither of which ships
            // migrations of its own, so it follows `notifications` here.
            ("crm", Some("module-crm")),
        ],
    ),
    (
        // The auth harness missed for a different reason than the waitlist.
        // It does provide a binary — `crates/auth-fz` — but that crate is
        // excluded from the cargo workspace, so nothing in CI builds it and
        // collect is only ever run by hand, when someone remembers. The
        // passkey and magic-link modules each shipped a sqlite migration
        // afterwards and the directory was never refreshed.
        "crates/auth-worker",
        &[
            ("auth-core", Some("auth-core")),
            ("auth-oidc", None),
            ("auth-passkeys", Some("auth-passkeys")),
            ("auth-magic-link", Some("auth-magic-link")),
            ("auth-password", None),
            ("auth-meta", None),
        ],
    ),
];

/// Whether a directory entry is a migration file.
fn is_sql(name: &str) -> bool {
    Path::new(name)
        .extension()
        .is_some_and(|ext| ext.eq_ignore_ascii_case("sql"))
}

/// The `(id, name, file)` triples a module crate ships, in id order — the
/// same list `Module::migrations().sqlite` yields, read with the doctor's
/// own [`shipped_sql_files`]. A module listed with a crate that ships no
/// SQL at all is a mistake in the `VENTURES` table rather than a missed
/// file, so it fails here with the entry named instead of passing
/// silently.
fn module_migrations(root: &Path, module_dir: &str) -> Vec<(String, String, PathBuf)> {
    let files = shipped_sql_files(&root.join("crates").join(module_dir));
    assert!(
        !files.is_empty(),
        "VENTURES lists {module_dir} but crates/{module_dir} ships no sqlite \
         migration (no migrations/sqlite/*.sql, no flat migrations/*.sql); \
         fix the entry or drop it"
    );
    files
        .iter()
        .map(|file| {
            let name = file.file_name().expect("file name").to_string_lossy();
            let (id, rest) = name
                .trim_end_matches(".sql")
                .split_once('_')
                .expect("<id>_<name>.sql");
            (id.to_owned(), rest.to_owned(), file.clone())
        })
        .collect()
}

#[test]
fn every_venture_ships_every_migration_its_modules_declare() {
    let root = repo_root();
    let mut failures: Vec<String> = Vec::new();

    for (venture, modules) in VENTURES {
        let dir = root.join(venture).join("migrations");
        let present: BTreeMap<String, String> = std::fs::read_dir(&dir)
            .unwrap_or_else(|err| panic!("cannot read {}: {err}", dir.display()))
            .map(|entry| entry.expect("readable entry").file_name())
            .filter_map(|name| name.to_str().map(str::to_owned))
            .filter(|name| is_sql(name))
            .map(|name| {
                // <GGGG>_<module>_<id>_<name>.sql. Module names are
                // kebab-case so they carry no underscore, while migration
                // names carry several — so split from the left, not the
                // right: the first two fields are the module and the id
                // and everything after them is the name.
                let stem = name.trim_end_matches(".sql");
                let rest = stem.split_once('_').expect("global number").1;
                let mut fields = rest.splitn(3, '_');
                let module = fields.next().expect("module name");
                let id = fields.next().expect("migration id");
                let migration_name = fields.next().expect("migration name");
                (format!("{module}/{id}"), format!("{migration_name}|{name}"))
            })
            .collect();

        for (module_name, module_dir) in *modules {
            let Some(module_dir) = module_dir else {
                continue;
            };
            for (id, name, shipped_file) in module_migrations(&root, module_dir) {
                let key = format!("{module_name}/{id}");
                let Some(found) = present.get(&key) else {
                    failures.push(format!(
                        "{venture}/migrations is missing {key} ({name}) — run \
                         `fz migrations collect` for that venture; a deploy without it \
                         leaves the table absent and every write to it fails"
                    ));
                    continue;
                };
                let collected_name = found.split('|').next().expect("name half");
                assert_eq!(
                    collected_name, name,
                    "{venture}: {key} is checked in under the wrong migration name"
                );

                // The body must be what the module ships: collect writes
                // `sql.trim_end() + "\n"`, and a locked file that drifts
                // from its module is a migration applied from one source
                // and maintained in another.
                let shipped =
                    std::fs::read_to_string(&shipped_file).expect("module migration readable");
                let checked_in =
                    std::fs::read_to_string(dir.join(found.split('|').nth(1).expect("file half")))
                        .expect("venture migration readable");
                assert_eq!(
                    checked_in.trim_end(),
                    shipped.trim_end(),
                    "{venture}: {key} differs from the migration its module ships"
                );
            }
        }
    }

    assert!(failures.is_empty(), "{}", failures.join("\n"));
}

/// A venture cannot add a module dependency whose SQL silently never
/// ships (issue #870): every local crate it depends on — `path`
/// dependencies and `workspace = true` ones the workspace root manifest
/// resolves — that ships sqlite SQL must appear in that venture's
/// `VENTURES` entry here. A crate pulled in for features that ships no
/// sqlite SQL (the facade, the runtimes, the adapters) is not flagged:
/// there is nothing of its own to ship.
///
/// The dependency resolution is the doctor's own
/// (`venture_dependency_dirs`), so this test cannot quietly disagree
/// with the check it mirrors.
#[test]
fn every_local_dependency_that_ships_sql_is_listed() {
    let root = repo_root();
    let mut failures: Vec<String> = Vec::new();

    for (venture, modules) in VENTURES {
        let listed: BTreeSet<&str> = modules.iter().filter_map(|(_, dir)| *dir).collect();
        for dep in venture_dependency_dirs(&root.join(venture).join("migrations")) {
            let name = dep
                .file_name()
                .expect("a resolved dependency has a directory name")
                .to_str()
                .expect("a dependency directory name is utf-8");
            if shipped_sql_files(&dep).is_empty() || listed.contains(name) {
                continue;
            }
            failures.push(format!(
                "{venture} depends on `{name}`, which ships sqlite migrations, but it is \
                 not in this test's VENTURES entry — nothing declares its SQL, so it is \
                 never collected and its tables never exist on D1. List it under the \
                 module that declares it, or drop the dependency"
            ));
        }
    }

    assert!(failures.is_empty(), "{}", failures.join("\n"));
}
