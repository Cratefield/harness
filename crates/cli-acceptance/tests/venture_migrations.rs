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
//! would write and compares it against what is checked in.

mod common;

use common::repo_root;
use std::collections::BTreeMap;
use std::path::Path;

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
        ],
    ),
];

/// Whether a directory entry is a migration file.
fn is_sql(name: &str) -> bool {
    Path::new(name)
        .extension()
        .is_some_and(|ext| ext.eq_ignore_ascii_case("sql"))
}

/// The `(id, name)` pairs a module ships, in id order — the same list
/// `Module::migrations().sqlite` yields.
fn module_migrations(root: &Path, module_dir: &str) -> Vec<(String, String)> {
    let dir = root
        .join("crates")
        .join(module_dir)
        .join("migrations/sqlite");
    let mut files: Vec<_> = std::fs::read_dir(&dir)
        .unwrap_or_else(|err| panic!("cannot read {}: {err}", dir.display()))
        .map(|entry| entry.expect("readable entry").file_name())
        .filter_map(|name| name.to_str().map(str::to_owned))
        .filter(|name| is_sql(name))
        .collect();
    files.sort();
    files
        .iter()
        .map(|name| {
            let stem = name.trim_end_matches(".sql");
            let (id, rest) = stem.split_once('_').expect("<id>_<name>.sql");
            (id.to_owned(), rest.to_owned())
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
            for (id, name) in module_migrations(&root, module_dir) {
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
                let shipped = std::fs::read_to_string(
                    root.join("crates")
                        .join(module_dir)
                        .join("migrations/sqlite")
                        .join(format!("{id}_{name}.sql")),
                )
                .expect("module migration readable");
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
