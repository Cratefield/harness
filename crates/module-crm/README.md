# cratefield-module-crm

Contacts, organisations and the tags that label them, with an idempotent
upsert API other modules and a venture's own code can call.

```rust
use cratefield_module_crm::Crm;

let module = Crm::new();
```

Mounted at `/v1/crm`. It requires the `Db`, `IdGen` and `Clock` ports and
declares `Auth` as optional.

## Configuration

None. The module reads no config keys of its own: every default is a
constant, every route is admin-gated, and `Module::validate_config` accepts
whatever it is given. The one key that decides whether the module is usable
is the harness-wide `ADMIN_TOKEN`, because every route it declares is an
admin action — with no token configured, all of them answer `401`
(`admin-unauthorized`) rather than open.

## In a venture manifest

The module is a catalog slug, so a venture that wants it lists `"crm"` in
its manifest and `fz build` wires it up:

```json
{
  "name": "acme",
  "host": "acme.factory0.dev",
  "cors_origins": ["https://acme.factory0.dev"],
  "modules": ["crm"]
}
```

Or, by hand, through the facade (the facade crate is not a dependency of this
one, so the snippet is not compiled):

```rust,ignore
use cratefield::crm::Crm;

let module = Crm::new();
```

## Idempotent by natural key

`store::upsert_contact` keys a contact on its normalized email address, and
`store::upsert_organisation` keys an organisation on its lowered domain. The
same address filed twice is one contact: the second call updates the fields it
supplies, leaves the ones it does not, bumps the row's `generation`, and
reports whether it inserted or updated. That is what makes the call safe from
an event handler that may run twice, which is the reason the API is public
rather than only reachable through the admin routes.

## Optimistic concurrency

Every row carries a `generation` that starts at 1 and is bumped by each write.
A PATCH must carry the generation it read; the update is a single
`UPDATE … WHERE id = ? AND generation = ?`, so a caller working from a stale
copy changes nothing and is answered `409` with the `crm-stale-generation`
problem instead of silently overwriting a newer edit.

## Routes

Everything is an admin action behind the harness `ADMIN_TOKEN` bearer:

- `GET /v1/crm/admin/contacts.csv` and `GET /v1/crm/admin/organisations.csv`
  export a page of rows as CSV (`limit`/`offset`, at most 5000 rows per page,
  with `x-cf-export-more: true` when there is more to fetch).
- `POST /v1/crm/admin/contacts` files a contact (upsert by address);
  `PATCH /v1/crm/admin/contacts/{id}` and `DELETE …/{id}` edit and remove one.
- `POST /v1/crm/admin/contacts/merge` folds one contact into another, filling
  the survivor's empty fields, merging their structured data and moving their
  tags, all in one atomic batch.
- `POST /v1/crm/admin/organisations` files an organisation (upsert by domain);
  `PATCH …/{id}` and `DELETE …/{id}` edit and remove one.
- `POST /v1/crm/admin/tags` creates a tag; `POST …/tags/tag` and
  `POST …/tags/untag` file a tag against a subject and take it off again.

## Events

| event | emitted when |
| --- | --- |
| `crm.contact.created` | An upsert inserted a contact. |
| `crm.contact.updated` | An upsert matched an existing contact, a PATCH changed one, or a merge folded another into it. |
| `crm.organisation.created` | An upsert inserted an organisation. |

Nothing else emits: a delete is silent, and an organisation PATCH has no
event because the module declares no `crm.organisation.updated` — inventing
one per edit would be a promise no subscription list carries.

## Personal data

The privacy module reads the declarations in `Module::personal_data`:

| table | subject | kind | disposition |
| --- | --- | --- | --- |
| `crm_contacts` | `id` | contact | erase |
| `crm_organisations` | — | — | retained: a business record, not a person's |
| `crm_tags` | — | — | not personal: a name and a colour |
| `crm_taggings` | `subject_id`, via `crm_contacts` | identifier | erase |

So a contact is erased with its taggings — the tables are declared
parent-first because the privacy module erases in reverse catalog order, and
`crm_taggings`' polymorphic `subject_id` is matched through `crm_contacts`
rather than a foreign key. An organisation survives: it is a business record,
and deleting one would take every contact linked to it with it. Review that
before relying on it — an organisation's `email` and `phone` may hold an
individual's details rather than a switchboard, and a sole trader's record is
a person's data in practice.
