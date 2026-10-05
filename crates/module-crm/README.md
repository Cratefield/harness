# cratefield-module-crm

Contacts, organisations and the tags that label them, with an idempotent
upsert API other modules and a venture's own code can call.

```rust
use cratefield_module_crm::Crm;

let module = Crm::new();
```

Mounted at `/v1/crm`. It requires the `Db`, `IdGen` and `Clock` ports and
declares `Auth` as optional.

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

## Personal data

The privacy module reads the declarations in `Module::personal_data`: a contact
is erased with its taggings, an organisation is a business record that
survives, and the tag table names nobody.
