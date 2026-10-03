# cratefield-module-orgs

Organizations, memberships, roles and email invitations for a Cratefield
venture: a person creates an organization and is its owner, invites people by
address, and everyone who belongs holds a role the venture configured.

Mounted at `/v1/orgs`. One migration, three tables. Every route but the admin
listing acts for the account the venture's `Auth` port identifies; no route
reads a subject id from anywhere else, so one person cannot act as another.

## Composing it

```rust
use cratefield_module_orgs::Orgs;

let orgs = Orgs::builder()
    // `owner` is always in the set and is the creator's role.
    .roles(["owner", "manager", "staff"])
    // Non-owner roles that may manage members and invitations.
    .managers(["manager"])
    .build();
```

| builder | meaning |
| --- | --- |
| `.roles([..])` | The roles an organization may use. `owner` is added if omitted. A role outside the set is refused with `422 orgs-unknown-role`, so a typo cannot be stored. |
| `.managers([..])` | The non-owner roles that may add, remove, re-role and invite. The default is that only owners manage. |
| `.staff_org(org_id)` | The venture's staff organization. `ORGS_STAFF_ORG` overrides it per deployment. |
| `.staff_roles([..])` | The roles in the staff organization that may see the admin listing. |
| `.invitation_ttl(Duration)` | How long an invitation stays acceptable. Seven days by default. |

Configuration keys (all prefixed `ORGS_`):

| key | meaning |
| --- | --- |
| `ORGS_API_BASE` | The public base the accept link is built from (default `https://api.<venture domain>`). |
| `ORGS_ACCEPT_URL` | A venture's own accept page, when it has one. |
| `ORGS_STAFF_ORG` | Overrides the builder's staff organization. |
| `ORGS_FROM` / `ORGS_REPLY_TO` | The invitation mail's sender. |

## The rules

- An organization always has at least one owner. The last owner cannot leave,
  be removed or be demoted — each is one guarded statement whose affected-row
  count decides it, answered with `409 orgs-last-owner`.
- Owners may do anything. A manager role may add, remove, re-role and invite,
  but only an owner may grant or revoke the `owner` role and only an owner may
  change an owner's membership.
- A caller who is not a member gets the `404 orgs-not-found` an unknown id
  gets, so organizations cannot be enumerated.
- An invitation stores only the SHA-256 of its token and of the invitee's
  normalized address, and is spent by one guarded `UPDATE`: a second accept,
  or one from the wrong address, finds it already gone. The raw token is
  mailed, never returned in a response.

## Typed API

```rust,ignore
// May this person see this organization's page?
let role = cratefield_module_orgs::member_role(&*db, org_id, &subject).await?;

// May this caller use an admin route?
let staff = cratefield_module_orgs::require_staff(&ctx, &headers, staff_org, &roles).await?;
```

## Moving from `ADMIN_TOKEN` to a staff org

`require_staff` and the admin listing accept **either** a machine holding
`ADMIN_TOKEN` **or** a person whose verified subject is a member of the staff
organization holding one of the staff roles. A deployment that has an
`ADMIN_TOKEN` keeps working unchanged; the staff organization is the path for
people.

To move:

1. Compose the module with `.roles([.., "admin"]).staff_org("<org id>").staff_roles(["admin"])`.
   A staff role configured without a staff organization is a `self_check`
   failure, because nobody could ever hold it.
2. Create the staff organization in the venture and give the people who should
   have access the staff role there. Nothing else changes: membership is
   grantable and revocable through the ordinary routes.
3. Once no machine needs `ADMIN_TOKEN`, remove it. Every admin route then
   answers `401` unless the caller is staff.

No shared secret to rotate, and removing somebody from the staff organization
is a `DELETE` — that is the reason to move.

## Ports

Requires `Db` and `Auth`. Optionally uses `Clock` (expiry and single-use),
`IdGen` (ids and the invitation token) and `Mailer`. A mailer that reports
`NotConfigured` leaves no invitation behind: the row is deleted and the caller
gets the same `503 mail-not-configured` the waitlist form degrades on.

## Personal data (ADR 0015)

| table | subject | kind | disposition |
| --- | --- | --- | --- |
| `org_members` | `user_sub` | identifier | erase |
| `orgs` | `created_by` | identifier | retain |
| `org_invitations` | — | contact | unreachable (the address is held only as a hash) |

An organization outlives its creator — deleting the row would delete every
other member's organization with it — so `orgs` is retained, with the reason
published in the manifest. A membership is the member's, and erasing their
account removes it.
