# WP Post Subscribers

Let visitors subscribe by email and get notified whenever a new post is published — no third-party service, no monthly fee, just WordPress and `wp_mail()`.

## Features

- **Subscribe form** — drop `[subscribe_form]` anywhere (page, widget, footer)
- **Double opt-in** — a confirmation email goes out first; only confirmed addresses ever receive notifications, so your list stays clean and spam-complaint-free
- **New-post emails** — on first publish (not on updates), every confirmed subscriber gets the title, an excerpt, the post link and a one-click unsubscribe link
- **One-click unsubscribe** — signed HMAC links, no login required
- **Anti-spam** — nonce, hidden honeypot field and a 3-second timing trap on the form
- **Per-post-type control** — choose which post types trigger notifications (posts, pages, custom types)
- **Admin list** — **Tools → Post Subscribers** shows confirmed/pending counts, a paged subscriber table and the settings

## How it works

1. A visitor submits their email in the `[subscribe_form]` form.
2. They get a confirmation email with a signed link (`?wps_action=confirm&...`). The signature is an HMAC of the email + action using `wp_salt()`, so links cannot be forged.
3. On confirm, their status flips to `confirmed`.
4. When a post is published for the first time, `transition_post_status` sends the notification to every confirmed subscriber. Password-protected posts are never mailed.

## Filters

- `wps_notify_subject` — filter the notification email subject (`$subject`, `$post`)

## Requirements

- WordPress 5.8+
- PHP 7.4+
- A working `wp_mail()` setup (an SMTP plugin such as [wp-smtp-mailer](https://github.com/Azanumer/wp-smtp-mailer) is recommended for deliverability)

## License

MIT — see [LICENSE](LICENSE).
