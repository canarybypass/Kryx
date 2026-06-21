=== TITLE (вставить в поле "title") ===

Show HN: Kryx – an AI agent that proves the vulnerabilities it finds


=== URL (поле "url") ===

[ваш сайт — пока ждём домен]


=== FIRST COMMENT (запостить сразу под своим постом) ===

Hi HN. I've been building Kryx, an autonomous offensive-security agent. What bugs me about most scanners is the flood of "maybe" — you spend hours triaging and 90% is noise, and a single false positive in front of a client kills trust.

So the core rule is simple: it only reports what it can prove by execution.

- Command injection is confirmed by making the server compute arithmetic I inject ($((a*b)) — the product shows up in the response), not by reflection.
- SSRF by making the server call back to a listener I control.
- It combines white-box (reads the source for the root cause) and black-box (attacks the running app for the proof), and every finding goes through an adversarial debate — one agent argues it's real, another tries to break it, a judge rules — before it lands in the report.

The most useful thing happened early: it confidently reported an SSRF that turned out to be a false positive of its own making. The endpoint was actually an open redirect (302 to my payload), and the probe followed that redirect with its own HTTP client — so it hit its own listener and "confirmed" SSRF. It was knocking on its own door. Fix was one line: stop following redirects on the probe; a real SSRF still fires from the server's own request. I added a test so the class can't regress.

What it's not: it doesn't promise to find everything — nobody can. The goal is narrower and more honest: what it finds is proven. I'd rather ship 10 confirmed findings than 100 "maybes".

It's not self-serve yet. If you have your own web project and want a free scan + a report of proven findings with fixes (only after you confirm you own the domain), I'm collecting case studies — reach me at [контакт]. Sample report and details: [сайт].

Would love hard feedback, especially on the proof-by-execution approach and where you think it would break.
