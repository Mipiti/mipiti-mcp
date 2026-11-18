---
name: mipiti-review
description: Work a Mipiti threat model's review queue (proposals, behavioural questions, entity flags, decisions waiting on the owner) through the Mipiti MCP server. Use when asked to review, clear or work the decisions, proposals or questions of a Mipiti model.
---

<!-- mipiti-mcp install-skill: this file is replaced when the skill is installed again -->

# Working a Mipiti model's review queue

The procedure lives on the server, so this skill never goes stale: read it
there every time.

1. Call `get_review_playbook` with the model's id before deciding anything.
   It returns the procedure for each kind of item, the model's open items,
   what you may decide under the workspace's delegation policy, the paid acts
   the open items lead to, and the review run your work is recorded under.
   Follow it.
2. Work the items you may decide in the order it gives. Gather decisions of
   one kind into one batch where a batch tool exists.
3. Pass `evidence` on every judgment: the file and lines, the URL and lines,
   or the quoted sentence and its source that the decision rests on. Without
   evidence, decide nothing.
4. A refused judgment is parked for a person: report it and never retry it.
   A call that ended without its result is read back before it is repeated.
5. A paid act (an extraction, a check, a build, a judgement of objectives)
   runs only with the person's agreement to its estimate, or within the
   workspace's spending allowance.
6. Call `get_review_playbook` again after a round of work.
7. Close the run with `close_review_run`, with your notes, and give the
   person the digest it returns: what was decided and on what evidence, what
   waits on them, what was spent, and how each decision is undone.
