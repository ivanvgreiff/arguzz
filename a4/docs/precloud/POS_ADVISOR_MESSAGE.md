# Draft Message to Advisor / Testbed Admin

> Based on `PIVOT_TO_POS.md §14`. Edit names, contact, and degree of formality before sending. The substantive technical questions match `POS_ACCESS_NOTES.md`.

---

Subject: POS testbed access for RISC Zero fuzzing campaign — request for guidance

Hi [Advisor Name],

I'm planning a CPU-bound experiment for [project name] that uses the university's POS testbed. Each independent job is one seeded fuzzing campaign producing a SQLite database and a log file. A campaign can take several hours to run depending on the parameters. I do **not** need GPUs and I do **not** need any special network measurements; this is purely CPU + memory.

The overall experiment is small in count but long in wall time:

- 3 strategies × 5 seeds = 15 independent campaigns total (for the main run).
- Plus a smaller validation pass (3 × 3 × small-N) before the main run.
- Plus a one-node benchmark pass to size the main run.

Before I write any production code against POS, I'd like to confirm a few details:

1. **Testbed and nodes** — Which testbed and which nodes do you recommend? My workload is CPU-bound (one process per node) and benefits from many cores per node and from being homogeneous across the 15 jobs. The Blockchain testbed's compute nodes (e.g. `intelexp0/1`, `vmexp0/1`, `amdexp0/1`, `galvos`, `tether`) look like a good fit on paper; could you confirm whether they're available to me?

2. **Reservation length** — Can I reserve approximately [X] nodes for up to **3 uninterrupted days**? My plan assumes that as the base case; if it's not realistic I'll need to scale down `N` per campaign.

3. **Long jobs** — Is it OK to run continuous CPU-bound jobs (hours) on those nodes during the reservation window?

4. **OS image** — Which standard Debian image should I use with `pos nodes image`? (`debian-buster`, `debian-bullseye`, something else?) I'd like to assume a clean Debian boot and stage everything myself rather than rely on a custom image.

5. **Outbound internet on test nodes** — Do the test nodes have outbound internet (PyPI / crates.io / GitHub)? Even if they do, I plan to stage dependencies, so this is informational, not blocking.

6. **File staging** — I plan to ship a tarball bundle (repo source + a single prebuilt binary + scripts + manifests, ~100–200 MB) and have each test node `pos_download` it. The docs say `pos_download` reads from `/srv/testbed/files`. Where should I place my bundle? Do I create a per-user subdirectory? Is there a quota?

7. **Results storage** — Where do `pos_upload` artifacts end up? Are there quotas? Is there a recommended naming convention for many parallel campaigns within one experiment?

8. **Docker** — Is Docker installed and allowed on the chosen test nodes? My default plan **avoids** Docker (per advice; I have no Docker experience yet), but knowing the answer helps me size up future options.

9. **POS examples** — Is there a `pos-examples` repository or sample workflow you'd recommend I read first? Something with `pos_download` + `pos_upload` + a non-blocking command would be especially useful.

If easier, I can write this up in a one-page workflow sketch and walk through it with you in [next meeting / 1:1] — I just don't want to start cooking against POS until the basics above are settled.

Thanks!

— [Eddie]
[contact]
