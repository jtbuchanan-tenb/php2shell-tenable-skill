import json
import shutil
import tempfile
import unittest
from pathlib import Path

from verify import (ACTIONABLE, VERDICTS, VERIFY_FIRST, Evidence, credential_state, judge,
                    load_run)

FIXTURE = Path(__file__).parent / "fixtures" / "run"
SHOP = "https://shop.example.com"


def run_dir(edit=None) -> Path:
    """A temp copy of the fixture run folder; edit(files) may change any JSON file in it."""
    tmp = Path(tempfile.mkdtemp())
    shutil.copytree(FIXTURE, tmp / "run")
    d = tmp / "run"
    if edit:
        names = ["findings.json", "assets.json", "plugins.json", "faq.json",
                 "advisories/index.json"]
        files = {n: json.loads((d / n).read_text()) for n in names}
        edit(files)
        for n, data in files.items():
            (d / n).write_text(json.dumps(data))
    return d


def results(edit=None) -> dict:
    d = run_dir(edit)
    try:
        return {r.key: r for r in judge(load_run(d))}
    finally:
        shutil.rmtree(d.parent)


def refs(verdict, kind):
    return [e.reference_id for e in verdict.evidence if e.type == kind]


def first_ev(verdict, kind) -> Evidence:
    return next(e for e in verdict.evidence if e.type == kind)


class Fixture(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.r = results()

    def verdicts(self, key):
        return [v for _, v in self.r[key].installs]

    def only(self, key):
        vs = self.verdicts(key)
        self.assertEqual(len(vs), 1, key)
        return vs[0]


class CredentialState(unittest.TestCase):
    def test_credential_state(self):
        vm = ["Nessus Scan"]
        self.assertEqual(credential_state({"sensors": vm, "auth_plugins": [141118]}),
                         "credentialed")
        self.assertEqual(credential_state({"sensors": ["Nessus Agent"], "auth_plugins": []}),
                         "credentialed")
        self.assertEqual(credential_state({"sensors": vm, "auth_plugins": [141118, 104410]}),
                         "failed")
        self.assertEqual(credential_state({"sensors": vm, "auth_plugins": [110723]}),
                         "not-credentialed")
        self.assertEqual(credential_state({"sensors": vm, "auth_plugins": []}),
                         "not-credentialed")
        self.assertEqual(credential_state({"sensors": ["WAS"], "auth_plugins": []}, SHOP),
                         "not-applicable")
        self.assertEqual(credential_state({"sensors": ["Cloud"], "auth_plugins": []}),
                         "not-applicable")

    def test_verdict_sets(self):
        self.assertEqual(VERDICTS["no-stream-fix"], "Vulnerable – no fix for this stream")
        self.assertEqual(ACTIONABLE, {"vulnerable", "no-vendor-fix", "no-stream-fix",
                                      "backport-only", "eol"})
        self.assertEqual(VERIFY_FIRST, {"conflict", "likely-patched",
                                        "unverified-credentials", "unverified-no-data"})


class Table(Fixture):
    def test_every_key(self):
        self.assertEqual(sorted(self.r), sorted([
            "a-rhel9", "a-ol8", "a-ubuntu-ok", "a-ubuntu-conflict", "a-deb-clean",
            "a-nocreds", "a-authfail", "a-win", "a-eol", SHOP, "a-image", "a-trunc"]))
        self.assertEqual([r.key for r in judge(load_run(FIXTURE))], sorted(self.r))

    def test_a_rhel9(self):
        r = self.r["a-rhel9"]
        self.assertEqual([i.path for i, _ in r.installs], ["/usr/bin/php", "/usr/bin/php-cgi"])
        self.assertEqual(r.credential_state, "credentialed")
        for v in self.verdicts("a-rhel9"):
            self.assertEqual((v.code, v.label, v.rule, v.action),
                             ("vulnerable", "Vulnerable", "1+3", "vendor-update"))
            self.assertIn("RHSA-2026:87151", v.fix_target)
            self.assertIn("php-cli-8.0.30-3.el9_6.2", v.fix_target)
            self.assertEqual(v.evidence[0].type, "tenable-plugin")
            self.assertEqual(v.evidence[0].reference_id, "370210")
            feed = first_ev(v, "vendor-feed")
            self.assertEqual((feed.source, feed.reference_id, feed.observed, feed.expected),
                             ("redhat", "RHSA-2026:88720", "8.0.30-3.el9_6", "8.0.30-3.el9_6.2"))
            self.assertEqual(feed.url, "https://access.redhat.com/errata/RHSA-2026:88720")
            self.assertEqual(feed.fetched_at, "2026-10-27T15:26:16+00:00")

    def test_a_ol8(self):
        v = self.only("a-ol8")
        self.assertEqual((v.code, v.rule, v.action, v.fix_target),
                         ("no-stream-fix", "4a", "upgrade-stream", "php:8.2 stream"))
        self.assertEqual(v.evidence[0].type, "absence")
        self.assertEqual((v.evidence[0].observed, v.evidence[0].expected),
                         ("php:8.0", "php:7.4, php:8.2"))

    def test_a_ubuntu_ok(self):
        v = self.only("a-ubuntu-ok")
        self.assertEqual((v.code, v.label, v.rule, v.action), ("patched", "Patched", "3", ""))
        feeds = [e for e in v.evidence if e.type == "vendor-feed"]
        self.assertEqual(len(feeds), 2)  # one per run CVE
        for e in feeds:
            self.assertEqual((e.source, e.reference_id, e.observed, e.expected),
                             ("osv", "USN-8948-1", "8.1.2-1ubuntu2.28", "8.1.2-1ubuntu2.28"))
        self.assertEqual(refs(v, "tenable-plugin"), [])

    def test_a_ubuntu_conflict(self):
        v = self.only("a-ubuntu-conflict")
        self.assertEqual((v.code, v.label, v.rule, v.action),
                         ("conflict", "Conflict – verify", "1+3", ""))
        self.assertEqual(refs(v, "tenable-plugin"), ["370517"])
        self.assertEqual(first_ev(v, "vendor-feed").expected, "8.1.2-1ubuntu2.28")

    def test_a_deb_clean(self):
        v = self.only("a-deb-clean")
        self.assertEqual((v.code, v.rule, v.action), ("likely-patched", "6", ""))
        self.assertEqual(v.label, "Likely patched – Tenable distro check clean")
        self.assertEqual(v.evidence[0].type, "absence")
        self.assertIn("2026-10-22", v.evidence[0].expected)
        self.assertIn("2026-10-25", v.evidence[0].observed)
        self.assertEqual(refs(v, "credential"), ["141118"])

    def test_a_nocreds(self):
        r = self.r["a-nocreds"]
        v = self.only("a-nocreds")
        self.assertEqual(r.credential_state, "not-credentialed")
        self.assertIsNone(r.installs[0][0].managed_by_os)
        self.assertEqual((v.code, v.rule, v.action), ("unverified-credentials", "7", ""))
        self.assertEqual(v.evidence[0].type, "credential")
        self.assertEqual(v.evidence[0].observed, "not-credentialed")
        self.assertEqual(refs(v, "tenable-plugin"), ["369483"])

    def test_a_authfail(self):
        r = self.r["a-authfail"]
        v = self.only("a-authfail")
        self.assertEqual(r.credential_state, "failed")
        self.assertEqual((v.code, v.rule), ("unverified-credentials", "7"))
        self.assertEqual((v.evidence[0].reference_id, v.evidence[0].observed),
                         ("104410", "failed"))

    def test_a_win(self):
        v = self.only("a-win")
        self.assertEqual((v.code, v.rule, v.action, v.fix_target),
                         ("vulnerable", "5", "patch", "8.3.36"))
        up = v.evidence[0]
        self.assertEqual((up.type, up.observed, up.expected), ("upstream-version", "8.3.30", "8.3.36"))
        self.assertEqual(refs(v, "tenable-plugin"), ["369483"])

    def test_a_eol(self):
        v = self.only("a-eol")
        self.assertEqual((v.code, v.label, v.rule, v.action),
                         ("eol", "Vulnerable – EOL", "5", "isolate-or-upgrade"))
        self.assertEqual(v.evidence[0].observed, "7.2.34")
        self.assertEqual(self.r["a-eol"].asset["ips"], ["203.0.113.10"])

    def test_shop_unjoined_was(self):
        r = self.r[SHOP]
        v = self.only(SHOP)
        self.assertEqual((r.credential_state, r.sources, r.urls),
                         ("not-applicable", {"WAS"}, [SHOP]))
        self.assertEqual((v.code, v.rule, v.action, v.fix_target),
                         ("vulnerable", "5", "patch", "8.3.36"))
        self.assertEqual(refs(v, "tenable-plugin"), ["115721"])
        self.assertEqual((v.evidence[0].observed, v.evidence[0].expected), ("8.3.30", "8.3.36"))

    def test_a_image(self):
        r = self.r["a-image"]
        v = self.only("a-image")
        self.assertEqual((r.credential_state, r.sources), ("not-applicable", {"Cloud"}))
        self.assertEqual(r.installs[0][0].path, "")
        self.assertEqual(r.installs[0][0].version, "8.3.30")
        self.assertEqual((v.code, v.rule, v.action), ("vulnerable", "1", "vendor-update"))
        self.assertEqual(v.evidence[0].reference_id, "CVE-2026-109618")

    def test_a_trunc(self):
        r = self.r["a-trunc"]
        self.assertTrue(r.output_truncated)
        self.assertEqual(len(r.installs), 2)
        self.assertEqual({(v.code, v.rule) for _, v in r.installs}, {("vulnerable", "3")})
        self.assertEqual([k for k, x in self.r.items() if x.output_truncated], ["a-trunc"])


class FeedFailure(unittest.TestCase):
    def test_feed_failed_never_patched(self):
        for cves in (["CVE-2026-109618"], ["CVE-2026-109619"],
                     ["CVE-2026-109618", "CVE-2026-109619"]):
            def fail(files):
                for e in files["advisories/index.json"]:
                    if e["source"] == "osv" and e["cve"] in cves and "UBUNTU" in e["url"]:
                        e.update(status="failed", file=None, error="HTTP 429")
            with self.subTest(failed=cves):
                v = results(fail)["a-ubuntu-ok"].installs[0][1]
                self.assertEqual((v.code, v.rule), ("unverified-no-data", "8"))
                self.assertEqual(v.evidence[0].type, "absence")
                self.assertIn("fetch failed", v.evidence[0].observed)

    def test_no_feed_record_never_patched(self):
        def drop(files):
            files["advisories/index.json"] = [
                e for e in files["advisories/index.json"] if "UBUNTU" not in e["url"]]
        v = results(drop)["a-ubuntu-ok"].installs[0][1]
        self.assertEqual(v.code, "unverified-no-data")


class AuthOutput(unittest.TestCase):
    def test_auth_output_never_kept(self):
        def stray(files):
            files["assets.json"]["a-authfail"]["auth_output"] = "User: 'svc-scan'\nPort: 22"
        rs = results(stray)
        for r in rs.values():
            self.assertNotIn("svc-scan", repr(r.asset))
            for _, v in r.installs:
                for e in v.evidence:
                    for field in e:
                        self.assertNotIn("svc-scan", field)


class Variants(unittest.TestCase):
    def test_was_join_patched_host_is_conflict(self):
        def join(files):
            row = next(r for r in files["findings.json"] if r["source"] == "WAS")
            row.update(url="https://app02.example.internal", fqdn="", ip="")
        rs = results(join)
        self.assertNotIn(SHOP, rs)
        r = rs["a-ubuntu-ok"]
        self.assertEqual(r.sources, {"VM", "WAS"})
        self.assertEqual(r.urls, ["https://app02.example.internal"])
        codes = [(v.code, v.rule) for _, v in r.installs]
        self.assertEqual(codes, [("patched", "3"), ("conflict", "5+3")])
        self.assertIn("115721", refs(r.installs[1][1], "tenable-plugin"))
        self.assertIn("vendor-feed", [e.type for e in r.installs[1][1].evidence])

    def test_was_join_by_ip_stays_vulnerable(self):
        def join(files):
            row = next(r for r in files["findings.json"] if r["source"] == "WAS")
            row.update(ip="10.0.1.10")
        r = results(join)["a-rhel9"]
        self.assertEqual([(v.code, v.rule) for _, v in r.installs][-1], ("vulnerable", "5"))
        self.assertEqual(r.credential_state, "credentialed")

    def test_was_ambiguous_join_stays_own_result(self):
        def join(files):
            row = next(r for r in files["findings.json"] if r["source"] == "WAS")
            row.update(ip="10.0.1.10")
            files["assets.json"]["a-trunc"]["ips"] = ["10.0.1.10"]
        rs = results(join)
        self.assertIn(SHOP, rs)
        self.assertNotIn("WAS", rs["a-rhel9"].sources)

    def test_rule4_vendor_affected_no_fix(self):
        pkg = "php-cli-8.4.5-1.module+el9.6.0+20000+abcdef12.x86_64"

        def edit(files):
            for r in files["findings.json"]:
                if r["asset_id"] == "a-trunc":
                    r["plugin_output"] = (
                        "Nessus detected 1 install of PHP:\n\n  Path : /usr/bin/php\n"
                        "  Version : 8.4.5\n  Associated Package : %s\n"
                        "  Managed by OS : True\n" % pkg)
        v = results(edit)["a-trunc"].installs[0][1]
        self.assertEqual((v.code, v.rule, v.action),
                         ("no-vendor-fix", "4", "isolate-or-upgrade"))
        self.assertEqual(first_ev(v, "vendor-feed").expected, "affected-no-fix")

    def test_rule4_out_of_support_without_newer_stream(self):
        def edit(files):
            files["assets.json"]["a-trunc"]["os"] = "Red Hat Enterprise Linux 6.10"
            for r in files["findings.json"]:
                if r["asset_id"] == "a-trunc":
                    r["plugin_output"] = (
                        "Nessus detected 1 install of PHP:\n\n  Path : /usr/bin/php\n"
                        "  Version : 5.4.16\n  Associated Package : php-cli-5.4.16-48.el6.x86_64\n"
                        "  Managed by OS : True\n")
        v = results(edit)["a-trunc"].installs[0][1]
        self.assertEqual((v.code, v.rule), ("no-vendor-fix", "4"))
        self.assertEqual(first_ev(v, "vendor-feed").expected, "out-of-support")

    def test_369483_on_distro_install_is_no_data(self):
        def edit(files):
            files["findings.json"].append({
                "asset_id": "a-deb-clean", "asset": "deb01", "ip": "10.0.1.14", "fqdn": "",
                "url": "", "source": "VM", "plugin_id": "369483", "plugin_name": "PHP < 8.2.35",
                "cves": [], "role": "vulnerable", "php_version": "8.2.7", "port": "",
                "last_seen": "2026-10-25"})
            files["plugins.json"] = [p for p in files["plugins.json"]
                                     if not p["name"].startswith("Debian")]
        v = results(edit)["a-deb-clean"].installs[0][1]
        self.assertEqual((v.code, v.rule), ("unverified-no-data", "8"))
        self.assertEqual(refs(v, "tenable-plugin"), ["369483"])

    def test_rule6_needs_plugin_published_before_last_seen(self):
        def edit(files):
            files["assets.json"]["a-deb-clean"]["last_seen"] = "2026-10-21"
        v = results(edit)["a-deb-clean"].installs[0][1]
        self.assertEqual(v.code, "unverified-no-data")


class LoadRun(unittest.TestCase):
    def test_empty_run(self):
        d = Path(tempfile.mkdtemp())
        try:
            (d / "findings.json").write_text("[]")
            (d / "assets.json").write_text("{}")
            run = load_run(d)
            self.assertEqual((run.catalog, run.faq), ([], {}))
            self.assertEqual(judge(run), [])
        finally:
            shutil.rmtree(d)

    def test_findings_required(self):
        d = Path(tempfile.mkdtemp())
        try:
            (d / "assets.json").write_text("{}")
            with self.assertRaises(FileNotFoundError):
                load_run(d)
        finally:
            shutil.rmtree(d)


if __name__ == "__main__":
    unittest.main()
