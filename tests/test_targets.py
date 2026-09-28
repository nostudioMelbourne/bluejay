import unittest

from bluejay.targets import (
    is_allowed_web_url,
    normalize_decoy_list,
    normalize_target,
    normalize_web_urls,
)


class TargetValidationTests(unittest.TestCase):
    def test_normalize_target_cleans_hostnames_and_ips(self) -> None:
        self.assertEqual(normalize_target("LOCALHOST."), "localhost")
        self.assertEqual(normalize_target("127.0.0.1"), "127.0.0.1")
        self.assertEqual(normalize_target("::1"), "::1")

    def test_normalize_target_rejects_unsafe_input(self) -> None:
        for target in [
            "",
            "example.com/path",
            "example.com:443",
            "example.com?debug=true",
            "user@example.com",
            "example.com\nother",
            "-bad.example",
            "127.000.000.001",
            "1.2.3.4.5",
        ]:
            self.assertIsNone(normalize_target(target))

    def test_normalize_decoy_list_accepts_hosts_and_one_me(self) -> None:
        self.assertEqual(
            normalize_decoy_list("192.168.56.20,LAB.example,ME"),
            "192.168.56.20,lab.example,ME",
        )

    def test_normalize_decoy_list_rejects_unsafe_or_ambiguous_values(self) -> None:
        for decoys in [
            "",
            "ME",
            "localhost,,ME",
            "localhost,localhost,ME",
            "localhost,ME,ME",
            "localhost,ME;id",
            "localhost,ME/path",
            "localhost,ME\n",
            "a,b,c,d,e,f,ME",
            "a,b,c,d,e,ME",
        ]:
            self.assertIsNone(normalize_decoy_list(decoys), decoys)

        self.assertEqual(normalize_decoy_list("localhost,me"), "localhost,ME")

    def test_normalize_web_urls_expands_plain_allowed_targets(self) -> None:
        self.assertEqual(
            normalize_web_urls("localhost"),
            ["https://localhost/", "http://localhost/"],
        )
        self.assertEqual(
            normalize_web_urls("::1"),
            ["https://[::1]/", "http://[::1]/"],
        )

    def test_normalize_web_urls_normalizes_explicit_urls(self) -> None:
        self.assertEqual(
            normalize_web_urls("HTTP://LOCALHOST:8080/path"),
            ["http://localhost:8080/path"],
        )
        self.assertEqual(
            normalize_web_urls("https://[::1]/admin"),
            ["https://[::1]/admin"],
        )

    def test_web_url_safety_rejects_unsafe_parts(self) -> None:
        for url in [
            "http://127.0.0.1/?debug=true",
            "http://user:pass@127.0.0.1/",
            "http://127.0.0.1/#frag",
            "http://127.0.0.1:0/",
            "http://127.0.0.1:99999/",
            "http://127.0.0.1/\nHost: example.com",
        ]:
            self.assertFalse(is_allowed_web_url(url))

    def test_web_url_safety_can_allow_query_for_redirect_validation(self) -> None:
        self.assertTrue(is_allowed_web_url("http://127.0.0.1/path?next=/home", allow_query=True))
        self.assertFalse(is_allowed_web_url("http://127.0.0.1/path?next=/home"))


if __name__ == "__main__":
    unittest.main()
