import io
import urllib.parse
import unittest

from run_live_splunk_smoke import (
    ENDPOINT, EXPECTED, NoRedirect, check_result, decode_csv, execute,
    validate_base_url,
)


def csv_response(rows):
    fields = list(EXPECTED)
    return (",".join(fields) + "\n" + "\n".join(
        ",".join(str(row[key]) for key in fields) for row in rows
    ) + ("\n" if rows else "")).encode()


class MockResponse:
    def __init__(self, data):
        self._stream = io.BytesIO(data)
    def __enter__(self):
        return self
    def __exit__(self, *_):
        self._stream.close()
    def read(self, count):
        return self._stream.read(count)


class MockTransport:
    def __init__(self, data):
        self.data = data
        self.request = None
        self.timeout = None
    def open(self, req, timeout):
        self.request = req
        self.timeout = timeout
        return MockResponse(self.data)


class SplunkApiSmokeTests(unittest.TestCase):
    def test_origin_validation(self):
        self.assertEqual(validate_base_url("https://localhost:8089/"), "https://localhost:8089")
        for invalid in ("http://localhost:8089", "https://a:secret@localhost:8089",
                        "https://example.com/path", "https://example.com?x=1",
                        "https://example.com#secret", ""):
            with self.subTest(url=invalid), self.assertRaises(ValueError):
                validate_base_url(invalid)

    def test_valid_csv(self):
        self.assertTrue(check_result(decode_csv(csv_response([EXPECTED]))))

    def test_missing_result_fails(self):
        self.assertFalse(check_result(decode_csv(csv_response([]))))

    def test_wrong_count_fails(self):
        self.assertFalse(check_result(decode_csv(csv_response([
            dict(EXPECTED, failure_count_in_window="4")]))))

    def test_duplicate_row_fails(self):
        self.assertFalse(check_result(decode_csv(csv_response([EXPECTED, EXPECTED]))))

    def test_html_error_rejected(self):
        with self.assertRaisesRegex(ValueError, "CSV header"):
            decode_csv(b"<html>please log in</html>")

    def test_live_call_shape_and_scrubbed_report_using_mock_transport(self):
        transport = MockTransport(csv_response([EXPECTED]))
        report = execute("https://localhost:8089", "fake-test-token", opener=transport)
        self.assertEqual(report["status"], "SMOKE_RESULT_PASS")
        self.assertFalse(report["independently_attested"])
        self.assertNotIn("fake-test-token", str(report))
        self.assertEqual(transport.request.full_url, "https://localhost:8089" + ENDPOINT)
        self.assertEqual(transport.request.get_method(), "POST")
        self.assertEqual(transport.request.get_header("Authorization"), "Bearer fake-test-token")
        data = urllib.parse.parse_qs(transport.request.data.decode())
        self.assertEqual(data["output_mode"], ["csv"])
        self.assertIn("| makeresults", data["search"][0])

    def test_bogus_mock_response_is_not_a_pass(self):
        report = execute("https://localhost:8089", "fake-test-token",
                         opener=MockTransport(csv_response([])))
        self.assertEqual(report["status"], "SMOKE_RESULT_FAIL")

    def test_redirect_handler_rejects(self):
        handler = NoRedirect()
        with self.assertRaisesRegex(ValueError, "redirect rejected"):
            handler.redirect_request(None, None, 302, "", {}, "https://other.invalid")

    def test_oversized_response_fails(self):
        with self.assertRaisesRegex(ValueError, "bounded"):
            decode_csv(b"a" * (256 * 1024 + 1))


if __name__ == "__main__":
    unittest.main()
