"""
tests/test_cloud_api.py
=======================
Tests for Cloud Telemetry Ingestion API and microservice endpoints.
"""

import asyncio
import json
import unittest

from api import healthz, status_endpoint, ingest_telemetry, mitigate_endpoint


class MockAsyncRequest:
    def __init__(self, json_data=None):
        self._json_data = json_data

    async def json(self):
        return self._json_data


class TestCloudAPI(unittest.TestCase):
    """Test suite for cloud endpoints."""

    def test_healthz_endpoint(self):
        async def run_test():
            req = MockAsyncRequest()
            res = await healthz(req)
            self.assertEqual(res.status_code, 200)
            data = json.loads(res.body.decode())
            self.assertEqual(data["status"], "healthy")
            self.assertIn("timestamp", data)
            self.assertIn("bound_port", data)

        asyncio.run(run_test())

    def test_status_endpoint(self):
        async def run_test():
            req = MockAsyncRequest()
            res = await status_endpoint(req)
            self.assertEqual(res.status_code, 200)
            data = json.loads(res.body.decode())
            self.assertEqual(data["mode"], "autonomous")
            self.assertEqual(len(data["agents"]), 5)
            self.assertTrue(data["cloud_ready"])

        asyncio.run(run_test())

    def test_telemetry_ingest_and_annotation(self):
        async def run_test():
            payload = [
                {
                    "timestamp": "2024-10-12T12:00:00Z",
                    "source_ip": "198.51.100.77",
                    "destination_ip": "10.0.0.8",
                    "source_port": 51234,
                    "destination_port": 22,
                    "protocol": "SSH",
                    "user": "admin",
                    "event_type": "failed_login",
                    "status": "FAILURE",
                    "bytes": 256,
                    "packets": 2,
                }
            ] * 12

            req = MockAsyncRequest(payload)
            res = await ingest_telemetry(req)
            self.assertEqual(res.status_code, 200)
            data = json.loads(res.body.decode())
            self.assertEqual(data["status"], "PROCESSED")
            self.assertEqual(data["events_ingested"], 12)
            self.assertGreater(data["threats_detected"], 0)
            self.assertEqual(len(data["step_annotations"]), 5)

        asyncio.run(run_test())

    def test_mitigate_endpoint(self):
        async def run_test():
            req = MockAsyncRequest({"ip": "203.0.113.99", "action": "FIREWALL_DROP"})
            res = await mitigate_endpoint(req)
            self.assertEqual(res.status_code, 200)
            data = json.loads(res.body.decode())
            self.assertEqual(data["status"], "EXECUTED")
            self.assertIn("audit_hash", data)
            self.assertEqual(data["target_ip"], "203.0.113.99")

        asyncio.run(run_test())


if __name__ == "__main__":
    unittest.main()
