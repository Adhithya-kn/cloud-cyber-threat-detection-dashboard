"""
tests/test_cloud_environment.py
===============================
Tests verifying cloud deployment specifications, Docker, Kubernetes,
and container execution scripts.
"""

import os
import unittest


class TestCloudEnvironment(unittest.TestCase):
    """Test suite for cloud deployment configurations."""

    def test_entrypoint_executable(self):
        entrypoint_path = "entrypoint.sh"
        self.assertTrue(os.path.exists(entrypoint_path))
        self.assertTrue(os.access(entrypoint_path, os.X_OK), "entrypoint.sh must be executable")

    def test_dockerfile_and_compose_present(self):
        self.assertTrue(os.path.exists("Dockerfile"))
        self.assertTrue(os.path.exists("docker-compose.yml"))
        self.assertTrue(os.path.exists(".dockerignore"))

        with open("Dockerfile", "r") as f:
            content = f.read()
            self.assertIn("HEALTHCHECK", content)
            self.assertIn("USER appuser", content)

    def test_cloud_paas_configs(self):
        self.assertTrue(os.path.exists("render.yaml"))
        self.assertTrue(os.path.exists("fly.toml"))
        self.assertTrue(os.path.exists("Procfile"))
        self.assertTrue(os.path.exists(".env.example"))

    def test_kubernetes_manifests(self):
        k8s_files = [
            "k8s/namespace.yaml",
            "k8s/configmap.yaml",
            "k8s/deployment.yaml",
            "k8s/service.yaml",
            "k8s/ingress.yaml",
            "k8s/hpa.yaml",
        ]
        for k_file in k8s_files:
            self.assertTrue(os.path.exists(k_file), f"Missing K8s manifest: {k_file}")


if __name__ == "__main__":
    unittest.main()
