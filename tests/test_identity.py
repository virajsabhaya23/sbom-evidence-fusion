import importlib.metadata
import unittest

import sbom_fuse
from sbom_fuse.identity import (
    IdentityError,
    canonical_component,
    canonical_reference,
    canonicalize_purl,
    register_component,
)


class PurlIdentityTests(unittest.TestCase):
    def test_generic_identity_preserves_case(self):
        self.assertEqual(
            canonicalize_purl("pkg:generic/Acme/Widget@V1"),
            "pkg:generic/Acme/Widget@V1",
        )
        self.assertNotEqual(
            canonicalize_purl("pkg:generic/Acme/Widget@V1"),
            canonicalize_purl("pkg:generic/acme/widget@v1"),
        )

    def test_maven_and_nuget_case_is_not_destroyed(self):
        self.assertEqual(
            canonicalize_purl("pkg:maven/Org.Apache/Artifact@1.0"),
            "pkg:maven/Org.Apache/Artifact@1.0",
        )
        self.assertEqual(
            canonicalize_purl("pkg:nuget/EnterpriseLibrary.Common@6.0.1304"),
            "pkg:nuget/EnterpriseLibrary.Common@6.0.1304",
        )

    def test_registered_type_normalization_is_applied(self):
        self.assertEqual(
            canonicalize_purl("pkg:pypi/Django_REST.Framework@3.0"),
            "pkg:pypi/django-rest.framework@3.0",
        )
        self.assertEqual(
            canonical_component("@Angular/Animation", "12.3.1", ecosystem="npm"),
            "pkg:npm/%40Angular/animation@12.3.1",
        )

    def test_qualifier_keys_and_order_are_canonical(self):
        self.assertEqual(
            canonicalize_purl("pkg:generic/widget@1?Repository_URL=https%3A%2F%2FEXAMPLE.com&arch=arm64"),
            "pkg:generic/widget@1?arch=arm64&repository_url=https:%2F%2FEXAMPLE.com",
        )

    def test_invalid_purl_fails_closed(self):
        with self.assertRaises(IdentityError):
            canonicalize_purl("pkg:npm")

    def test_opaque_references_are_case_sensitive(self):
        self.assertEqual(canonical_reference("SPDXRef-ABC"), "SPDXRef-ABC")
        self.assertEqual(
            canonical_reference("pkg:generic/Acme/Widget@V1"),
            "pkg:generic/Acme/Widget@V1",
        )

    def test_aliases_are_preserved_for_known_equivalents(self):
        components = {}
        key = canonicalize_purl("pkg:pypi/Django_REST.Framework@3.0")
        register_component(components, key, {"name": "Django_REST.Framework", "version": "3.0", "purl": "pkg:pypi/Django_REST.Framework@3.0"})
        register_component(components, key, {"name": "django-rest.framework", "version": "3.0", "purl": "pkg:pypi/django-rest.framework@3.0"})
        self.assertIn("pkg:pypi/Django_REST.Framework@3.0", components[key]["identity_aliases"])
        self.assertIn("pkg:pypi/django-rest.framework@3.0", components[key]["identity_aliases"])

    def test_opaque_collision_is_rejected(self):
        components = {}
        register_component(components, "component-1", {"name": "alpha", "version": "1"})
        with self.assertRaises(IdentityError):
            register_component(components, "component-1", {"name": "beta", "version": "1"})

    def test_runtime_and_distribution_versions_match(self):
        self.assertEqual(
            sbom_fuse.__version__,
            importlib.metadata.version("sbom-evidence-fusion"),
        )


if __name__ == "__main__":
    unittest.main()
