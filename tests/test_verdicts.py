import unittest
import rov_utils

class TestVerdicts(unittest.TestCase):
    
    def test_tier1_protected(self):
        # AS3356 is a Tier 1
        v = rov_utils.assign_verdict(3356, True, 67000, [1, 2], 0, False)
        self.assertEqual(v, "CORE: PROTECTED")
        
    def test_tier1_unprotected(self):
        v = rov_utils.assign_verdict(3356, False, 67000, [1, 2], 1, False)
        self.assertEqual(v, "CORE: UNPROTECTED")
        
    def test_atlas_override_secure(self):
        # Atlas secure should override everything else
        v = rov_utils.assign_verdict(1234, False, 100, [5, 6], 2, False, "SECURE (Verified Active)")
        self.assertEqual(v, "SECURE (Verified ROV)")
        
    def test_atlas_override_vulnerable(self):
        v = rov_utils.assign_verdict(1234, True, 100, [], 0, False, "VULNERABLE (Verified Active)")
        self.assertEqual(v, "VULNERABLE (Atlas Verified)")
        
    def test_not_routed(self):
        v = rov_utils.assign_verdict(1234, False, 0, [], 0, False)
        self.assertEqual(v, "NOT ROUTED")
        
    def test_unverified_transit(self):
        # Has cone but no parents
        v = rov_utils.assign_verdict(1234, False, 10, [], 0, False)
        self.assertEqual(v, "Unverified (Transit/Peer?)")
        
    def test_stub_secure_stable(self):
        v = rov_utils.assign_verdict(1234, False, 0, [3356], 0, False)
        self.assertEqual(v, "STUB: SECURE STABLE")
        
    def test_stub_vulnerable_stable(self):
        v = rov_utils.assign_verdict(1234, False, 0, [5], 1, False)
        self.assertEqual(v, "STUB: VULNERABLE STABLE")
        
    def test_partial_mixed(self):
        # 2 parents, 1 dirty
        v = rov_utils.assign_verdict(1234, False, 10, [3356, 5], 1, False)
        self.assertEqual(v, "PARTIAL: VULNERABLE (Mixed)")
        
    def test_transit_secure_unstable(self):
        v = rov_utils.assign_verdict(1234, True, 10, [3356], 0, True)
        self.assertEqual(v, "SECURE UNSTABLE")

if __name__ == '__main__':
    unittest.main()
