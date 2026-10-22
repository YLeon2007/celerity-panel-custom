"""Real fixed9e artifacts only; no fixture pins or acceptance monkeypatches."""
import importlib.util
import os
from pathlib import Path
import unittest

HERE=Path(__file__).resolve().parent
REPO=HERE.parents[1]
CANDIDATE=Path('/home/leon/.hermes/cache/scratch/c3-fixed9e-jxaruiv1/candidate')
try:
    import fresh_install_source_pack_9e_v1 as product
except ModuleNotFoundError:
    product=None

class Fixed9eTests(unittest.TestCase):
    def test_verified_fixed9e_candidate(self):
        self.assertIsNotNone(product, 'explicit versioned fixed9e product is missing')
        self.assertEqual(product.PROFILE['sourceCommit'], '9e1b9897539750c3fef02b98055967d1a7edbbec')
        repo_fd=product.open_directory(str(REPO))
        fd=product.open_directory(str(CANDIDATE))
        try:
            manifest,report,files,snapshot=product.verify_candidate(str(REPO),repo_fd,product.SOURCE,fd)
            self.assertEqual(len(manifest),10518)
            self.assertEqual(report['sourceCommit'],product.SOURCE)
        finally:
            os.close(fd);os.close(repo_fd)

if __name__=='__main__':unittest.main()
