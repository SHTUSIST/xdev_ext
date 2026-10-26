"""Parser regressions for actual fresh-frame generation zero, not hardware proof."""
import unittest
from test_decode import Decode
from test_driver_audit import Driver

class InitialGeneration(unittest.TestCase):
    def test_native_fresh_frame_generation_zero_is_an_immutable_identity(self):
        fixture=Decode();fixture.setUp()
        raw=fixture.positive().replace('generation=1 ', 'generation=0 ')
        events=fixture.decoder.decode(raw,'nvme_nic')
        self.assertEqual(events[1]['frame_generations'],[0,0])
        corrupt=raw.replace('phase=native_complete origin=K session_id=7 batch_id=1 batch_key=1 frame_id=8 generation=0',
                            'phase=native_complete origin=K session_id=7 batch_id=1 batch_key=1 frame_id=8 generation=1')
        with self.assertRaises(ValueError):fixture.decoder.decode(corrupt,'nvme_nic')

    def test_descriptor_fresh_generation_zero_keeps_binding_correlation(self):
        fixture=Driver();fixture.setUp()
        raw=fixture.positive().replace('generation=2 ', 'generation=0 ')
        self.assertEqual(fixture.d.audit(raw,7)['native_submits'],1)
        corrupt=raw.replace('phase=downstream_complete origin=K session_id=7 batch_id=1 batch_key=1 frame_id=8 generation=0',
                            'phase=downstream_complete origin=K session_id=7 batch_id=1 batch_key=1 frame_id=8 generation=1')
        with self.assertRaises(ValueError):fixture.d.audit(corrupt,7)

if __name__=='__main__':unittest.main(verbosity=2)
