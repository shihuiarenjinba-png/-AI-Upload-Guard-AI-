import tempfile
import unittest
from pathlib import Path

from windows_app import inspect_file, make_safer_copy


class PdfMetadataGateTests(unittest.TestCase):
    def setUp(self):
        self.t=tempfile.TemporaryDirectory()
        self.addCleanup(self.t.cleanup)
        self.root=Path(self.t.name)
        self.output=self.root/'out'
        self.output.mkdir()
    def make_pdf(self, name, text):
        from reportlab.pdfgen.canvas import Canvas
        p=self.root/name
        c=Canvas(str(p))
        c.drawString(100,700,text)
        c.save()
        return p
    def test_email_pdf_rejected_without_output(self):
        source=self.make_pdf('sample.pdf','Email: person@example.com')
        self.assertIn('email address candidate',inspect_file(source)['findings'])
        with self.assertRaisesRegex(ValueError,'metadata-only copying is refused'):
            make_safer_copy(source,self.output)
        self.assertEqual(list(self.output.iterdir()),[])
    def test_no_false_claim_of_full_redaction(self):
        source=self.make_pdf('notice.pdf','This file was reviewed by a person')
        inspection=inspect_file(source)
        self.assertIn('remaining pages', ' '.join(inspection['unchecked']))
        self.assertIn(inspection['decision'], ('REVIEW','LIMITED'))


if __name__=='__main__':
    unittest.main()
