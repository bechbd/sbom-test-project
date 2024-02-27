import logging
from nodestream.pipeline import Extractor
from typing import Any, AsyncGenerator, Iterable
from pathlib import Path
from glob import glob
import json
from sbom_writer import CycloneDXWriter, SPDXWriter


class SBOMExtractor(Extractor):
    def __init__(self, paths: Iterable[Path]) -> None:
        p = Path(paths)
        if p.is_dir():
            self.paths = sorted(Path(paths).rglob("*.json"))
        elif p.is_file():
            self.paths = [p]
        self.logger = logging.getLogger(self.__class__.__name__)

    async def extract_records(self):
        for path in self.paths:
            with open(path, "r") as f:
                self.elements = []
                str = f.read()
                record = json.loads(str)
                if "bomFormat" in record and record["bomFormat"] == "CycloneDX":
                    writer = CycloneDXWriter(record)
                    elements = writer.write_document()
                    for e in elements:
                        # self.logger.info(e)
                        # print(json.dumps(e, indent=2))
                        yield e
                elif "SPDXID" in record:
                    writer = SPDXWriter(record)
                    elements = writer.write_document()
                    for e in elements:
                        # self.logger.info(e)
                        # print(json.dumps(e, indent=2))
                        yield e
                else:
                    self.logger.info(
                        f"The file at path {path} is not a valid CycloneDX SBOM"
                    )
                    print(f"The file at path {path} is not a valid CycloneDX SBOM")
