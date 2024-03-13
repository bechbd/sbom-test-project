import logging
from nodestream.pipeline import Extractor
from typing import Any, AsyncGenerator, Iterable
from pathlib import Path
from glob import glob
import json
from sbom_writer import CycloneDXWriter, SPDXWriter
import flatdict


class SBOMExtractor(Extractor):
    def __init__(self, paths: Iterable[Path]) -> None:
        p = Path(paths)
        if p.is_dir():
            self.paths = sorted(Path(paths).rglob("*.json"))
        elif p.is_file():
            self.paths = [p]
        self.logger = logging.getLogger(self.__class__.__name__)

    def __clean_dict(self, data: dict) -> dict:
        d = data
        try:
            for key in list(data):
                if isinstance(d[key], list) and len(d[key]) == 0:
                    d.pop(key)
                else:
                    if key.startswith("__"):
                        d.pop(key)
            return dict(flatdict.FlatterDict(d, delimiter=".").items())
        except Exception as e:
            self.logger.error(e)
            return d

    async def extract_records(self):
        for path in self.paths:
            elements = []
            with open(path, "r") as f:
                str = f.read()
                record = json.loads(str)
                if "bomFormat" in record and record["bomFormat"] == "CycloneDX":
                    writer = CycloneDXWriter(record)
                    elements = writer.write_document()
                elif "SPDXID" in record:
                    writer = SPDXWriter(record)
                    elements = writer.write_document()
                else:
                    self.logger.info(
                        f"The file at path {path} is not a valid CycloneDX SBOM"
                    )
                    print(f"The file at path {path} is not a valid CycloneDX SBOM")

            for e in elements:
                self.logger.debug(e)
                if "attributes" in e:
                    e["attributes"] = self.__clean_dict(e["attributes"])
                # if e["__type"] == "Vulnerability":
                #     print(e)
                yield e
