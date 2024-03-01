import logging
from nodestream.pipeline import Extractor
from typing import Any, AsyncGenerator, Iterable
from pathlib import Path
from glob import glob
import json
from sbom_writer import CycloneDXWriter, SPDXWriter
import requests


class GithubSBOMExtractor(Extractor):
    bearer_token: str = None

    def __init__(self, repos: list[str], bearer_token: str = None) -> None:
        self.repos = repos
        if bearer_token is not None:
            self.bearer_token = bearer_token
        self.logger = logging.getLogger(self.__class__.__name__)

    def fetch_sbom_from_github(self, repo: str) -> object:
        headers = {}
        if self.bearer_token is not None:
            headers["Authorization"] = f"Bearer {self.bearer_token}"

        resp = requests.get(
            f"https://api.github.com/repos/{repo}/dependency-graph/sbom",
            headers=headers,
        )

        if resp.ok:
            data = resp.json()
            return data["sbom"]
        else:
            raise Exception(
                f"Failed to fetch SBOM from GitHub for repo {repo}: {resp.text}"
            )

    async def extract_records(self):
        for repo in self.repos:
            record = self.fetch_sbom_from_github(repo)
            writer = SPDXWriter(record)
            elements = writer.write_document()
            for e in elements:
                yield e
