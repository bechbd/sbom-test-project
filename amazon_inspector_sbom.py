import logging
from nodestream.pipeline import Extractor
import os
from sbom_writer import CycloneDXWriter
import boto3
import time
from botocore.client import Config
from pathlib import Path
import json
import shutil


class AmazonInspectorSBOMExtractor(Extractor):
    bearer_token: str = None

    def __init__(self, bucketName: str, keyPrefix: str, kmsKeyArn: str) -> None:
        self.bucketName = bucketName
        self.keyPrefix = keyPrefix
        self.kmsKeyArn = kmsKeyArn
        self.logger = logging.getLogger(self.__class__.__name__)
        report_id = self.start_sbom_export()
        self.logger.info(f"Report ID: {report_id}")
        successful = self.check_for_export_complete(report_id)
        if successful:
            self.logger.info("SBOM export successful")
            self.keyPrefix = self.keyPrefix + f"CYCLONEDX_1_4_outputs_{report_id}/"
            self.download_s3_dir()
        else:
            self.logger.error("SBOM export failed")

    def start_sbom_export(self) -> str:
        self.client = boto3.client("inspector2")
        response = self.client.create_sbom_export(
            reportFormat="CYCLONEDX_1_4",
            s3Destination={
                "bucketName": self.bucketName,
                "keyPrefix": self.keyPrefix,
                "kmsKeyArn": self.kmsKeyArn,
            },
        )

        return response["reportId"]

    def check_for_export_complete(self, report_id: str) -> object:
        while True:
            time.sleep(30)
            self.logger.info("Checking for SBOM export completion")
            response = self.client.get_sbom_export(reportId=report_id)
            self.logger.info(f"Current Status: {response['status']}")
            if not response["status"] == "IN_PROGRESS":
                if response["status"] == "SUCCEEDED":
                    return True
                else:
                    return False

    def download_s3_dir(self):
        shutil.rmtree("tmp")

        s3_client = boto3.client("s3", config=Config(signature_version="s3v4"))
        keys = []
        dirs = []
        next_token = ""
        base_kwargs = {
            "Bucket": self.bucketName,
            "Prefix": self.keyPrefix,
        }
        while next_token is not None:
            kwargs = base_kwargs.copy()
            if next_token != "":
                kwargs.update({"ContinuationToken": next_token})
            results = s3_client.list_objects_v2(**kwargs)
            contents = results.get("Contents")
            for i in contents:
                k = i.get("Key")
                if k[-1] != "/":
                    keys.append(k)
                else:
                    dirs.append(k)
            next_token = results.get("NextContinuationToken")
        for d in dirs:
            dest_pathname = os.path.join("tmp", d)
            if not os.path.exists(os.path.dirname(dest_pathname)):
                os.makedirs(os.path.dirname(dest_pathname))
        for k in keys:
            dest_pathname = os.path.join("tmp", k)
            if not os.path.exists(os.path.dirname(dest_pathname)):
                os.makedirs(os.path.dirname(dest_pathname))
            s3_client.download_file(self.bucketName, k, dest_pathname)

    async def extract_records(self):
        paths = sorted(Path("tmp").rglob("*.json"))
        for path in paths:
            with open(path, "r") as f:
                self.elements = []
                str = f.read()
                record = json.loads(str)
                writer = CycloneDXWriter(record)
                elements = writer.write_document()
                for e in elements:
                    yield e
