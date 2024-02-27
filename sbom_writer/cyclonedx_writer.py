import uuid
from typing import Any, AsyncGenerator, Iterable
from enum import Enum
import logging
from .sbom_writer import SBOMWriter


class CycloneDXWriter(SBOMWriter):
    def write_document(self) -> Iterable:
        """Writes the CycloneDX document

        Args:
            bom (dict): The dict of the CycloneDX document

        Returns:
            bool: True if successful, False if not
        """
        self.logger.info("Writing bom metadata")
        document = self.__write_bom(self.bom)

        if "components" in self.bom:
            document = self.__write_components(self.bom["components"], document)

        if "dependencies" in self.bom:
            self.__write_dependencies(self.bom["dependencies"])

        if "vulnerabilities" in self.bom:
            self.__write_vulnerabilities(self.bom["vulnerabilities"])

        self.elements.append(document)
        return self.elements

    def __write_bom(self, bom):
        """Writes the BOM metadata

        Args:
            bom (str): The string of the CycloneDX document

        Returns:
            dict: The document
        """
        if "serialNumber" in bom:
            document_id = f"{self.NodeLabels.DOCUMENT.value}_{bom['serialNumber']}"
        else:
            document_id = f"{self.NodeLabels.DOCUMENT.value}_{uuid.uuid4()}"

        document = {
            **bom,
            "__type": self.NodeLabels.DOCUMENT.value,
            "__document_id": document_id,
        }

        if "components" in document:
            del document["components"]
        if "dependencies" in document:
            del document["dependencies"]
        if "vulnerabilities" in document:
            del document["vulnerabilities"]

        # Do mappings from Cyclone DX to more generic name
        # document["spec_version"] = document.pop("specVersion")
        # document["created_timestamp"] = document.pop("timestamp")

        return document

    def __write_components(self, components: list, document: dict):
        """Writes the components of the BOM to the graph

        Args:
            components (list): The components to write
            document (dict): The document to link the components to
        """
        for c in components:
            if "bom-ref" in c:
                component = {
                    **c,
                    "__type": self.NodeLabels.COMPONENT.value,
                    "__component_id": f"{self.NodeLabels.COMPONENT.value}_{c['bom-ref']}",
                }
            else:
                self.logger.error(f"Component {c['name']} does not contain a bom-ref")
                raise AttributeError(
                    f"Component {c['name']} does not contain a bom-ref"
                )
            document["describes"] = []
            document["describes"].extend(
                [
                    {
                        "__toId": f"{self.NodeLabels.COMPONENT.value}_{c['bom-ref']}",
                    }
                    for c in components
                ]
            )
            if "externalReferences" in c:
                self.elements.extend(
                    [
                        {
                            **c,
                            "__type": self.NodeLabels.REFERENCE.value,
                            "__reference_id": f"{self.NodeLabels.REFERENCE.value}_{r['url']}",
                        }
                        for r in c["externalReferences"]
                    ]
                )
                component["references"] = []
                component["references"].extend(
                    [
                        {
                            "__toId": f"{self.NodeLabels.REFERENCE.value}_{r['url']}",
                        }
                        for r in c["externalReferences"]
                    ]
                )

            self.elements.append(component)

        return document

    def __write_dependencies(self, dependencies: list):
        """Writes the dependencies and relationships to the graph

        Args:
            dependencies (list): The dependencies to write
        """
        for d in dependencies:
            if "dependsOn" in d:
                dependency = {
                    **d,
                    "__type": self.NodeLabels.COMPONENT.value,
                    "__component_id": f"{self.NodeLabels.COMPONENT.value}_{d['ref']}",
                }
                dependency["dependsOn"] = []
                dependency["dependsOn"].extend(
                    [
                        {
                            "__toId": f"{self.NodeLabels.COMPONENT.value}_{dep}",
                        }
                        for dep in d["dependsOn"]
                    ]
                )

                self.elements.append(dependency)

    def __write_vulnerabilities(self, vulnerabilities: list):
        """Writes the vulnerabilities to the graph

        Args:
            vulnerabilities (list): The vulnerabilities to write
        """
        for v in vulnerabilities:
            vul = {
                **v,
                "__type": self.NodeLabels.VULNERABILITY.value,
                "__vulnerability_id": f"{self.NodeLabels.VULNERABILITY.value}_{v['id']}",
            }
            if "ratings" in v and len(v["ratings"]) > 0:
                vul.append(v["ratings"][0])

            if "affects" in v:
                vul["affects"] = []
                vul["affects"].extend(
                    [
                        {
                            "__toId": f"{self.NodeLabels.COMPONENT.value}_{a['ref']}",
                        }
                        for a in v["affects"]
                    ]
                )
            self.elements.append(vul)
