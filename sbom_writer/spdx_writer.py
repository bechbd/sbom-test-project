import uuid
from typing import Iterable
from .sbom_writer import SBOMWriter


class SPDXWriter(SBOMWriter):
    def write_document(self):
        """ "This writes the SPDX document

        Args:
            bom (dict): The dict of the BOM

        Returns:
            bool: True if successful, False if not
        """
        self.logger.info("Writing bom metadata")

        document = self.__write_bom(self.bom)

        if "packages" in self.bom:
            self.logger.info("Writing packages as components")
            self.__write_packages(self.bom["packages"])

        if "relationships" in self.bom:
            self.logger.info("Writing relationships")
            document = self.__write_relationships(self.bom["relationships"], document)

        self.elements.append(document)
        return self.elements

    def __write_bom(self, bom):
        """Writes the BOM metadata

        Args:
            bom (str): The string of the CycloneDX document

        Returns:
            dict: The document
        """
        document_id = f"{self.NodeLabels.DOCUMENT.value}_{uuid.uuid4()}"
        document = {
            **bom,
            **bom["creationInfo"],
            "__type": self.NodeLabels.DOCUMENT.value,
            "__document_id": document_id,
        }

        # Do mappings from Cyclone DX to more generic name
        document["specVersion"] = document.pop("spdxVersion")
        document["createdTimestamp"] = document.pop("created")
        document["bomFormat"] = "SPDX"
        document["describes"] = []
        document["describes"].extend(
            [
                {
                    "__toId": f"{self.NodeLabels.COMPONENT.value}_{r['name']}",
                }
                for r in bom["packages"]
            ]
        )

        return document

    def __write_packages(self, packages: list):
        """Writes the pacakges of the BOM to the graph

        Args:
            packages (list): The packages to write
        """

        for c in packages:
            component = {
                **c,
                "__type": self.NodeLabels.COMPONENT.value,
                "__component_id": f"{self.NodeLabels.COMPONENT.value}_{c['SPDXID']}",
            }
            if "externalRefs" in c:
                component["references"] = []
                for r in c["externalRefs"]:
                    self.elements.append(
                        {
                            **r,
                            "__type": self.NodeLabels.REFERENCE.value,
                            "__reference_id": f"{self.NodeLabels.REFERENCE.value}_{r['referenceLocator']}",
                        }
                    )
                    if r["referenceType"] == "purl" and "purl" not in component:
                        component["purl"] = r["referenceLocator"]
                    component["references"].extend(
                        [
                            {
                                "__toId": f"{self.NodeLabels.REFERENCE.value}_{r['referenceLocator']}",
                            }
                            for r in c["externalRefs"]
                        ]
                    )
            self.elements.append(component)

    def __write_relationships(self, relationships: list, document: object):
        """Writes the relationships of the BOM to the graph

        Args:
            relationships (list): The relationships to write
            document_id (str): The document id to link the relationships to
        """
        self.logger.info("Writing relationship edges")
        document["describes"] = []
        document["depends_on"] = []
        document["dependency_of"] = []
        document["described_by"] = []
        document["contains"] = []
        for d in relationships:
            if d["relationshipType"] == "DESCRIBES":
                document["describes"].append(
                    {
                        "__toId": f"{self.NodeLabels.REFERENCE.value}_{d['relatedSpdxElement']}",
                    }
                )
            elif d["relationshipType"] == "DEPENDS_ON":
                document["depends_on"].append(
                    {
                        "__toId": f"{self.NodeLabels.COMPONENT.value}_{d['relatedSpdxElement']}"
                    }
                )
            elif d["relationshipType"] == "DEPENDENCY_OF":
                document["dependency_of"].append(
                    {
                        "__toId": f"{self.NodeLabels.COMPONENT.value}_{d['relatedSpdxElement']}"
                    }
                )
            elif d["relationshipType"] == "DESCRIBED_BY":
                document["described_by"].append(
                    {
                        "__toId": f"{self.NodeLabels.COMPONENT.value}_{d['relatedSpdxElement']}"
                    }
                )
            elif d["relationshipType"] == "CONTAINS":
                document["contains"].append(
                    {
                        "__toId": f"{self.NodeLabels.COMPONENT.value}_{d['relatedSpdxElement']}"
                    }
                )
            else:
                self.logger.warning(
                    f"Unknown relationship type {d['relationshipType']}"
                )

        return document
