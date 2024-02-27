import uuid


class SPDXWriter:
    def write_document(self):
        """Writes the CycloneDX document

        Args:
            bom (dict): The dict of the CycloneDX document

        Returns:
            bool: True if successful, False if not
        """

        raise NotImplementedError

    def __write_bom(self, bom):
        """Writes the BOM metadata

        Args:
            bom (str): The string of the CycloneDX document

        Returns:
            dict: The document
        """
        raise NotImplementedError

    def __write_components(self, components: list, document: dict):
        """Writes the components of the BOM to the graph

        Args:
            components (list): The components to write
            document (dict): The document to link the components to
        """

        raise NotImplementedError

    def __write_dependencies(self, dependencies: list):
        """Writes the dependencies and relationships to the graph

        Args:
            dependencies (list): The dependencies to write
        """

        raise NotImplementedError

    def __write_vulnerabilities(self, vulnerabilities: list):
        """Writes the vulnerabilities to the graph

        Args:
            vulnerabilities (list): The vulnerabilities to write
        """
        raise NotImplementedError
