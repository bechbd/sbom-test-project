from pathlib import Path
from contextlib import contextmanager
from os import environ
from testcontainers.neo4j import Neo4jContainer


import pytest
from nodestream.pipeline import (
    PipelineInitializationArguments,
    PipelineProgressReporter,
)
from nodestream.project import Project, RunRequest


@pytest.fixture
def project():
    return Project.read_from_file(Path("nodestream.yaml"))


class Neo4jContainerWithApoc(Neo4jContainer):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.with_env("NEO4J_PLUGINS", '["apoc"]]')


@pytest.fixture
def neo4j_container():
    @contextmanager
    def _create_neo4j_container(neo4j_version):
        with Neo4jContainerWithApoc(image=f"neo4j:{neo4j_version}") as neo4j_container:
            environ["NEO4J_CONNECT_URI"] = neo4j_container.get_connection_url()
            yield neo4j_container

    return _create_neo4j_container


def validate_nodes(session):
    result = session.run(
        """
        MATCH (a)
        RETURN count(a) AS count
        """
    )

    assert result.single()["count"] > 0


@pytest.mark.asyncio
async def test_sbom_pipeline(project):
    target = project.get_target_by_name("my-db")

    await project.run(
        RunRequest(
            "sbom",
            PipelineInitializationArguments(extra_steps=[target.make_writer()]),
            PipelineProgressReporter(),
        )
    )

    """
        for validator in validations:
            validator(session)
        """
