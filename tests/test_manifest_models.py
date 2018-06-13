#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Tests for classes from manifest_models module."""

from bayesian.manifest_models import MavenPom as maven
from bayesian.manifest_models import PypiRequirements as pypi
from bayesian.manifest_models import NpmPackage as npm
import pytest
from lxml import etree


class TestManifestModels:
    """Tests for the manifest_models module."""

    def test_mavenpom_constructor_with_blank_xml_str(self):
        """Test the constructor for the MavenPom class with blank document."""
        with pytest.raises(ValueError):
            maven('')

    def test_mavenpom_constructor_with_invalid_xml_str(self):
        """Test the constructor for the MavenPom class with invalid document."""
        with pytest.raises(etree.XMLSyntaxError):
            maven('<xml></xml> <project>')

    def test_mavenpom_constructor_with_valid_xml_str(self):
        """Test the constructor for the MavenPom class with valid document."""
        obj = maven('<project/>')
        assert obj is not None

    def test_attributes(self):
        """Test the content of MavenPom attributes."""
        obj = maven("""
                <project>
                    <groupId>some.groupId</groupId>
                    <artifactId>some-artifactId</artifactId>
                    <dependencies/>
                </project>
                """)
        assert obj.root is not None
        assert obj.root.groupId is not None
        assert obj.root.artifactId is not None
        assert obj.root.dependencies is not None

    def test_add_tags_and_value(self):
        """Test add tags and values in POM."""
        obj = maven('<project/>')
        obj['artifactId'] = 'blank-artifactId'
        obj['groupId'] = 'blank.groupId'

        assert obj['artifactId'] == 'blank-artifactId'
        assert obj['groupId'] == 'blank.groupId'

    def test_add_dependency(self):
        """Test add dependency in POM."""
        obj = maven('<project/>')
        dependency = {
            'groupId': 'org.wildfly.swarm',
            'artifactId': 'bom-all',
            'version': '2018.5.0',
        }
        obj.add_dependency(dependency)
        assert dependency in obj

    def test_add_dependencies(self):
        """Test add dependencies in POM."""
        obj = maven('<project/>')
        dependencies = [
            {
                'groupId': 'org.wildfly.swarm',
                'artifactId': 'bom-all',
                'version': '2018.5.0',
            },
            {
                'groupId': 'org.arquillian.cube',
                'artifactId': 'arquillian-cube-openshift',
                'scope': 'test',
                'exclusions': [{
                    'groupId': 'io.undertow',
                    'artifactId': 'undertow-core',
                }]
            }]
        obj.add_dependencies(dependencies)
        assert all([d in obj for d in dependencies])

    def test_remove_dependency(self):
        """Test remove dependency from POM."""
        obj = maven('<project/>')
        dependency = {
            'groupId': 'org.wildfly.swarm',
            'artifactId': 'bom-all',
            'version': '2018.5.0',
        }
        obj.add_dependency(dependency)
        obj.remove_dependency(dependency)
        assert dependency not in obj

    def test_get_dependencies(self):
        """Test list all dependencies from POM."""
        obj = maven("""
                <project>
                    <dependencies>
                        <dependency>
                            <groupId>org.wildfly.swarm</groupId>
                            <artifactId>bom</artifactId>
                            <version>2018.5.2018.5.0</version>
                        </dependency>
                        <dependency>
                        <groupId>org.arquillian.cube</groupId>
                        <artifactId>arquillian-cube-openshift</artifactId>
                        <scope>test</scope>
                        <exclusions>
                            <exclusion>
                            <groupId>io.undertow</groupId>
                            <artifactId>undertow-core</artifactId>
                            </exclusion>
                        </exclusions>
                        </dependency>
                    </dependencies>
                </project>
                """)
        assert len(list(obj.get_dependencies())) == 2
        assert not {'org.arquillian.cube', 'org.wildfly.swarm'} - \
            {d['groupId'] for d in obj.get_dependencies()}

    def test_pypi_constructor(self):
        """Test the constructor for the PypiRequirements class."""
        with pytest.raises(NotImplementedError):
            pypi()

    def test_npm_constructor(self):
        """Test the constructor for the NpmPackage class."""
        with pytest.raises(NotImplementedError):
            npm()
