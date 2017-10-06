#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from lxml.etree import SubElement, Element, ElementTree
from io import BytesIO


class PomXMLTemplate:

    def __init__(self, json_data=None):
        if json_data:
            self._data = dict(json_data)
        else:
            raise ValueError
        self.root = Element(
            'project',
            xmlns="http://maven.apache.org/POM/4.0.0",
        )
        self.tree = ElementTree(self.root)
        self.create()

    def create(self):
        self._project = self._data.get('project', None)
        if self._project:
            self._options = self._project.get('options', None)
            SubElement(self.root, 'modelVersion').text = '4.0.0'
            if self._options:
                SubElement(self.root, 'groupId').text = self._options.get(
                    'group', None)
                SubElement(self.root, 'artifactId').text = self._options.get(
                    'artifactId', None)
                SubElement(self.root, 'version').text = self._options.get(
                    'version', None)
            SubElement(self.root, 'packaging').text = 'pom'
            SubElement(self.root, 'description').text = self._project.get(
                'description', None)
            SubElement(self.root, 'url').text = 'https://example.com'
            self.licenses = SubElement(self.root, 'licenses')
            self.license = SubElement(self.licenses, 'license')
            SubElement(
                self.license, 'name').text = "Apache License, Version 2.0"
            SubElement(
                self.license, 'url').text = "http://www.apache.org/licenses"
            self.add_framework(self._data.get('framework', None))
            self.add_dependencies(self._data.get('dependencies', None))

    def add_framework(self, fw):
        frameworks = {'springboot': ["org.springframework.boot",
                                     "spring-boot-starter-parent",
                                     self._data.get('version', None)],
                      'wildfly': (None, None, None),
                      'vertx': (None, None, None)
                      }
        if fw in frameworks:
            self._parent = SubElement(self.root, 'parent')
            for child, data in zip(('groupID', 'artifactID', 'version'),
                                   frameworks.get(fw, [])):
                SubElement(self._parent, child).text = data

    def add_dependencies(self, dependencies):
        if dependencies:
            self.dpmanage = SubElement(self.root, "dependencyManagement")
            self.dps = SubElement(self.dpmanage, "dependencies")
            for item in dependencies:
                dp = SubElement(self.dps, 'dependency')
                for child, data in zip(('groupID', 'artifactID', 'version'),
                                       item.split(':')):
                    SubElement(dp, child).text = data

    def xml_file(self):
        tempFile = BytesIO()
        self.tree.write(tempFile, encoding='utf-8',
                        xml_declaration=True, pretty_print=True)
        tempFile.seek(0)
        return tempFile
