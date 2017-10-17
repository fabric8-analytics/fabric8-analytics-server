#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from lxml.etree import SubElement, Element, ElementTree, tostring


class PomXMLTemplate:

    def __init__(self, json_data):
        self._data = json_data
        self.root = Element(
            'project',
            xmlns="http://maven.apache.org/POM/4.0.0",
        )
        self.tree = ElementTree(self.root)
        self.create()

    def create(self):
        self._project = self._data.get('project')
        if self._project:
            self._options = self._project.get('options')
            SubElement(self.root, 'modelVersion').text = '4.0.0'
            if self._options:
                SubElement(self.root, 'groupId').text = self._options.get('group')
                SubElement(self.root, 'artifactId').text = self._options.get('artifactId')
                SubElement(self.root, 'version').text = self._options.get('version')
            SubElement(self.root, 'packaging').text = 'pom'
            SubElement(self.root, 'description').text = self._project.get('description')
            SubElement(self.root, 'url').text = 'https://example.com'
            self.licenses = SubElement(self.root, 'licenses')
            self.license = SubElement(self.licenses, 'license')
            SubElement(
                self.license, 'name').text = "Apache License, Version 2.0"
            SubElement(
                self.license, 'url').text = "http://www.apache.org/licenses"
            self.add_framework(self._data.get('framework'))
            self.add_dependencies(self._data.get('dependencies'))

    def add_framework(self, fw):
        frameworks = {'springboot': ["org.springframework.boot",
                                     "spring-boot-starter-parent",
                                     self._data.get('version')],
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

    def xml_string(self):
        return tostring(self.root, encoding='utf-8',
                        xml_declaration=True, pretty_print=True)
