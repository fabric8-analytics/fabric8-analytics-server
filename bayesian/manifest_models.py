#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Model to parse manifest files."""

from lxml import etree
from lxml import objectify


class MavenPom:
    """Model for Maven POM (Project Object Model)."""

    def __init__(self, document=None):
        """Initialize constructor for MavenPom class.

        :document: Parse the content of the file.
        :returns: None

        """
        if not document:
            raise ValueError("No content is provided for parsing")

        self.document = document.strip()
        if not isinstance(self.document, (bytes, bytearray)):
            self.document = self.document.encode()

        try:
            self.root = objectify.fromstring(self.document)
            if getattr(self.root, 'dependencies', None) is None:
                # create a dependencies element if doesn't exist
                _prev = getattr(self.root, 'dependencyManagement', None)\
                    or getattr(self.root, 'properties', None)\
                    or getattr(self.root, 'name', None)
                if _prev is not None:
                    _prev.addnext(objectify.Element('dependencies'))
                else:
                    self.root.dependencies = objectify.ObjectifiedElement()
                self.root = self._reload(self.root)

        except etree.XMLSyntaxError as exc:
            print("Unable to parse xml document:\n {}".format(str(exc)))

    def __getitem__(self, key):
        """TODO: Doc for __getitem__."""
        attr = getattr(self.root, key, None)
        objectify.deannotate(self.root)
        return attr

    def __setitem__(self, key, value):
        """TODO: Doc for __setitem__."""
        if key in ('groupId', 'artifactId', 'name', 'version', 'packaging'):
            #  add these tags just after modelVersion tag.
            _prev = getattr(self.root, 'modelVersion', None)
            element = etree.Element(key)
            element.text = value
            _prev.addnext(element)
        else:
            setattr(self.root, key, value)
        objectify.deannotate(self.root)
        self._reload(self.root)

    def add_dependency(self, dependency):
        """Add dependency to POM.

        dependency: dict
        return: None
        """
        self.root.dependencies.append(
            MavenPom.to_objectify(self.Dependency(dependency)))
        self.root = self._reload(self.root)

    def add_dependencies(self, dependencies):
        """Add dependency to POM.

        dependencies: list
        return: None
        """
        for dep in dependencies:
            self.root.dependencies.append(
                MavenPom.to_objectify(self.Dependency(dep)))
            self.root = self._reload(self.root)

    def find_dependency(self, dependency):
        """Search for dependency and return the first match.

        dependency: dict
        return: Dependency
        """
        _dependency = self.Dependency(dependency)
        for dep in getattr(self.root.dependencies, 'dependency', []):
            if self.Dependency(dep) == _dependency:
                return _dependency

    def is_exist(self, dependency):
        """Check for dependency exists or not.

        dependency: dict
        return: bool
        """
        _dependency = self.Dependency(dependency)
        return any([_dependency == self.Dependency(dep)
                    for dep in getattr(self.root.dependencies, 'dependency', [])])

    def get_dependencies(self):
        """Return list of all the dependencies.

        return: generator
        """
        for dep in getattr(self.root.dependencies, 'dependency', []):
            yield self.Dependency(dep)

    @staticmethod
    def tostring(obj, decoding=False):
        """Convert the xml object into string.

        :returns: String
        """
        objectify.deannotate(obj.root, xsi_nil=True,
                             pytype=False, xsi=False, cleanup_namespaces=True)
        _str = etree.tostring(obj.root, pretty_print=True)
        if decoding:
            return _str.decode()
        return _str

    @staticmethod
    def to_objectify(obj):
        """Convert the object into ObjectifiedElement.

        :returns: ObjectifiedElement

        """
        return obj.root

    @staticmethod
    def _reload(obj):
        obj = objectify.fromstring(etree.tostring(obj))
        objectify.deannotate(obj, xsi_nil=True, cleanup_namespaces=True)
        return obj

    class Dependency:
        """Dependency class of outer class MavenPom."""

        def __init__(self, dependency=None):
            """Initialize constructor for Dependency class.

            :returns: None
            """
            self.Exclusion = MavenPom.Exclusion
            if dependency is not None:
                if not isinstance(dependency, objectify.ObjectifiedElement):
                    self.root = objectify.Element('dependency')
                else:
                    self.root = dependency

                for k, v in dependency.items():
                    if k == 'exclusions' and len(v) > 0:
                        self.root.exclusions = objectify.ObjectifiedElement()
                        for excl in v:
                            self.root.exclusions.append(
                                MavenPom.to_objectify(self.Exclusion(excl)))
                    else:
                        setattr(self.root, k, v)

        def __eq__(self, other):
            """Check equality of dependency object.

            other: Dependency
            Return: boolean
            """
            return self.root.groupId == other.root.groupId\
                and self.root.artifactId == other.root.artifactId

        def __getitem__(self, key):
            """TODO: Doc for __getitem__."""
            attr = getattr(self.root, key, None)
            objectify.deannotate(self.root)
            return attr

        def __setitem__(self, key, value):
            """TODO: Doc for __setitem__."""
            attr = setattr(self.root, key, value)
            objectify.deannotate(self.root)
            return attr

    class Exclusion:
        """Exclusion class of outer class MavenPom."""

        def __init__(self, exclusion=None):
            """Initialize constructor for Exclusion class.

            :returns: None
            """
            if exclusion is not None:
                if not isinstance(exclusion, objectify.ObjectifiedElement):
                    self.root = objectify.Element('exclusion')
                else:
                    self.root = exclusion
                for k, v in exclusion.items():
                    setattr(self.root, k, v)

        def __eq__(self, other):
            """Check equality of Exclusion object.

            other: Exclusion
            Return: boolean
            """
            return self.root.groupId == other.groupId\
                and self.root.artifactId == other.artifactId

        def __getitem__(self, key):
            """TODO: Doc for __getitem__."""
            return getattr(self.root, key, None)

        def __setitem__(self, key, value):
            """TODO: Doc for __setitem__."""
            return setattr(self.root, key, value)

    class Properties:
        """Properties class of outer class MavenPom."""

        pass

    class Plugin:
        """Plugin class of outer class MavenPom."""

        pass


class PypiRequirements:
    """Model for pip requirements.txt."""

    def __init__(self):
        """Initialize constructor for PypiRequirements class.

        :returns: None
        """
        raise NotImplementedError


class NpmPackage:
    """Model for NPM package.json."""

    def __init__(self):
        """Initialize constructor for NpmPackage class.

        :returns: None
        """
        raise NotImplementedError
