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

        self.root = objectify.fromstring(self.document)

        # create a dependencies element if doesn't exist
        if getattr(self.root, 'dependencies', None) is None:
            _prev = getattr(self.root, 'dependencyManagement', None)\
                or getattr(self.root, 'properties', None)\
                or getattr(self.root, 'name', None)
            if _prev is not None:
                _prev.addnext(objectify.Element('dependencies'))
            else:
                self.root.dependencies = objectify.ObjectifiedElement()
            self.root = self._reload(self.root)

        self.dependency_set = set([self.Dependency(d) for d in getattr(
            self.root.dependencies, 'dependency', [])])

    def __getitem__(self, key):
        """Return the value for attr key."""
        attr = getattr(self.root, key, None)
        objectify.deannotate(self.root)
        return attr

    def __setitem__(self, key, value):
        """Set value for attr key."""
        _prev = getattr(self.root, 'modelVersion', None)
        if key in ('groupId', 'artifactId', 'name', 'version', 'packaging') and _prev is not None:
            #  add these tags just after modelVersion tag.
            element = etree.Element(key)
            element.text = value
            _prev.addnext(element)
        else:
            setattr(self.root, key, value)
        objectify.deannotate(self.root)
        self._reload(self.root)

    def add_element(self, data={}, parent=None, next_to=None):
        """Add element to POM.

        data: dict
        parent: etree.Element or string
        return: None
        """
        _prev = None
        if next_to is not None:
            if isinstance(next_to, (str, bytes)):
                _prev = getattr(self.root, next_to, None)
            else:
                _prev = next_to

        if isinstance(parent, (str, bytes)):
            if _prev is not None:
                parent = etree.Element(parent)
                _prev.addnext(parent)
            else:
                parent = etree.SubElement(self.root, parent)

        if isinstance(data, dict):
            for key, value in data.items():
                self.add_element(value, etree.SubElement(parent, key))
        elif isinstance(data, (tuple, list)):
            for value in data:
                self.add_element(value, parent)
        elif isinstance(data, (bytes, bytearray)):
            parent._setText(data.decode())
        else:
            parent._setText(data)

    def add_dependency(self, dependency):
        """Add dependency to POM.

        dependency: dict
        return: None
        """
        self.dependency_set.add(self.Dependency(dependency))

    def add_dependencies(self, dependencies):
        """Add dependency to POM.

        dependencies: list
        return: None
        """
        self.dependency_set.update({self.Dependency(dep)
                                    for dep in dependencies})

    def remove_dependency(self, dependency):
        """Remove dependency to POM.

        dependency: dict
        return: None
        """
        self.dependency_set.remove(self.Dependency(dependency))

    def __contains__(self, dependency):
        """Check for dependency exists or not.

        dependency: dict
        return: bool
        """
        return self.Dependency(dependency) in self.dependency_set

    def get_dependencies(self):
        """Return list of all the dependencies.

        return: generator
        """
        for dep in self.dependency_set:
            yield dep

    def _commit(self):
        """Commit the changes to the XML root object."""
        for dep in self.dependency_set:
            self.root.dependencies.append(MavenPom.to_objectify(dep))
        self.root = self._reload(self.root)

    @staticmethod
    def tostring(obj, decoding=False):
        """Convert the xml object into string.

        :returns: String
        """
        if getattr(obj, '_commit', None) is not None:
            obj._commit()

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

        def __repr__(self):
            """Representation of an Dependency object in string."""
            return "groupId: {}\nartifactId: {}"\
                .format(self.root.groupId, self.root.artifactId)

        def __eq__(self, other):
            """Check equality of dependency object.

            other: Dependency
            Return: boolean
            """
            return (self.root.groupId, self.root.artifactId) ==\
                (other.root.groupId, other.root.artifactId)

        def __ne__(self, other):
            """Check non-equality of Dependency object.

            other: Dependency
            Return: boolean
            """
            return not self.__eq__(other)

        def __getitem__(self, key):
            """Return the value for attr key."""
            attr = getattr(self.root, key, None)
            objectify.deannotate(self.root)
            return attr

        def __setitem__(self, key, value):
            """Set value for attr key."""
            attr = setattr(self.root, key, value)
            objectify.deannotate(self.root)
            return attr

        def __hash__(self):
            """Return hash for String representation of an Dependency object."""
            return hash(self.__repr__())

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
            return (self.root.groupId, self.root.artifactId) ==\
                (other.root.groupId, other.root.artifactId)

        def __ne__(self, other):
            """Check non-equality of Exclusion object.

            other: Exclusion
            Return: boolean
            """
            return not self.__eq__(other)

        def __getitem__(self, key):
            """Return the value for attr key."""
            return getattr(self.root, key, None)

        def __setitem__(self, key, value):
            """Set value for attr key."""
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
