"""Definition of a class to find dependencies from an input manifest file."""

import os
import json
from selinon import FatalTaskError
from sqlalchemy.exc import SQLAlchemyError

from f8a_worker.manifests import get_manifest_descriptor_by_filename
from f8a_worker.models import StackAnalysisRequest, Ecosystem
from f8a_worker.solver import get_ecosystem_solver
from tempfile import TemporaryDirectory
from f8a_worker.workers.mercator import MercatorTask

from .utils import generate_content_hash


pom_hash = {}


class DependencyFinder():
    """Implementation of methods to find dependencies from manifest file."""

    @staticmethod
    def _handle_external_deps(ecosystem, deps):
        """Resolve external dependency specifications."""
        if not ecosystem or not deps:
            return []
        solver = get_ecosystem_solver(ecosystem)
        try:
            versions = solver.solve(deps)
        except Exception as exc:
            raise FatalTaskError("Dependencies could not be resolved: '{}'" .format(deps)) from exc
        return [{"package": k, "version": v} for k, v in versions.items()]

    def execute(self, arguments, db, manifests, source=None):
        """Dependency finder logic."""
        #  try:
        #      results = db.query(StackAnalysisRequest)\
        #                  .filter(StackAnalysisRequest.id == arguments.get('external_request_id'))\
        #                  .first()
        #  except SQLAlchemyError:
        #   raise ('Could not find data for request id = %s' % arguments.get(
        #       'external_request_id'))
        #
        #  manifests = []
        #  if results is not None:
        #      row = results.to_dict()
        #      request_json = row.get("requestJson", {})
        #      manifests = request_json.get('manifest', [])

        # If we receive a manifest file we need to save it first
        result = []
        for manifest in manifests:
            resolve_poms = False
            hashed_data = None
            # Special case where maintaining the results of the booster dependencies in memory.
            if source == 'osio':
                content_hash = generate_content_hash(manifest['content'])
                if pom_hash.get(content_hash) is not None:
                    hashed_data = pom_hash.get(content_hash)
                else:
                    resolve_poms = True

            if hashed_data is None:
                with TemporaryDirectory() as temp_path:
                    with open(os.path.join(temp_path, manifest['filename']), 'a+') as fd:
                        fd.write(manifest['content'])

                    # mercator-go does not work if there is no package.json
                    if 'shrinkwrap' in manifest['filename'].lower():
                        with open(os.path.join(temp_path, 'package.json'), 'w') as f:
                            f.write(json.dumps({}))

                    # Create instance manually since stack analysis is not handled by dispatcher
                    subtask = MercatorTask.create_test_instance(task_name='metadata')
                    arguments['ecosystem'] = manifest['ecosystem']
                    out = subtask.run_mercator(arguments, temp_path, resolve_poms=resolve_poms)

                if not out["details"]:
                    raise FatalTaskError("No metadata found processing manifest file '{}'"
                                         .format(manifest['filename']))

                if 'dependencies' not in out['details'][0] and out.get('status', None) == 'success':
                    raise FatalTaskError("Dependencies could not be resolved from manifest file"
                                         "'{}'".format(manifest['filename']))

                out["details"][0]['manifest_file'] = manifest['filename']
                out["details"][0]['ecosystem'] = manifest['ecosystem']
                out["details"][0]['manifest_file_path'] = manifest.get('filepath',
                                                                       'File path not available')

                # Convert dependency specifications for external requests.
                manifest_descriptor = get_manifest_descriptor_by_filename(manifest['filename'])
                if 'external_request_id' in arguments:
                    manifest_dependencies = []
                    if manifest_descriptor.has_resolved_deps:  # npm-shrinkwrap.json, pom.xml
                        if "_dependency_tree_lock" in out["details"][0]:  # npm-shrinkwrap.json
                            if 'dependencies' in out['details'][0]["_dependency_tree_lock"]:
                                manifest_dependencies = out["details"][0]["_dependency_tree_lock"]\
                                    .get("dependencies", [])
                        else:  # pom.xml
                            if 'dependencies' in out['details'][0]:
                                manifest_dependencies = out["details"][0].get("dependencies", [])
                        if manifest_descriptor.has_recursive_deps:  # npm-shrinkwrap.json
                            def _flatten(deps, collect):
                                for dep in deps:
                                    collect.append({'package': dep['name'],
                                                    'version': dep['version']})
                                    _flatten(dep['dependencies'], collect)
                            resolved_deps = []
                            _flatten(manifest_dependencies, resolved_deps)
                        else:  # pom.xml
                            resolved_deps =\
                                [{'package': x.split(' ')[0], 'version': x.split(' ')[1]}
                                 for x in manifest_dependencies]
                    else:  # package.json, requirements.txt
                        resolved_deps = self._handle_external_deps(
                            Ecosystem.by_name(db, arguments['ecosystem']),
                            out["details"][0]["dependencies"])
                    out["details"][0]['_resolved'] = resolved_deps
                result.append(out)
            else:
                result.append(hashed_data)

        return {'result': result}
