import datetime
import pytest

from bayesian.utils import do_projection
from f8a_worker.enums import EcosystemBackend
from f8a_worker.models import Analysis, Ecosystem, Package, Version, WorkerResult

now = datetime.datetime.now()
later = now + datetime.timedelta(minutes=10)


@pytest.fixture
def analyses(app):
    e1 = Ecosystem(name='npm', backend=EcosystemBackend.npm)
    p1 = Package(ecosystem=e1, name='arrify')
    v1 = Version(package=p1, identifier='1.0.1')
    model1 = Analysis(version=v1, started_at=now, finished_at=later)
    app.rdb.session.add(model1)

    e2 = Ecosystem(name='pypi', backend=EcosystemBackend.pypi)
    p2 = Package(ecosystem=e2, name='flexmock')
    v2 = Version(package=p2, identifier='0.10.1')
    model2 = Analysis(version=v2, started_at=later, access_count=1)
    app.rdb.session.add(model2)
    app.rdb.session.commit()

    worker_results2 = {'a': 'b', 'c': 'd', 'e': 'f', 'g': 'h', 'i': 'j',
                       'digests': {'details':
                                   [{'artifact': True,
                                     'sha1': '6be7ae55bae2372c7be490321bbe5ead278bb51b'}]}}
    for w, tr in worker_results2.items():
        app.rdb.session.add(WorkerResult(analysis_id=model2.id, worker=w, task_result=tr))

    model3 = Analysis(version=v2, started_at=later, access_count=1,
                      audit={'audit': {'audit': 'audit', 'e': 'f', 'g': 'h'}, 'a': 'b', 'c': 'd'})
    app.rdb.session.add(model3)
    app.rdb.session.commit()
    worker_results3 = {'digests': {'details':
                                   [{'artifact': True,
                                     'sha1': '6be7ae55bae2372c7be490321bbe5ead278bb51b'}]}}
    for w, tr in worker_results3.items():
        app.rdb.session.add(WorkerResult(analysis_id=model3.id, worker=w, task_result=tr))
    app.rdb.session.commit()
    return (model1, model2, model3)


@pytest.mark.usefixtures('rdb')
class TestDoProjection(object):
    def test_empty_projection(self, analyses):
        """In this case no fields should be returned"""
        projection = []
        expected = {}
        result = do_projection(projection, analyses[0])
        assert expected == result

    def test_simple_projection(self, analyses):
        """Test simple projection of 2 simple arguments"""
        projection = ['ecosystem', 'package']
        # pypi has order 1
        expected = {'ecosystem': 'npm', 'package': 'arrify'}
        returned = do_projection(projection, analyses[0])
        assert expected == returned

    def test_none_projection(self, analyses):
        """If projection is None original model should be returned"""
        projection = None
        returned = do_projection(projection, analyses[0])
        expected = analyses[0].to_dict()
        assert expected == returned

    def test_nested_projection(self, analyses):
        """Test whether filtering of nested JSON returns just desired field"""
        projection = ['analyses.digests']
        expected = {'analyses': {'digests': {'details':
                                             [{'artifact': True, 'sha1':
                                               '6be7ae55bae2372c7be490321bbe5ead278bb51b'}]}}}
        result = do_projection(projection, analyses[1])
        assert expected == result

    def test_combined_projection(self, analyses):
        """Combining simple fields with nested fields"""
        projection = ['analyses.digests', 'analyses.a', 'package']
        expected = {'analyses': {'a': 'b', 'digests': {
            'details': [{'artifact': True, 'sha1': '6be7ae55bae2372c7be490321bbe5ead278bb51b'}]}},
                    'package': 'flexmock'}
        result = do_projection(projection, analyses[1])
        assert expected == result

    def test_three_level_fields(self, analyses):
        """Testing third level of nested JSON"""
        projection = ['analyses.digests.details', 'audit.audit.audit']
        expected = {'audit': {'audit': {'audit': 'audit'}},
                    'analyses':
                    {'digests': {'details':
                                 [{'artifact': True,
                                     'sha1': '6be7ae55bae2372c7be490321bbe5ead278bb51b'}]}}}
        result = do_projection(projection, analyses[2])
        assert expected == result
