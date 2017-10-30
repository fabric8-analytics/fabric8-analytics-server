#!/usr/bin/env groovy
@Library('github.com/msrb/cicd-pipeline-helpers')

def commitId
node('docker') {

    def image = docker.image('bayesian/bayesian-api')

    stage('Checkout') {
        checkout scm
        commitId = sh(returnStdout: true, script: 'git rev-parse --short HEAD').trim()
        dir('openshift') {
            stash name: 'template', includes: 'template.yaml'
        }
    }

    stage('Build') {
        dockerCleanup()
        docker.build(image.id, '--pull --no-cache .')
        sh "docker tag ${image.id} registry.devshift.net/${image.id}"
        docker.build('coreapi-server-tests', '-f Dockerfile.tests .')
    }

    stage('Unit Tests') {
        timeout(30) {
            sh './runtest.sh'
        }
    }

    if (env.BRANCH_NAME == 'master') {
        stage('Push Images') {
            docker.withRegistry('https://push.registry.devshift.net/', 'devshift-registry') {
                image.push('latest')
                image.push(commitId)
            }
        }
    }
}

if (env.BRANCH_NAME == 'master') {
    node('oc') {

        def dc = 'bayesian-api'
        lock('f8a_staging') {

            stage('Deploy - Stage') {
                unstash 'template'
                sh "oc --context=rh-idev process -v IMAGE_TAG=${commitId} -f template.yaml | oc --context=rh-idev apply -f -"
            }

            stage('End-to-End Tests') {
                def result
                try {
                    timeout(20) {
                        sleep 5
                        sh "oc logs -f dc/${dc}"
                        def e2e = build job: 'fabric8-analytics-common-master', wait: true, propagate: false, parameters: [booleanParam(name: 'runOnOpenShift', value: true)]
                        result = e2e.result
                    }
                } catch (err) {
                    error "Error: ${err}"
                } finally {
                    if (!result?.equals('SUCCESS')) {
                        sh "oc rollback ${dc}"
                        error 'End-to-End tests failed.'
                    } else {
                        echo 'End-to-End tests passed.'
                    }
                }
            }
        }
    }
}

