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

    stage('Tests') {
        timeout(30) {
            sh './runtest.sh'
        }
    }

    stage('Integration Tests') {
        ws {
            docker.withRegistry('https://registry.devshift.net/') {
                docker.image('bayesian/cucos-worker').pull()
                docker.image('bayesian/data-model-importer').pull()
                docker.image('bayesian/coreapi-jobs').pull()
                docker.image('bayesian/coreapi-pgbouncer').pull()
                docker.image('bayesian/cvedb-s3-dump').pull()
                docker.image('slavek/anitya-server').pull()
                docker.image('bayesian/gremlin').pull()
            }

            git url: 'https://github.com/fabric8-analytics/fabric8-analytics-common.git', branch: 'master', poll: false
            dir('integration-tests') {
                timeout(30) {
                    sh './runtest.sh'
                }
            }
        }
    }

    if (env.BRANCH_NAME == 'master') {
        stage('Push Images') {
            docker.withRegistry('https://registry.devshift.net/') {
                image.push('latest')
                image.push(commitId)
            }
        }
    }
}

if (env.BRANCH_NAME == 'master') {
    node('oc') {
        stage('Deploy - dev') {
            unstash 'template'
            sh "oc --context=dev process -v IMAGE_TAG=${commitId} -f template.yaml | oc --context=dev apply -f -"
        }

        stage('Deploy - rh-idev') {
            unstash 'template'
            sh "oc --context=rh-idev process -v IMAGE_TAG=${commitId} -f template.yaml | oc --context=rh-idev apply -f -"
        }
    }
}
