pipeline {
  environment {
    registry = "buildarium/bdapi-auth"
    registryCredential = 'dockerhub'
    dockerImage = ''
  }

  agent any

  stages {
    stage('Test') {
      steps {
        checkout scm
      }
    }
    stage('Build') {
      steps {
        script {
          dockerImage = docker.build registry
        }
      }
    }
    stage('Deploy') {
      steps{
        script {
          docker.withRegistry('', registryCredential) {
            dockerImage.push("${env.BUILD_NUMBER}")
            if (env.BRANCH_NAME == 'master') {
              dockerImage.push("latest")
              // sh "kubectl config use-context buildarium"
              sh "kubectl set image deployment/bdapi-auth bdapi-auth=buildarium/bdapi-auth:${env.BUILD_NUMBER} --kubeconfig /var/lib/jenkins/config"
            } else if (env.BRANCH_NAME == 'develop') {
              dockerImage.push("dev")
            }
          }
        }
        sh "docker rmi $registry:$BUILD_NUMBER"
      }
    }
  }
}